//! Background event publisher that polls the outbox and publishes to Redis Streams.

use deadpool_redis::Pool as RedisPool;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};

use crate::DbPool;

use super::outbox::OutboxService;

#[derive(Debug, Clone)]
pub struct PublisherConfig {
    pub poll_interval: Duration,
    pub batch_size: i64,
    pub stream_name: String,
    pub retention_days: i32,
    pub cleanup_interval_polls: u32,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            batch_size: 100,
            stream_name: "signet:events".to_string(),
            retention_days: 7,
            cleanup_interval_polls: 3600,
        }
    }
}

pub struct EventPublisher {
    db_pool: DbPool,
    redis_pool: Option<RedisPool>,
    config: PublisherConfig,
}

impl EventPublisher {
    pub fn new(db_pool: DbPool, redis_pool: Option<RedisPool>, config: PublisherConfig) -> Self {
        Self {
            db_pool,
            redis_pool,
            config,
        }
    }

    pub fn spawn(self) -> watch::Sender<bool> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        tokio::spawn(async move {
            self.run(shutdown_rx).await;
        });

        shutdown_tx
    }

    #[instrument(skip(self, shutdown_rx), name = "event_publisher")]
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            poll_interval_ms = self.config.poll_interval.as_millis(),
            batch_size = self.config.batch_size,
            stream = %self.config.stream_name,
            "Event publisher started"
        );

        let mut poll_timer = interval(self.config.poll_interval);
        let mut poll_count: u32 = 0;

        loop {
            tokio::select! {
                _ = poll_timer.tick() => {
                    poll_count = poll_count.wrapping_add(1);

                    if let Err(e) = self.poll_and_publish().await {
                        error!(error = %e, "Error polling/publishing events");
                    }

                    if poll_count.is_multiple_of(self.config.cleanup_interval_polls) {
                        if let Err(e) = self.cleanup().await {
                            warn!(error = %e, "Error during event cleanup");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Event publisher received shutdown signal");
                        break;
                    }
                }
            }
        }

        info!("Draining remaining events before shutdown...");
        for _ in 0..3 {
            match self.poll_and_publish().await {
                Ok(0) => break,
                Ok(n) => debug!(count = n, "Drained events"),
                Err(e) => {
                    error!(error = %e, "Error during final drain");
                    break;
                }
            }
        }

        info!("Event publisher stopped");
    }

    #[instrument(skip(self))]
    async fn poll_and_publish(&self) -> Result<usize, PublishError> {
        let events = {
            let pool = self.db_pool.clone();
            let batch_size = self.config.batch_size;

            tokio::task::spawn_blocking(move || {
                let mut conn = pool
                    .get()
                    .map_err(|e| PublishError::Database(e.to_string()))?;
                OutboxService::fetch_unpublished(&mut conn, batch_size)
                    .map_err(|e| PublishError::Database(e.to_string()))
            })
            .await
            .map_err(|e| PublishError::Task(e.to_string()))??
        };

        if events.is_empty() {
            return Ok(0);
        }

        debug!(count = events.len(), "Fetched unpublished events");

        if let Some(redis_pool) = &self.redis_pool {
            self.publish_to_redis(redis_pool, &events).await?;
        } else {
            debug!("No Redis configured, marking events as published without streaming");
        }

        let event_ids: Vec<_> = events.iter().map(|e| e.id).collect();
        let pool = self.db_pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| PublishError::Database(e.to_string()))?;
            OutboxService::mark_published_batch(&mut conn, &event_ids)
                .map_err(|e| PublishError::Database(e.to_string()))
        })
        .await
        .map_err(|e| PublishError::Task(e.to_string()))??;

        Ok(events.len())
    }

    #[instrument(skip(self, redis_pool, events), fields(count = events.len()))]
    async fn publish_to_redis(
        &self,
        redis_pool: &RedisPool,
        events: &[crate::models::OutboxEvent],
    ) -> Result<(), PublishError> {
        use redis::AsyncCommands;

        let mut conn = redis_pool
            .get()
            .await
            .map_err(|e| PublishError::Redis(e.to_string()))?;

        for event in events {
            let event_data = serde_json::json!({
                "id": event.id.to_string(),
                "event_type": event.event_type,
                "aggregate_type": event.aggregate_type,
                "aggregate_id": event.aggregate_id.to_string(),
                "payload": event.payload,
                "created_at": event.created_at.to_string(),
            });

            let _: String = conn
                .xadd(
                    &self.config.stream_name,
                    "*",
                    &[
                        ("event_type", event.event_type.as_str()),
                        ("data", &event_data.to_string()),
                    ],
                )
                .await
                .map_err(|e| PublishError::Redis(e.to_string()))?;

            debug!(
                event_id = %event.id,
                event_type = %event.event_type,
                "Published event to Redis Stream"
            );
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn cleanup(&self) -> Result<usize, PublishError> {
        let pool = self.db_pool.clone();
        let retention_days = self.config.retention_days;

        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| PublishError::Database(e.to_string()))?;
            OutboxService::cleanup_old_events(&mut conn, retention_days)
                .map_err(|e| PublishError::Database(e.to_string()))
        })
        .await
        .map_err(|e| PublishError::Task(e.to_string()))?
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Redis error: {0}")]
    Redis(String),

    #[error("Task error: {0}")]
    Task(String),
}

pub struct EventPublisherBuilder {
    db_pool: DbPool,
    redis_pool: Option<RedisPool>,
    config: PublisherConfig,
}

impl EventPublisherBuilder {
    pub fn new(db_pool: DbPool) -> Self {
        Self {
            db_pool,
            redis_pool: None,
            config: PublisherConfig::default(),
        }
    }

    pub fn redis_pool(mut self, pool: RedisPool) -> Self {
        self.redis_pool = Some(pool);
        self
    }

    pub fn maybe_redis_pool(mut self, pool: Option<RedisPool>) -> Self {
        self.redis_pool = pool;
        self
    }

    pub fn poll_interval(mut self, duration: Duration) -> Self {
        self.config.poll_interval = duration;
        self
    }

    pub fn batch_size(mut self, size: i64) -> Self {
        self.config.batch_size = size;
        self
    }

    pub fn stream_name(mut self, name: impl Into<String>) -> Self {
        self.config.stream_name = name.into();
        self
    }

    pub fn retention_days(mut self, days: i32) -> Self {
        self.config.retention_days = days;
        self
    }

    pub fn build(self) -> EventPublisher {
        EventPublisher::new(self.db_pool, self.redis_pool, self.config)
    }

    pub fn spawn(self) -> watch::Sender<bool> {
        self.build().spawn()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_publisher_config_default() {
        let config = PublisherConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(1));
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.stream_name, "signet:events");
        assert_eq!(config.retention_days, 7);
        assert_eq!(config.cleanup_interval_polls, 3600);
    }

    #[test]
    fn test_publisher_config_clone() {
        let config = PublisherConfig::default();
        let cloned = config.clone();
        assert_eq!(config.poll_interval, cloned.poll_interval);
        assert_eq!(config.stream_name, cloned.stream_name);
    }

    #[test]
    fn test_publish_error_display() {
        let err = PublishError::Database("connection failed".to_string());
        assert!(err.to_string().contains("Database error"));
        assert!(err.to_string().contains("connection failed"));

        let err = PublishError::Redis("timeout".to_string());
        assert!(err.to_string().contains("Redis error"));

        let err = PublishError::Task("panic".to_string());
        assert!(err.to_string().contains("Task error"));
    }
}
