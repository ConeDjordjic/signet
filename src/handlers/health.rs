//! Health check handlers.

use axum::{extract::State, http::StatusCode, Json};
use diesel::prelude::*;
use serde::Serialize;
use utoipa::ToSchema;

use crate::AppState;

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    #[schema(example = "healthy")]
    pub status: String,
    #[schema(example = "signet")]
    pub service: String,
    #[schema(example = "0.1.0")]
    pub version: String,
    #[schema(example = "2024-01-15T10:30:00Z")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadinessResponse {
    #[schema(example = "ready")]
    pub status: String,
    pub checks: ReadinessChecks,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadinessChecks {
    pub database: ComponentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis: Option<ComponentStatus>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ComponentStatus {
    #[schema(example = "up")]
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 5)]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "Connection refused")]
    pub error: Option<String>,
}

impl ComponentStatus {
    pub fn up(latency_ms: u64) -> Self {
        Self {
            status: "up".to_string(),
            latency_ms: Some(latency_ms),
            error: None,
        }
    }

    pub fn down(error: impl Into<String>) -> Self {
        Self {
            status: "down".to_string(),
            latency_ms: None,
            error: Some(error.into()),
        }
    }
}

#[utoipa::path(
    get,
    path = "/health/status",
    tag = "Health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    )
)]
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "signet".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Some(chrono::Utc::now().to_rfc3339()),
    })
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Simple health check", content_type = "text/plain")
    )
)]
pub async fn health_check_simple() -> &'static str {
    "OK"
}

#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    responses(
        (status = 200, description = "Service is ready", body = ReadinessResponse),
        (status = 503, description = "Service is not ready", body = ReadinessResponse)
    )
)]
pub async fn ready_check(
    State(state): State<AppState>,
) -> Result<Json<ReadinessResponse>, (StatusCode, Json<ReadinessResponse>)> {
    let db_status = match check_database(&state).await {
        Ok(latency_ms) => ComponentStatus::up(latency_ms),
        Err(e) => ComponentStatus::down(e),
    };

    let redis_status = check_redis(&state).await;

    let db_healthy = db_status.status == "up";
    let redis_healthy = redis_status
        .as_ref()
        .map(|s| s.status == "up")
        .unwrap_or(true);

    let response = ReadinessResponse {
        status: if db_healthy && redis_healthy {
            "ready".to_string()
        } else {
            "not_ready".to_string()
        },
        checks: ReadinessChecks {
            database: db_status,
            redis: redis_status,
        },
    };

    if db_healthy && redis_healthy {
        Ok(Json(response))
    } else {
        Err((StatusCode::SERVICE_UNAVAILABLE, Json(response)))
    }
}

async fn check_database(state: &AppState) -> Result<u64, String> {
    let start = std::time::Instant::now();

    let mut conn = state
        .db_pool
        .get()
        .map_err(|e| format!("Failed to get connection: {}", e))?;

    diesel::sql_query("SELECT 1")
        .execute(&mut conn)
        .map_err(|e| format!("Query failed: {}", e))?;

    let latency = start.elapsed().as_millis() as u64;
    Ok(latency)
}

async fn check_redis(state: &AppState) -> Option<ComponentStatus> {
    use redis::AsyncCommands;

    let pool = state.cache.token_revocation.pool()?;
    let start = std::time::Instant::now();

    match pool.get().await {
        Ok(mut conn) => {
            let result: Result<String, _> = conn.get("health_check_ping").await;
            match result {
                Ok(_) | Err(redis::RedisError { .. }) => {
                    let latency = start.elapsed().as_millis() as u64;
                    Some(ComponentStatus::up(latency))
                }
            }
        }
        Err(e) => Some(ComponentStatus::down(format!("Connection failed: {}", e))),
    }
}

#[utoipa::path(
    get,
    path = "/health/live",
    tag = "Health",
    responses(
        (status = 200, description = "Service is alive")
    )
)]
pub async fn live_check() -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_status_up() {
        let status = ComponentStatus::up(10);
        assert_eq!(status.status, "up");
        assert_eq!(status.latency_ms, Some(10));
        assert!(status.error.is_none());
    }

    #[test]
    fn test_component_status_down() {
        let status = ComponentStatus::down("Connection refused");
        assert_eq!(status.status, "down");
        assert!(status.latency_ms.is_none());
        assert_eq!(status.error, Some("Connection refused".to_string()));
    }

    #[tokio::test]
    async fn test_health_check_returns_healthy() {
        let response = health_check().await;
        assert_eq!(response.status, "healthy");
        assert_eq!(response.service, "signet");
    }

    #[tokio::test]
    async fn test_health_check_simple() {
        let response = health_check_simple().await;
        assert_eq!(response, "OK");
    }
}
