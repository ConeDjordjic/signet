//! Outbox pattern implementation for reliable event publishing.

use diesel::prelude::*;
use tracing::{debug, instrument};
use uuid::Uuid;

use crate::models::{NewOutboxEvent, OutboxEvent};
use crate::schema::outbox_events;

use super::types::{AggregateType, DomainEvent, EventType};

#[derive(Debug, Clone)]
pub struct OutboxService;

impl OutboxService {
    #[instrument(skip(conn, event), fields(event_type = %event.event_type, aggregate_id = %event.aggregate_id))]
    pub fn write_event(
        conn: &mut PgConnection,
        event: &DomainEvent,
    ) -> Result<OutboxEvent, diesel::result::Error> {
        let payload = serde_json::json!({
            "data": event.payload,
            "metadata": event.metadata,
        });

        let new_event = NewOutboxEvent {
            event_type: event.event_type.as_str().to_string(),
            aggregate_type: event.aggregate_type.as_str().to_string(),
            aggregate_id: event.aggregate_id,
            payload,
        };

        let result = diesel::insert_into(outbox_events::table)
            .values(&new_event)
            .returning(OutboxEvent::as_returning())
            .get_result(conn)?;

        debug!(event_id = %result.id, "Event written to outbox");
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(conn, payload), fields(event_type = %event_type, aggregate_id = %aggregate_id))]
    pub fn emit(
        conn: &mut PgConnection,
        event_type: EventType,
        aggregate_type: AggregateType,
        aggregate_id: Uuid,
        payload: serde_json::Value,
        user_id: Option<Uuid>,
        project_id: Option<Uuid>,
        request_id: Option<String>,
    ) -> Result<OutboxEvent, diesel::result::Error> {
        let event = DomainEvent {
            event_type,
            aggregate_type,
            aggregate_id,
            payload,
            metadata: super::types::EventMetadata {
                user_id,
                project_id,
                request_id,
                timestamp: chrono::Utc::now(),
            },
        };

        Self::write_event(conn, &event)
    }

    #[instrument(skip(conn))]
    pub fn fetch_unpublished(
        conn: &mut PgConnection,
        limit: i64,
    ) -> Result<Vec<OutboxEvent>, diesel::result::Error> {
        outbox_events::table
            .filter(outbox_events::published.eq(false))
            .order(outbox_events::created_at.asc())
            .limit(limit)
            .select(OutboxEvent::as_select())
            .load(conn)
    }

    #[instrument(skip(conn))]
    pub fn mark_published(
        conn: &mut PgConnection,
        event_id: Uuid,
    ) -> Result<(), diesel::result::Error> {
        diesel::update(outbox_events::table.find(event_id))
            .set((
                outbox_events::published.eq(true),
                outbox_events::published_at.eq(diesel::dsl::now),
            ))
            .execute(conn)?;

        debug!(event_id = %event_id, "Event marked as published");
        Ok(())
    }

    #[instrument(skip(conn, event_ids), fields(count = event_ids.len()))]
    pub fn mark_published_batch(
        conn: &mut PgConnection,
        event_ids: &[Uuid],
    ) -> Result<usize, diesel::result::Error> {
        let count = diesel::update(outbox_events::table)
            .filter(outbox_events::id.eq_any(event_ids))
            .set((
                outbox_events::published.eq(true),
                outbox_events::published_at.eq(diesel::dsl::now),
            ))
            .execute(conn)?;

        debug!(count, "Events marked as published in batch");
        Ok(count)
    }

    #[instrument(skip(conn))]
    pub fn cleanup_old_events(
        conn: &mut PgConnection,
        older_than_days: i32,
    ) -> Result<usize, diesel::result::Error> {
        let cutoff = chrono::Utc::now()
            .naive_utc()
            .checked_sub_signed(chrono::Duration::days(older_than_days as i64))
            .unwrap_or_else(|| chrono::Utc::now().naive_utc());

        let count = diesel::delete(outbox_events::table)
            .filter(outbox_events::published.eq(true))
            .filter(outbox_events::published_at.lt(cutoff))
            .execute(conn)?;

        if count > 0 {
            debug!(count, older_than_days, "Cleaned up old outbox events");
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbox_service_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OutboxService>();
    }
}
