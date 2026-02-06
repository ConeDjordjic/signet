//! Observability: tracing, metrics, and OpenTelemetry integration.

pub mod metrics;
pub mod tracing;

pub use metrics::{record_auth_attempt, record_permission_check, AuthOutcome, MetricsState};
pub use tracing::init_telemetry;
