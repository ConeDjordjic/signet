//! Application metrics using the metrics crate.

use axum::{http::StatusCode, response::IntoResponse};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

#[derive(Clone)]
pub struct MetricsState {
    handle: Option<PrometheusHandle>,
}

impl MetricsState {
    pub fn new(enabled: bool) -> Self {
        if !enabled {
            return Self { handle: None };
        }

        let handle = PROMETHEUS_HANDLE.get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("Failed to install Prometheus recorder")
        });

        Self {
            handle: Some(handle.clone()),
        }
    }

    pub fn disabled() -> Self {
        Self { handle: None }
    }

    pub fn render(&self) -> Option<String> {
        self.handle.as_ref().map(|h| h.render())
    }

    pub fn is_enabled(&self) -> bool {
        self.handle.is_some()
    }
}

pub async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<MetricsState>,
) -> impl IntoResponse {
    match state.render() {
        Some(metrics) => (StatusCode::OK, metrics),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Metrics not enabled".to_string(),
        ),
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AuthOutcome {
    Success,
    InvalidCredentials,
    AccountLocked,
    AccountInactive,
    TokenExpired,
    TokenRevoked,
}

impl AuthOutcome {
    fn as_str(&self) -> &'static str {
        match self {
            AuthOutcome::Success => "success",
            AuthOutcome::InvalidCredentials => "invalid_credentials",
            AuthOutcome::AccountLocked => "account_locked",
            AuthOutcome::AccountInactive => "account_inactive",
            AuthOutcome::TokenExpired => "token_expired",
            AuthOutcome::TokenRevoked => "token_revoked",
        }
    }
}

pub fn record_auth_attempt(action: &str, outcome: AuthOutcome) {
    counter!(
        "auth_attempts_total",
        "action" => action.to_string(),
        "outcome" => outcome.as_str().to_string()
    )
    .increment(1);
}

pub fn record_permission_check(cached: bool, granted: bool, duration: std::time::Duration) {
    counter!(
        "permission_checks_total",
        "cached" => cached.to_string(),
        "granted" => granted.to_string()
    )
    .increment(1);

    histogram!(
        "permission_check_duration_seconds",
        "cached" => cached.to_string()
    )
    .record(duration.as_secs_f64());
}

pub fn record_request_latency(
    method: &str,
    path: &str,
    status: u16,
    duration: std::time::Duration,
) {
    histogram!(
        "http_request_duration_seconds",
        "method" => method.to_string(),
        "path" => path.to_string(),
        "status" => status.to_string()
    )
    .record(duration.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_outcome_as_str() {
        assert_eq!(AuthOutcome::Success.as_str(), "success");
        assert_eq!(
            AuthOutcome::InvalidCredentials.as_str(),
            "invalid_credentials"
        );
        assert_eq!(AuthOutcome::AccountLocked.as_str(), "account_locked");
    }

    #[test]
    fn test_metrics_state_disabled() {
        let state = MetricsState::disabled();
        assert!(!state.is_enabled());
        assert!(state.render().is_none());
    }
}
