//! Per-IP rate limiting middleware using governor.

use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    http::{HeaderValue, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use governor::{
    clock::{Clock, DefaultClock},
    middleware::NoOpMiddleware,
    state::keyed::DashMapStateStore,
    Quota, RateLimiter,
};
use serde::Serialize;
use std::{net::IpAddr, net::SocketAddr, num::NonZeroU32, sync::Arc, time::Duration};
use tracing::warn;

pub type KeyedRateLimiter =
    RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock, NoOpMiddleware>;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_secs: u64,
    pub enabled: bool,
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 60,
            window_secs: 60,
            enabled: true,
            burst_size: 30,
        }
    }
}

impl RateLimitConfig {
    pub fn new(requests_per_window: u32, window_secs: u64) -> Self {
        Self {
            requests_per_window,
            window_secs,
            enabled: true,
            burst_size: requests_per_window / 2,
        }
    }

    pub fn strict() -> Self {
        Self {
            requests_per_window: 20,
            window_secs: 60,
            enabled: true,
            burst_size: 10,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    pub fn create_limiter(&self) -> Option<Arc<KeyedRateLimiter>> {
        if !self.enabled {
            return None;
        }

        // Replenish interval: e.g. 60 req / 60s = 1 token per second
        let replenish_interval_ns =
            (self.window_secs as u128 * 1_000_000_000) / self.requests_per_window as u128;
        let replenish_interval = Duration::from_nanos(replenish_interval_ns as u64);

        let quota = Quota::with_period(replenish_interval)
            .expect("Replenish interval should be valid")
            .allow_burst(
                NonZeroU32::new(self.burst_size.max(1)).expect("Burst size should be non-zero"),
            );

        Some(Arc::new(RateLimiter::dashmap(quota)))
    }
}

#[derive(Clone)]
pub struct RateLimitState {
    pub global_limiter: Option<Arc<KeyedRateLimiter>>,
    pub auth_limiter: Option<Arc<KeyedRateLimiter>>,
    pub config: RateLimitConfig,
}

impl RateLimitState {
    pub fn new() -> Self {
        let config = RateLimitConfig::default();
        let auth_config = RateLimitConfig::strict();

        Self {
            global_limiter: config.create_limiter(),
            auth_limiter: auth_config.create_limiter(),
            config,
        }
    }

    pub fn with_config(global_config: RateLimitConfig, auth_config: RateLimitConfig) -> Self {
        Self {
            global_limiter: global_config.create_limiter(),
            auth_limiter: auth_config.create_limiter(),
            config: global_config,
        }
    }

    pub fn disabled() -> Self {
        Self {
            global_limiter: None,
            auth_limiter: None,
            config: RateLimitConfig::disabled(),
        }
    }
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
pub struct RateLimitExceeded {
    pub error: String,
    pub retry_after_secs: u64,
}

impl IntoResponse for RateLimitExceeded {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::to_string(&self)
            .unwrap_or_else(|_| r#"{"error":"Rate limit exceeded"}"#.to_string());

        let mut response = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Content-Type", "application/json")
            .header("Retry-After", self.retry_after_secs.to_string())
            .body(Body::from(body))
            .unwrap();

        if let Ok(value) = HeaderValue::from_str(&self.retry_after_secs.to_string()) {
            response.headers_mut().insert("X-RateLimit-Reset", value);
        }

        response
    }
}

fn client_ip(req: &Request) -> IpAddr {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

pub async fn rate_limit_middleware(
    rate_limit_state: Option<axum::extract::Extension<RateLimitState>>,
    request: Request,
    next: Next,
) -> Result<axum::response::Response, RateLimitExceeded> {
    let state = match rate_limit_state {
        Some(axum::extract::Extension(state)) => state,
        None => return Ok(next.run(request).await),
    };

    let limiter = match &state.global_limiter {
        Some(limiter) => limiter,
        None => return Ok(next.run(request).await),
    };

    let ip = client_ip(&request);

    match limiter.check_key(&ip) {
        Ok(_) => {
            let mut response = next.run(request).await;
            add_rate_limit_headers(&mut response, &state.config);
            Ok(response)
        }
        Err(not_until) => {
            let wait_duration = not_until.wait_time_from(DefaultClock::default().now());
            let retry_after = wait_duration.as_secs().max(1);

            warn!(ip = %ip, retry_after_secs = retry_after, "Rate limit exceeded");

            Err(RateLimitExceeded {
                error: "Too many requests".to_string(),
                retry_after_secs: retry_after,
            })
        }
    }
}

pub async fn auth_rate_limit_middleware(
    rate_limit_state: Option<axum::extract::Extension<RateLimitState>>,
    request: Request,
    next: Next,
) -> Result<axum::response::Response, RateLimitExceeded> {
    let state = match rate_limit_state {
        Some(axum::extract::Extension(state)) => state,
        None => return Ok(next.run(request).await),
    };

    let limiter = match &state.auth_limiter {
        Some(limiter) => limiter,
        None => return Ok(next.run(request).await),
    };

    let ip = client_ip(&request);

    match limiter.check_key(&ip) {
        Ok(_) => {
            let mut response = next.run(request).await;
            add_rate_limit_headers(&mut response, &state.config);
            Ok(response)
        }
        Err(not_until) => {
            let wait_duration = not_until.wait_time_from(DefaultClock::default().now());
            let retry_after = wait_duration.as_secs().max(1);

            warn!(ip = %ip, retry_after_secs = retry_after, "Auth rate limit exceeded");

            Err(RateLimitExceeded {
                error: "Too many authentication attempts".to_string(),
                retry_after_secs: retry_after,
            })
        }
    }
}

fn add_rate_limit_headers(response: &mut axum::response::Response, config: &RateLimitConfig) {
    if let Ok(value) = HeaderValue::from_str(&config.requests_per_window.to_string()) {
        response.headers_mut().insert("X-RateLimit-Limit", value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_window, 60);
        assert_eq!(config.window_secs, 60);
        assert!(config.enabled);
    }

    #[test]
    fn test_rate_limit_config_strict() {
        let config = RateLimitConfig::strict();
        assert_eq!(config.requests_per_window, 20);
        assert!(config.enabled);
    }

    #[test]
    fn test_rate_limit_config_disabled() {
        let config = RateLimitConfig::disabled();
        assert!(!config.enabled);
        assert!(config.create_limiter().is_none());
    }

    #[test]
    fn test_create_limiter() {
        let config = RateLimitConfig::default();
        let limiter = config.create_limiter();
        assert!(limiter.is_some());
    }

    #[test]
    fn test_rate_limit_state_default() {
        let state = RateLimitState::default();
        assert!(state.global_limiter.is_some());
        assert!(state.auth_limiter.is_some());
    }

    #[test]
    fn test_rate_limit_exceeded_response() {
        let exceeded = RateLimitExceeded {
            error: "Too many requests".to_string(),
            retry_after_secs: 60,
        };
        let response = exceeded.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_per_ip_keyed_limiter() {
        let config = RateLimitConfig {
            requests_per_window: 2,
            window_secs: 60,
            enabled: true,
            burst_size: 2,
        };
        let limiter = config.create_limiter().unwrap();

        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();

        // Both IPs get their own budget
        assert!(limiter.check_key(&ip1).is_ok());
        assert!(limiter.check_key(&ip1).is_ok());
        assert!(limiter.check_key(&ip1).is_err()); // ip1 exhausted

        assert!(limiter.check_key(&ip2).is_ok()); // ip2 still has budget
        assert!(limiter.check_key(&ip2).is_ok());
        assert!(limiter.check_key(&ip2).is_err()); // ip2 exhausted
    }
}
