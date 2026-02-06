//! Signet - Role-based access control with JWT authentication.

pub mod auth;
pub mod cache;
pub mod config;
pub mod error;
pub mod events;
pub mod grpc;
pub mod handlers;
pub mod helpers;
pub mod middleware;
pub mod models;
pub mod openapi;
pub mod pagination;
pub mod schema;
pub mod telemetry;

use axum::{
    http::StatusCode,
    middleware as axum_middleware,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};

use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use std::sync::Arc;
use std::time::Duration;

use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use auth::jwt::JwtConfig;
use auth::lockout::LockoutManager;
use auth::password::PasswordPolicy;
use cache::{create_redis_pool, CacheServices};
use middleware::{
    metrics::metrics_middleware,
    rate_limit::{
        auth_rate_limit_middleware, rate_limit_middleware, RateLimitConfig, RateLimitState,
    },
    request_id::request_id_middleware,
};
use telemetry::MetricsState;

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: DbPool,
    pub rate_limit: RateLimitState,
    pub jwt_config: Arc<JwtConfig>,
    pub cache: CacheServices,
    pub lockout: Arc<LockoutManager>,
    pub password_policy: PasswordPolicy,
    pub password_hash_cost: u32,
    pub rotate_refresh_tokens: bool,
    pub metrics: MetricsState,
}

impl AppState {
    pub fn new(db_pool: DbPool, redis_pool: Option<deadpool_redis::Pool>, config: &Config) -> Self {
        let rate_limit = if config.security.rate_limiting_enabled {
            RateLimitState::with_config(
                RateLimitConfig::new(config.security.rate_limit_requests_per_minute, 60),
                RateLimitConfig::strict(),
            )
        } else {
            RateLimitState::disabled()
        };

        let jwt_config = JwtConfig::from_env_with_expiry(
            config.jwt.access_token_expiry_secs,
            config.jwt.refresh_token_expiry_secs,
            config.jwt.issuer.clone(),
            config.jwt.audience.clone(),
        );

        let redis_pool = redis_pool.or_else(|| create_redis_pool(&config.redis));
        let cache = CacheServices::new(redis_pool.clone());
        let lockout = LockoutManager::new(
            redis_pool,
            config.security.max_failed_login_attempts,
            config.security.lockout_duration_mins,
        );

        let password_policy = if config.security.require_password_complexity {
            PasswordPolicy::complex(config.security.min_password_length)
        } else {
            PasswordPolicy {
                min_length: config.security.min_password_length,
                ..Default::default()
            }
        };

        let metrics = MetricsState::new(config.telemetry.metrics_enabled);

        Self {
            db_pool,
            rate_limit,
            jwt_config: Arc::new(jwt_config),
            cache,
            lockout: Arc::new(lockout),
            password_policy,
            password_hash_cost: config.security.password_hash_cost,
            rotate_refresh_tokens: config.security.rotate_refresh_tokens,
            metrics,
        }
    }
}

pub fn create_router(state: AppState, config: &config::Config) -> Router {
    let cors = build_cors_layer(config);
    let body_limit = RequestBodyLimitLayer::new(config.server.max_body_size);

    #[allow(deprecated)]
    let timeout = TimeoutLayer::new(Duration::from_secs(config.server.request_timeout_secs));

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    let rate_limit_state = state.rate_limit.clone();

    let metrics_state = state.metrics.clone();
    let public_routes = Router::new()
        .route("/health", get(handlers::health::health_check_simple))
        .route("/health/status", get(handlers::health::health_check))
        .route("/health/ready", get(handlers::health::ready_check))
        .route("/health/live", get(handlers::health::live_check))
        .route(
            "/metrics",
            get(telemetry::metrics::metrics_handler).with_state(metrics_state),
        )
        .with_state(state.clone());

    let auth_routes = Router::new()
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .route("/auth/refresh", post(handlers::auth::refresh_token))
        .route("/auth/logout", post(handlers::auth::logout))
        .route("/auth/verify", post(handlers::auth::verify_token))
        .route(
            "/auth/forgot-password",
            post(handlers::auth::forgot_password),
        )
        .route("/auth/reset-password", post(handlers::auth::reset_password))
        .layer(axum_middleware::from_fn(auth_rate_limit_middleware))
        .with_state(state.clone());

    let protected_routes = Router::new()
        .route("/projects", post(handlers::projects::create_project))
        .route("/projects", get(handlers::projects::list_user_projects))
        .route("/auth/logout-all", post(handlers::auth::logout_all))
        .route("/auth/revoke", post(handlers::auth::revoke_token))
        .route("/auth/account", delete(handlers::auth::delete_account))
        .route("/auth/me", get(handlers::auth::get_current_user))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ))
        .with_state(state.clone());

    let project_routes = Router::new()
        .route("/members", post(handlers::members::add_project_member))
        .route("/members", get(handlers::members::list_project_members))
        .route("/roles", post(handlers::roles::create_role))
        .route("/roles", get(handlers::roles::list_roles))
        .route("/roles/{role_id}", put(handlers::roles::update_role))
        .route("/roles/{role_id}", delete(handlers::roles::delete_role))
        .route(
            "/permissions",
            post(handlers::permissions::create_permission),
        )
        .route("/permissions", get(handlers::permissions::list_permissions))
        .route(
            "/permissions/check",
            post(handlers::permissions::check_permission),
        )
        .route(
            "/permissions/check-bulk",
            post(handlers::permissions::check_permissions_bulk),
        )
        .route(
            "/permissions/{permission_id}",
            delete(handlers::permissions::delete_permission),
        )
        .route(
            "/roles/{role_id}/permissions",
            post(handlers::permissions::assign_permission_to_role),
        )
        .route(
            "/roles/{role_id}/permissions",
            get(handlers::permissions::list_role_permissions),
        )
        .route(
            "/roles/{role_id}/permissions/{permission_id}",
            delete(handlers::permissions::remove_permission_from_role),
        )
        .route(
            "/user-permissions",
            post(handlers::user_permissions::set_user_permission_override),
        )
        .route(
            "/user-permissions/{user_id}",
            get(handlers::user_permissions::get_user_permissions),
        )
        .route(
            "/user-permissions/{user_id}/{permission_id}",
            delete(handlers::user_permissions::remove_user_permission_override),
        )
        .layer(axum_middleware::from_fn(
            middleware::auth::project_auth_middleware,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::auth_middleware,
        ))
        .with_state(state.clone());

    let docs_routes = openapi::swagger_router();

    Router::new()
        .merge(docs_routes)
        .merge(public_routes)
        .merge(auth_routes)
        .merge(protected_routes)
        .merge(project_routes)
        .fallback(fallback_handler)
        .layer(axum_middleware::from_fn(metrics_middleware))
        .layer(axum_middleware::from_fn(rate_limit_middleware))
        .layer(axum::Extension(rate_limit_state))
        .layer(axum_middleware::from_fn(request_id_middleware))
        .layer(trace_layer)
        .layer(timeout)
        .layer(body_limit)
        .layer(cors)
}

async fn fallback_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "Not found", "code": "NOT_FOUND"})),
    )
}

fn build_cors_layer(config: &config::Config) -> CorsLayer {
    use axum::http::header::HeaderName;
    use axum::http::Method;

    let is_wildcard_origin = config.cors.allowed_origins.contains(&"*".to_string())
        || config.cors.allowed_origins.is_empty();

    let methods: Vec<Method> = config
        .cors
        .allowed_methods
        .iter()
        .filter_map(|m| m.parse().ok())
        .collect();

    let headers: Vec<HeaderName> = config
        .cors
        .allowed_headers
        .iter()
        .filter_map(|h| h.parse().ok())
        .collect();

    if config.cors.allow_credentials && is_wildcard_origin {
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
            .allow_methods(methods)
            .allow_headers(headers)
            .allow_credentials(true)
            .max_age(Duration::from_secs(config.cors.max_age_secs))
    } else if config.cors.allow_credentials {
        let origins: Vec<_> = config
            .cors
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();

        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(methods)
            .allow_headers(headers)
            .allow_credentials(true)
            .max_age(Duration::from_secs(config.cors.max_age_secs))
    } else {
        let cors = if is_wildcard_origin {
            CorsLayer::new().allow_origin(Any)
        } else {
            let origins: Vec<_> = config
                .cors
                .allowed_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            CorsLayer::new().allow_origin(origins)
        };

        cors.allow_methods(methods)
            .allow_headers(headers)
            .allow_credentials(false)
            .max_age(Duration::from_secs(config.cors.max_age_secs))
    }
}

pub fn create_db_pool(config: &config::Config) -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new(&config.database.url);
    r2d2::Pool::builder()
        .max_size(config.database.max_connections)
        .min_idle(Some(config.database.min_connections))
        .connection_timeout(Duration::from_secs(config.database.connection_timeout_secs))
        .idle_timeout(Some(Duration::from_secs(config.database.idle_timeout_secs)))
        .build(manager)
        .expect("Failed to create database pool")
}

pub fn create_db_pool_with_url(database_url: &str) -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder()
        .max_size(10)
        .min_idle(Some(2))
        .connection_timeout(Duration::from_secs(30))
        .idle_timeout(Some(Duration::from_secs(600)))
        .build(manager)
        .expect("Failed to create database pool")
}

pub fn init_tracing(config: &config::Config) {
    telemetry::init_telemetry(config);
}

pub use telemetry::tracing::shutdown_telemetry;

pub use config::Config;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<AppState>();
    }

    #[test]
    fn test_build_cors_layer_wildcard() {
        let mut config = Config::default_for_testing();
        config.cors.allowed_origins = vec!["*".to_string()];
        let _ = build_cors_layer(&config);
    }

    #[test]
    fn test_build_cors_layer_specific_origins() {
        let mut config = Config::default_for_testing();
        config.cors.allowed_origins = vec![
            "http://localhost:3000".to_string(),
            "https://example.com".to_string(),
        ];
        let _ = build_cors_layer(&config);
    }
}
