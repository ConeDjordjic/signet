//! Shared error handling utilities.

use axum::{http::StatusCode, Json};
use serde::Serialize;
use tracing::error;
use utoipa::ToSchema;

use crate::DbPool;

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    pub error: String,
    pub code: String,
}

impl ApiError {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
        }
    }

    pub fn bad_request(
        error: impl Into<String>,
        code: impl Into<String>,
    ) -> (StatusCode, Json<Self>) {
        (StatusCode::BAD_REQUEST, Json(Self::new(error, code)))
    }

    pub fn unauthorized(
        error: impl Into<String>,
        code: impl Into<String>,
    ) -> (StatusCode, Json<Self>) {
        (StatusCode::UNAUTHORIZED, Json(Self::new(error, code)))
    }

    pub fn forbidden(
        error: impl Into<String>,
        code: impl Into<String>,
    ) -> (StatusCode, Json<Self>) {
        (StatusCode::FORBIDDEN, Json(Self::new(error, code)))
    }

    pub fn not_found(
        error: impl Into<String>,
        code: impl Into<String>,
    ) -> (StatusCode, Json<Self>) {
        (StatusCode::NOT_FOUND, Json(Self::new(error, code)))
    }

    pub fn conflict(error: impl Into<String>, code: impl Into<String>) -> (StatusCode, Json<Self>) {
        (StatusCode::CONFLICT, Json(Self::new(error, code)))
    }

    pub fn locked(error: impl Into<String>, code: impl Into<String>) -> (StatusCode, Json<Self>) {
        (StatusCode::LOCKED, Json(Self::new(error, code)))
    }

    pub fn internal(error: impl Into<String>, code: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Self::new(error, code)),
        )
    }

    pub fn db_error() -> (StatusCode, Json<Self>) {
        Self::internal("Database error", "DB_ERROR")
    }
}

pub type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

pub fn get_db_conn(
    pool: &DbPool,
) -> Result<
    diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::PgConnection>>,
    (StatusCode, Json<ApiError>),
> {
    pool.get().map_err(|e| {
        error!(error = %e, "Database connection error");
        ApiError::internal("Database connection error", "DB_CONNECTION_ERROR")
    })
}
