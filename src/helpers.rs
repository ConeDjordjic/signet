//! Shared helper functions for handlers.

use axum::{http::StatusCode, Json};
use uuid::Uuid;

use crate::auth::jwt::Claims;
use crate::error::ApiError;

pub fn get_project_id(claims: &Claims) -> Result<Uuid, (StatusCode, Json<ApiError>)> {
    claims
        .project_id
        .as_ref()
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or_else(|| ApiError::bad_request("Invalid project context", "INVALID_PROJECT_CONTEXT"))
}
