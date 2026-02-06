//! Authentication middleware.

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;

/// Validates JWT access tokens and stores claims in request extensions.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({"error": "Missing authorization header", "code": "MISSING_AUTH_HEADER"}),
                ),
            )
                .into_response()
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid authorization header format", "code": "INVALID_AUTH_FORMAT"})),
        )
            .into_response()
    })?;

    let claims = state.jwt_config.verify_access_token(token).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid or expired token", "code": "INVALID_TOKEN"})),
        )
            .into_response()
    })?;

    let token_hash = hash_token(token);
    if state
        .cache
        .token_revocation
        .is_token_revoked(&token_hash)
        .await
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Token has been revoked", "code": "TOKEN_REVOKED"})),
        )
            .into_response());
    }

    if let Ok(user_id) = Uuid::parse_str(&claims.sub) {
        if state
            .cache
            .token_revocation
            .is_user_token_revoked(user_id, claims.iat)
            .await
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Token has been revoked", "code": "TOKEN_REVOKED"})),
            )
                .into_response());
        }
    }

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Requires project context in the token.
pub async fn project_auth_middleware(req: Request, next: Next) -> Result<Response, Response> {
    let claims = req.extensions().get::<crate::auth::jwt::Claims>().cloned();

    match claims {
        Some(c) if c.project_id.is_some() => Ok(next.run(req).await),
        _ => Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Project context required. Login with a project_id to access this resource.", "code": "PROJECT_CONTEXT_REQUIRED"})),
        )
            .into_response()),
    }
}
