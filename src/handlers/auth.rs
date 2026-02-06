//! Authentication handlers.

use axum::{
    extract::State,
    http::{header, StatusCode},
    Extension, Json,
};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{error, info, warn};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::{
        jwt::{Claims, JwtConfig},
        password::PasswordService,
    },
    error::{get_db_conn, ApiError, ApiResult},
    events::{
        outbox::OutboxService, AggregateType, EventType, LoginFailedPayload, LoginSuccessPayload,
        UserRegisteredPayload,
    },
    models::{NewPasswordResetToken, NewUser, User},
    schema::{
        password_reset_tokens, project_members, projects, refresh_tokens, user_permissions, users,
    },
    telemetry::{record_auth_attempt, AuthOutcome},
    AppState,
};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "user@example.com")]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    #[schema(example = "securepassword123", min_length = 8)]
    pub password: String,
    #[schema(example = "John Doe")]
    pub full_name: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "user@example.com")]
    pub email: String,
    #[schema(example = "securepassword123")]
    pub password: String,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub project_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub user: UserResponse,
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub access_token: String,
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RefreshResponse {
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub access_token: String,
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,
    #[schema(example = "user@example.com")]
    pub email: String,
    #[schema(example = "John Doe")]
    pub full_name: Option<String>,
    #[schema(example = true)]
    pub is_active: bool,
    pub created_at: chrono::NaiveDateTime,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
            is_active: user.is_active,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema, Default)]
pub struct ErrorResponse {
    #[schema(example = "Invalid credentials")]
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "AUTH_INVALID_CREDENTIALS")]
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = refresh_tokens)]
struct NewRefreshToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: chrono::NaiveDateTime,
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn store_refresh_token(
    conn: &mut PgConnection,
    user_id: Uuid,
    token: &str,
    expires_in_days: i64,
) -> Result<(), diesel::result::Error> {
    let token_hash = hash_token(token);
    let expires_at = (Utc::now() + Duration::days(expires_in_days)).naive_utc();

    diesel::insert_into(refresh_tokens::table)
        .values(&NewRefreshToken {
            user_id,
            token_hash,
            expires_at,
        })
        .execute(conn)?;

    Ok(())
}

fn verify_stored_token(conn: &mut PgConnection, token: &str) -> Result<Uuid, &'static str> {
    let token_hash = hash_token(token);
    let now = Utc::now().naive_utc();

    let result: Result<(Uuid, chrono::NaiveDateTime), _> = refresh_tokens::table
        .filter(refresh_tokens::token_hash.eq(&token_hash))
        .select((refresh_tokens::user_id, refresh_tokens::expires_at))
        .first(conn);

    match result {
        Ok((user_id, expires_at)) => {
            if expires_at < now {
                let _ = diesel::delete(
                    refresh_tokens::table.filter(refresh_tokens::token_hash.eq(&token_hash)),
                )
                .execute(conn);
                Err("Refresh token has expired")
            } else {
                Ok(user_id)
            }
        }
        Err(_) => Err("Invalid refresh token"),
    }
}

fn invalidate_token(conn: &mut PgConnection, token: &str) -> Result<(), diesel::result::Error> {
    let token_hash = hash_token(token);
    diesel::delete(refresh_tokens::table.filter(refresh_tokens::token_hash.eq(&token_hash)))
        .execute(conn)?;
    Ok(())
}

fn cleanup_expired_tokens(conn: &mut PgConnection, user_id: Uuid) {
    let now = Utc::now().naive_utc();
    let result = diesel::delete(
        refresh_tokens::table
            .filter(refresh_tokens::user_id.eq(user_id))
            .filter(refresh_tokens::expires_at.lt(now)),
    )
    .execute(conn);

    if let Ok(count) = result {
        if count > 0 {
            info!(user_id = %user_id, deleted_count = count, "Cleaned up expired refresh tokens");
        }
    }
}

fn generate_tokens(
    jwt_config: &Arc<JwtConfig>,
    conn: &mut PgConnection,
    user: &User,
    project_id: Option<Uuid>,
    role: Option<String>,
) -> ApiResult<(String, String)> {
    let access_token = jwt_config
        .generate_access_token(user.id, &user.email, project_id, role)
        .map_err(|e| {
            error!(error = %e, "Token generation failed");
            ApiError::internal("Token generation failed", "TOKEN_GENERATION_ERROR")
        })?;

    let refresh_token = jwt_config.generate_refresh_token(user.id).map_err(|e| {
        error!(error = %e, "Token generation failed");
        ApiError::internal("Token generation failed", "TOKEN_GENERATION_ERROR")
    })?;

    store_refresh_token(conn, user.id, &refresh_token, 7).map_err(|e| {
        error!(error = %e, "Failed to store refresh token");
        ApiError::internal("Token storage failed", "TOKEN_STORAGE_ERROR")
    })?;

    Ok((access_token, refresh_token))
}

#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "Authentication",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Registration successful", body = AuthResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 409, description = "User already exists", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> ApiResult<Json<AuthResponse>> {
    if let Err(e) = payload.validate() {
        return Err(ApiError::bad_request(
            format!("Validation error: {}", e),
            "VALIDATION_ERROR",
        ));
    }

    if let Err(e) = state.password_policy.validate(&payload.password) {
        return Err(ApiError::bad_request(
            e.to_string(),
            "PASSWORD_POLICY_VIOLATION",
        ));
    }

    let password_hash =
        PasswordService::hash_password_with_cost(&payload.password, state.password_hash_cost)
            .map_err(|e| {
                error!(error = %e, "Password hashing failed");
                ApiError::internal("Failed to process password", "PASSWORD_HASH_ERROR")
            })?;

    let new_user = NewUser {
        email: payload.email.to_lowercase(),
        password_hash,
        full_name: payload.full_name,
    };

    let mut conn = get_db_conn(&state.db_pool)?;

    let user: User = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(&mut conn)
        .map_err(|e| {
            warn!(error = %e, email = %new_user.email, "Failed to register user");
            ApiError::conflict("User with this email already exists", "USER_EXISTS")
        })?;

    let (access_token, refresh_token) =
        generate_tokens(&state.jwt_config, &mut conn, &user, None, None)?;

    let _ = OutboxService::emit(
        &mut conn,
        EventType::UserRegistered,
        AggregateType::User,
        user.id,
        serde_json::to_value(UserRegisteredPayload {
            email: user.email.clone(),
        })
        .unwrap_or_default(),
        Some(user.id),
        None,
        None,
    );

    info!(user_id = %user.id, email = %user.email, "User registered");

    Ok(Json(AuthResponse {
        user: user.into(),
        access_token,
        refresh_token,
    }))
}

#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "Authentication",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 403, description = "User not a member of project", body = ErrorResponse),
        (status = 423, description = "Account locked", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> ApiResult<Json<AuthResponse>> {
    if let Err(e) = payload.validate() {
        return Err(ApiError::bad_request(
            format!("Validation error: {}", e),
            "VALIDATION_ERROR",
        ));
    }

    if state.lockout.is_locked(&payload.email).await {
        let remaining = state
            .lockout
            .get_lockout_remaining(&payload.email)
            .await
            .unwrap_or(0);
        warn!(email = %payload.email, "Login attempt for locked account");
        record_auth_attempt("login", AuthOutcome::AccountLocked);
        return Err(ApiError::locked(
            format!("Account is locked. Try again in {} seconds", remaining),
            "ACCOUNT_LOCKED",
        ));
    }

    let mut conn = get_db_conn(&state.db_pool)?;

    let user: User = users::table
        .filter(users::email.eq(payload.email.to_lowercase()))
        .first(&mut conn)
        .map_err(|_| {
            warn!(email = %payload.email, "Login attempt for non-existent user");
            ApiError::unauthorized("Invalid credentials", "INVALID_CREDENTIALS")
        })?;

    if !user.is_active {
        warn!(user_id = %user.id, "Login attempt for inactive user");
        record_auth_attempt("login", AuthOutcome::AccountInactive);
        return Err(ApiError::forbidden(
            "Account is inactive",
            "ACCOUNT_INACTIVE",
        ));
    }

    let is_valid = PasswordService::verify_password(&payload.password, &user.password_hash)
        .map_err(|e| {
            error!(error = %e, "Password verification error");
            ApiError::internal("Password verification error", "PASSWORD_VERIFY_ERROR")
        })?;

    if !is_valid {
        warn!(user_id = %user.id, "Failed login attempt - invalid password");
        record_auth_attempt("login", AuthOutcome::InvalidCredentials);
        let _ = state.lockout.record_failed_attempt(&payload.email).await;

        let _ = OutboxService::emit(
            &mut conn,
            EventType::LoginFailed,
            AggregateType::User,
            user.id,
            serde_json::to_value(LoginFailedPayload {
                email: payload.email.clone(),
                reason: "invalid_password".to_string(),
            })
            .unwrap_or_default(),
            Some(user.id),
            None,
            None,
        );

        return Err(ApiError::unauthorized(
            "Invalid credentials",
            "INVALID_CREDENTIALS",
        ));
    }

    let _ = state.lockout.clear_failed_attempts(&payload.email).await;

    let (project_id, role) = if let Some(pid) = payload.project_id {
        use crate::schema::roles;

        let member_role: Option<(Uuid, String)> = project_members::table
            .inner_join(roles::table.on(roles::id.eq(project_members::role_id)))
            .filter(project_members::project_id.eq(pid))
            .filter(project_members::user_id.eq(user.id))
            .select((roles::id, roles::name))
            .first(&mut conn)
            .optional()
            .map_err(|e| {
                error!(error = %e, "Database error checking project membership");
                ApiError::db_error()
            })?;

        match member_role {
            Some((_, role_name)) => (Some(pid), Some(role_name)),
            None => {
                warn!(user_id = %user.id, project_id = %pid, "User not a member of project");
                return Err(ApiError::forbidden(
                    "User is not a member of this project",
                    "NOT_PROJECT_MEMBER",
                ));
            }
        }
    } else {
        (None, None)
    };

    cleanup_expired_tokens(&mut conn, user.id);

    let (access_token, refresh_token) =
        generate_tokens(&state.jwt_config, &mut conn, &user, project_id, role)?;

    let _ = OutboxService::emit(
        &mut conn,
        EventType::LoginSuccess,
        AggregateType::User,
        user.id,
        serde_json::to_value(LoginSuccessPayload {
            email: user.email.clone(),
            project_id,
        })
        .unwrap_or_default(),
        Some(user.id),
        project_id,
        None,
    );

    record_auth_attempt("login", AuthOutcome::Success);
    info!(user_id = %user.id, email = %user.email, has_project_context = project_id.is_some(), "User logged in");

    Ok(Json(AuthResponse {
        user: user.into(),
        access_token,
        refresh_token,
    }))
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "Authentication",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Tokens refreshed", body = RefreshResponse),
        (status = 401, description = "Invalid or expired refresh token", body = ErrorResponse),
        (status = 403, description = "User account is inactive", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> ApiResult<Json<RefreshResponse>> {
    let refresh_claims = state
        .jwt_config
        .verify_refresh_token(&payload.refresh_token)
        .map_err(|_| {
            ApiError::unauthorized("Invalid or expired refresh token", "INVALID_REFRESH_TOKEN")
        })?;

    let user_id = Uuid::parse_str(&refresh_claims.sub).map_err(|e| {
        error!(error = %e, "Invalid user ID in refresh token");
        ApiError::bad_request("Invalid token format", "INVALID_TOKEN_FORMAT")
    })?;

    let mut conn = get_db_conn(&state.db_pool)?;

    let stored_user_id = verify_stored_token(&mut conn, &payload.refresh_token).map_err(|msg| {
        warn!(user_id = %user_id, "Refresh token not found in database");
        ApiError::unauthorized(msg, "INVALID_REFRESH_TOKEN")
    })?;

    if stored_user_id != user_id {
        warn!(claimed_user_id = %user_id, stored_user_id = %stored_user_id, "Refresh token user mismatch");
        return Err(ApiError::unauthorized(
            "Invalid refresh token",
            "TOKEN_USER_MISMATCH",
        ));
    }

    let user: User = users::table
        .filter(users::id.eq(user_id))
        .first(&mut conn)
        .map_err(|_| ApiError::unauthorized("User not found", "USER_NOT_FOUND"))?;

    if !user.is_active {
        return Err(ApiError::forbidden(
            "User account is inactive",
            "ACCOUNT_INACTIVE",
        ));
    }

    if state.rotate_refresh_tokens {
        invalidate_token(&mut conn, &payload.refresh_token).map_err(|e| {
            error!(error = %e, "Failed to invalidate old refresh token");
            ApiError::internal("Token invalidation failed", "TOKEN_INVALIDATION_ERROR")
        })?;

        let (access_token, refresh_token) =
            generate_tokens(&state.jwt_config, &mut conn, &user, None, None)?;

        info!(user_id = %user.id, "Tokens refreshed (rotated)");

        Ok(Json(RefreshResponse {
            access_token,
            refresh_token,
        }))
    } else {
        let access_token = state
            .jwt_config
            .generate_access_token(user.id, &user.email, None, None)
            .map_err(|e| {
                error!(error = %e, "Token generation failed");
                ApiError::internal("Token generation failed", "TOKEN_GENERATION_ERROR")
            })?;

        info!(user_id = %user.id, "Access token refreshed");

        Ok(Json(RefreshResponse {
            access_token,
            refresh_token: payload.refresh_token,
        }))
    }
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "Authentication",
    request_body = RefreshRequest,
    responses(
        (status = 204, description = "Logged out"),
        (status = 401, description = "Invalid token", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> ApiResult<StatusCode> {
    let mut conn = get_db_conn(&state.db_pool)?;
    let _ = invalidate_token(&mut conn, &payload.refresh_token);
    info!("User logged out");
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/auth/logout-all",
    tag = "Authentication",
    responses(
        (status = 204, description = "Logged out from all devices"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn logout_all(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::bad_request("Invalid token", "INVALID_TOKEN"))?;

    let mut conn = get_db_conn(&state.db_pool)?;

    let deleted_count =
        diesel::delete(refresh_tokens::table.filter(refresh_tokens::user_id.eq(user_id)))
            .execute(&mut conn)
            .map_err(|e| {
                error!(error = %e, "Failed to delete refresh tokens");
                ApiError::internal("Failed to logout", "LOGOUT_ERROR")
            })?;

    let access_token_ttl = state.jwt_config.access_token_expiry as u64;
    let _ = state
        .cache
        .token_revocation
        .revoke_all_user_tokens(user_id, access_token_ttl)
        .await;

    let _ = OutboxService::emit(
        &mut conn,
        EventType::LogoutCompleted,
        AggregateType::User,
        user_id,
        serde_json::json!({"all_devices": true}),
        Some(user_id),
        None,
        None,
    );

    info!(user_id = %user_id, tokens_deleted = deleted_count, "User logged out from all devices");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RevokeTokenResponse {
    #[schema(example = "Token revoked")]
    pub message: String,
}

/// Revokes the current access token so it can no longer be used.
/// The token is added to a revocation list and will be rejected by the auth middleware.
#[utoipa::path(
    post,
    path = "/auth/revoke",
    tag = "Authentication",
    responses(
        (status = 200, description = "Token revoked", body = RevokeTokenResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_token(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    req: axum::extract::Request,
) -> ApiResult<Json<RevokeTokenResponse>> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("Missing token", "MISSING_TOKEN"))?;

    let token_hash = hash_token(token);

    let remaining_secs = (claims.exp - chrono::Utc::now().timestamp()).max(0) as u64;
    if remaining_secs == 0 {
        return Ok(Json(RevokeTokenResponse {
            message: "Token already expired".to_string(),
        }));
    }

    if !state.cache.token_revocation.is_available() {
        warn!("Token revocation requested but Redis is not configured");
        return Ok(Json(RevokeTokenResponse {
            message: "Token revocation not available (Redis not configured)".to_string(),
        }));
    }

    state
        .cache
        .token_revocation
        .revoke_token(&token_hash, remaining_secs)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to revoke token");
            ApiError::internal("Failed to revoke token", "REVOCATION_ERROR")
        })?;

    let user_id = &claims.sub;
    info!(user_id = %user_id, "Access token revoked");

    Ok(Json(RevokeTokenResponse {
        message: "Token revoked".to_string(),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyTokenRequest {
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyTokenResponse {
    pub valid: bool,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub user_id: Option<Uuid>,
    #[schema(example = "user@example.com")]
    pub email: Option<String>,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub project_id: Option<Uuid>,
    #[schema(example = "admin")]
    pub role: Option<String>,
    pub expires_at: Option<i64>,
}

/// Verifies an access token and returns its claims.
/// Designed for microservice-to-microservice token validation.
#[utoipa::path(
    post,
    path = "/auth/verify",
    tag = "Authentication",
    request_body = VerifyTokenRequest,
    responses(
        (status = 200, description = "Token verification result", body = VerifyTokenResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse)
    )
)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(payload): Json<VerifyTokenRequest>,
) -> Json<VerifyTokenResponse> {
    match state.jwt_config.verify_access_token(&payload.token) {
        Ok(claims) => {
            let user_id = Uuid::parse_str(&claims.sub).ok();
            let project_id = claims
                .project_id
                .as_ref()
                .and_then(|id| Uuid::parse_str(id).ok());

            Json(VerifyTokenResponse {
                valid: true,
                user_id,
                email: Some(claims.email),
                project_id,
                role: claims.role,
                expires_at: Some(claims.exp),
            })
        }
        Err(_) => Json(VerifyTokenResponse {
            valid: false,
            user_id: None,
            email: None,
            project_id: None,
            role: None,
            expires_at: None,
        }),
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CurrentUserResponse {
    pub user: UserResponse,
    pub project_context: Option<ProjectContext>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectContext {
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub project_id: Uuid,
    #[schema(example = "admin")]
    pub role: String,
}

/// Returns the currently authenticated user's information.
#[utoipa::path(
    get,
    path = "/auth/me",
    tag = "Authentication",
    responses(
        (status = 200, description = "Current user information", body = CurrentUserResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_current_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<Json<CurrentUserResponse>> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::unauthorized("Invalid user ID in token", "INVALID_USER_ID"))?;

    let mut conn = get_db_conn(&state.db_pool)?;

    let user: User = users::table
        .filter(users::id.eq(user_id))
        .first(&mut conn)
        .map_err(|_| ApiError::not_found("User not found", "USER_NOT_FOUND"))?;

    let project_context = match (&claims.project_id, &claims.role) {
        (Some(pid), Some(role)) => Uuid::parse_str(pid).ok().map(|project_id| ProjectContext {
            project_id,
            role: role.clone(),
        }),
        _ => None,
    };

    Ok(Json(CurrentUserResponse {
        user: user.into(),
        project_context,
    }))
}

/// Deletes the authenticated user's account and all associated data.
#[utoipa::path(
    delete,
    path = "/auth/account",
    tag = "Authentication",
    responses(
        (status = 204, description = "Account deleted successfully"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
        (status = 409, description = "Cannot delete account - user owns projects with no other admins", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_account(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<StatusCode> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::unauthorized("Invalid user ID in token", "INVALID_USER_ID"))?;

    let mut conn = get_db_conn(&state.db_pool)?;

    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let owned_projects: Vec<Uuid> = projects::table
            .filter(projects::owner_id.eq(user_id))
            .select(projects::id)
            .load(conn)?;

        for project_id in &owned_projects {
            use crate::schema::roles;
            let other_admin: Option<Uuid> = project_members::table
                .inner_join(roles::table.on(roles::id.eq(project_members::role_id)))
                .filter(project_members::project_id.eq(project_id))
                .filter(project_members::user_id.ne(user_id))
                .filter(roles::name.eq("admin"))
                .select(project_members::user_id)
                .first(conn)
                .optional()?;

            if let Some(new_owner_id) = other_admin {
                diesel::update(projects::table.filter(projects::id.eq(project_id)))
                    .set(projects::owner_id.eq(new_owner_id))
                    .execute(conn)?;

                info!(project_id = %project_id, old_owner = %user_id, new_owner = %new_owner_id, "Transferred project ownership");
            } else {
                diesel::delete(
                    user_permissions::table
                        .filter(user_permissions::project_id.eq(project_id)),
                )
                .execute(conn)?;

                diesel::delete(
                    project_members::table
                        .filter(project_members::project_id.eq(project_id)),
                )
                .execute(conn)?;

                use crate::schema::role_permissions;
                let role_ids: Vec<Uuid> = roles::table
                    .filter(roles::project_id.eq(project_id))
                    .select(roles::id)
                    .load(conn)?;

                if !role_ids.is_empty() {
                    diesel::delete(
                        role_permissions::table
                            .filter(role_permissions::role_id.eq_any(&role_ids)),
                    )
                    .execute(conn)?;
                }

                diesel::delete(roles::table.filter(roles::project_id.eq(project_id)))
                    .execute(conn)?;

                use crate::schema::permissions;
                diesel::delete(
                    permissions::table.filter(permissions::project_id.eq(project_id)),
                )
                .execute(conn)?;

                diesel::delete(projects::table.filter(projects::id.eq(project_id)))
                    .execute(conn)?;

                info!(project_id = %project_id, "Deleted project with no other admins");
            }
        }

        diesel::delete(project_members::table.filter(project_members::user_id.eq(user_id)))
            .execute(conn)?;

        diesel::delete(user_permissions::table.filter(user_permissions::user_id.eq(user_id)))
            .execute(conn)?;

        diesel::delete(refresh_tokens::table.filter(refresh_tokens::user_id.eq(user_id)))
            .execute(conn)?;

        diesel::delete(users::table.filter(users::id.eq(user_id))).execute(conn)?;

        let _ = OutboxService::emit(
            conn,
            EventType::AccountDeleted,
            AggregateType::User,
            user_id,
            serde_json::json!({"user_id": user_id.to_string()}),
            Some(user_id),
            None,
            None,
        );

        Ok(())
    })
    .map_err(|e| {
        error!(error = %e, "Failed to delete user account");
        ApiError::internal("Failed to delete account", "DELETE_ERROR")
    })?;

    info!(user_id = %user_id, "User account deleted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ForgotPasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    #[schema(example = "user@example.com")]
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ForgotPasswordResponse {
    #[schema(example = "Password reset token created")]
    pub message: String,
    /// The reset token. Your backend should send this to the user via email.
    /// Null if no active account exists for the email.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "a1b2c3d4e5f6...")]
    pub reset_token: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    #[schema(example = "abc123...")]
    pub token: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    #[schema(example = "newSecurePassword123", min_length = 8)]
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResetPasswordResponse {
    #[schema(example = "Password has been reset")]
    pub message: String,
}

fn generate_reset_token() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Request a password reset token.
/// In development mode, returns the token directly.
/// In production, the token should be sent via email (not implemented).
#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    tag = "Authentication",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Reset initiated", body = ForgotPasswordResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse)
    )
)]
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> ApiResult<Json<ForgotPasswordResponse>> {
    if let Err(e) = payload.validate() {
        return Err(ApiError::bad_request(
            format!("Validation error: {}", e),
            "VALIDATION_ERROR",
        ));
    }

    let mut conn = get_db_conn(&state.db_pool)?;

    let user: Option<User> = users::table
        .filter(users::email.eq(payload.email.to_lowercase()))
        .first(&mut conn)
        .optional()
        .map_err(|e| {
            error!(error = %e, "Database error looking up user");
            ApiError::db_error()
        })?;

    let Some(user) = user else {
        return Ok(Json(ForgotPasswordResponse {
            message: "No active account found".to_string(),
            reset_token: None,
        }));
    };

    if !user.is_active {
        return Ok(Json(ForgotPasswordResponse {
            message: "No active account found".to_string(),
            reset_token: None,
        }));
    }

    diesel::delete(password_reset_tokens::table.filter(password_reset_tokens::user_id.eq(user.id)))
        .execute(&mut conn)
        .ok();

    let token = generate_reset_token();
    let token_hash = hash_token(&token);
    let expires_at = (Utc::now() + Duration::minutes(30)).naive_utc();

    diesel::insert_into(password_reset_tokens::table)
        .values(&NewPasswordResetToken {
            user_id: user.id,
            token_hash,
            expires_at,
        })
        .execute(&mut conn)
        .map_err(|e| {
            error!(error = %e, "Failed to create password reset token");
            ApiError::internal("Failed to initiate password reset", "RESET_TOKEN_ERROR")
        })?;

    info!(user_id = %user.id, "Password reset requested");

    Ok(Json(ForgotPasswordResponse {
        message: "Password reset token created".to_string(),
        reset_token: Some(token),
    }))
}

/// Reset password using a reset token.
#[utoipa::path(
    post,
    path = "/auth/reset-password",
    tag = "Authentication",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset successful", body = ResetPasswordResponse),
        (status = 400, description = "Invalid or expired token", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> ApiResult<Json<ResetPasswordResponse>> {
    if let Err(e) = payload.validate() {
        return Err(ApiError::bad_request(
            format!("Validation error: {}", e),
            "VALIDATION_ERROR",
        ));
    }

    if let Err(e) = state.password_policy.validate(&payload.password) {
        return Err(ApiError::bad_request(
            e.to_string(),
            "PASSWORD_POLICY_VIOLATION",
        ));
    }

    let mut conn = get_db_conn(&state.db_pool)?;

    let token_hash = hash_token(&payload.token);
    let now = Utc::now().naive_utc();

    let reset_token: Option<(Uuid, Uuid)> = password_reset_tokens::table
        .filter(password_reset_tokens::token_hash.eq(&token_hash))
        .filter(password_reset_tokens::expires_at.gt(now))
        .filter(password_reset_tokens::used_at.is_null())
        .select((password_reset_tokens::id, password_reset_tokens::user_id))
        .first(&mut conn)
        .optional()
        .map_err(|e| {
            error!(error = %e, "Database error looking up reset token");
            ApiError::db_error()
        })?;

    let Some((token_id, user_id)) = reset_token else {
        return Err(ApiError::bad_request(
            "Invalid or expired reset token",
            "INVALID_RESET_TOKEN",
        ));
    };

    let password_hash =
        PasswordService::hash_password_with_cost(&payload.password, state.password_hash_cost)
            .map_err(|e| {
                error!(error = %e, "Password hashing failed");
                ApiError::internal("Failed to process password", "PASSWORD_HASH_ERROR")
            })?;

    diesel::update(users::table.filter(users::id.eq(user_id)))
        .set((
            users::password_hash.eq(password_hash),
            users::updated_at.eq(now),
        ))
        .execute(&mut conn)
        .map_err(|e| {
            error!(error = %e, "Failed to update password");
            ApiError::internal("Failed to reset password", "PASSWORD_UPDATE_ERROR")
        })?;

    diesel::update(password_reset_tokens::table.filter(password_reset_tokens::id.eq(token_id)))
        .set(password_reset_tokens::used_at.eq(Some(now)))
        .execute(&mut conn)
        .ok();

    diesel::delete(refresh_tokens::table.filter(refresh_tokens::user_id.eq(user_id)))
        .execute(&mut conn)
        .ok();

    let access_token_ttl = state.jwt_config.access_token_expiry as u64;
    let _ = state
        .cache
        .token_revocation
        .revoke_all_user_tokens(user_id, access_token_ttl)
        .await;

    info!(user_id = %user_id, "Password reset completed");

    Ok(Json(ResetPasswordResponse {
        message: "Password has been reset".to_string(),
    }))
}
