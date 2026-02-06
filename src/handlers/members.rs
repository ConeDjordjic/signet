//! Project member management handlers.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::jwt::Claims,
    error::{get_db_conn, ApiError, ApiResult},
    helpers::get_project_id,
    models::{NewProjectMember, User},
    pagination::{PaginationMeta, PaginationParams},
    schema::{project_members, roles, users},
    AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddMemberRequest {
    #[schema(example = "newmember@example.com")]
    pub user_email: String,
    #[schema(example = "editor")]
    pub role_name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MemberResponse {
    pub user_id: Uuid,
    #[schema(example = "member@example.com")]
    pub email: String,
    #[schema(example = "John Doe")]
    pub full_name: Option<String>,
    #[schema(example = "editor")]
    pub role: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MembersListResponse {
    pub data: Vec<MemberResponse>,
    pub pagination: PaginationMeta,
}

#[utoipa::path(
    post,
    path = "/members",
    tag = "Members",
    request_body = AddMemberRequest,
    responses(
        (status = 201, description = "Member added", body = MemberResponse),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 404, description = "User or role not found", body = crate::handlers::auth::ErrorResponse),
        (status = 409, description = "User is already a member", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_project_member(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<AddMemberRequest>,
) -> ApiResult<(StatusCode, Json<MemberResponse>)> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let user: User = users::table
        .filter(users::email.eq(payload.user_email.to_lowercase()))
        .first(&mut conn)
        .map_err(|_| {
            warn!(email = %payload.user_email, "Attempted to add non-existent user to project");
            ApiError::not_found("User not found", "USER_NOT_FOUND")
        })?;

    let role: (Uuid, String) = roles::table
        .filter(roles::project_id.eq(project_id))
        .filter(roles::name.eq(&payload.role_name))
        .select((roles::id, roles::name))
        .first(&mut conn)
        .map_err(|_| {
            warn!(role_name = %payload.role_name, project_id = %project_id, "Attempted to assign non-existent role");
            ApiError::not_found(format!("Role '{}' not found in project", payload.role_name), "ROLE_NOT_FOUND")
        })?;

    let existing: Option<Uuid> = project_members::table
        .filter(project_members::project_id.eq(project_id))
        .filter(project_members::user_id.eq(user.id))
        .select(project_members::id)
        .first(&mut conn)
        .optional()
        .map_err(|_| ApiError::db_error())?;

    if existing.is_some() {
        return Err(ApiError::conflict(
            "User is already a member of this project",
            "ALREADY_MEMBER",
        ));
    }

    diesel::insert_into(project_members::table)
        .values(&NewProjectMember {
            project_id,
            user_id: user.id,
            role_id: role.0,
        })
        .execute(&mut conn)
        .map_err(|_| ApiError::conflict("Failed to add member", "INSERT_FAILED"))?;

    info!(user_id = %user.id, project_id = %project_id, role = %role.1, "Added member to project");

    Ok((
        StatusCode::CREATED,
        Json(MemberResponse {
            user_id: user.id,
            email: user.email,
            full_name: user.full_name,
            role: role.1,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/members",
    tag = "Members",
    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of project members", body = MembersListResponse),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_project_members(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(pagination): Query<PaginationParams>,
) -> ApiResult<Json<MembersListResponse>> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let total_count: i64 = project_members::table
        .filter(project_members::project_id.eq(project_id))
        .count()
        .get_result(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let (limit, offset) = pagination.limit_offset();

    let members: Vec<(Uuid, String, Option<String>, String)> = project_members::table
        .inner_join(users::table.on(users::id.eq(project_members::user_id)))
        .inner_join(roles::table.on(roles::id.eq(project_members::role_id)))
        .filter(project_members::project_id.eq(project_id))
        .order(users::email.asc())
        .limit(limit)
        .offset(offset)
        .select((users::id, users::email, users::full_name, roles::name))
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let data = members
        .into_iter()
        .map(|(user_id, email, full_name, role)| MemberResponse {
            user_id,
            email,
            full_name,
            role,
        })
        .collect();

    Ok(Json(MembersListResponse {
        data,
        pagination: pagination.into_metadata(total_count),
    }))
}
