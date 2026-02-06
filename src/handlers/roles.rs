//! Role management handlers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::jwt::Claims,
    error::{get_db_conn, ApiError, ApiResult},
    helpers::get_project_id,
    models::{NewRole, Role},
    pagination::{PaginationMeta, PaginationParams},
    schema::roles,
    AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    #[schema(example = "moderator")]
    pub name: String,
    #[schema(example = "Can moderate content and manage users")]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    #[schema(example = "senior-moderator")]
    pub name: Option<String>,
    #[schema(example = "Senior content moderator with elevated privileges")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleResponse {
    pub role: Role,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RolesListResponse {
    pub data: Vec<Role>,
    pub pagination: PaginationMeta,
}

#[utoipa::path(
    post,
    path = "/roles",
    tag = "Roles",
    request_body = CreateRoleRequest,
    responses(
        (status = 200, description = "Role created successfully", body = RoleResponse),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 403, description = "Project-scoped token required", body = crate::handlers::auth::ErrorResponse),
        (status = 409, description = "Role already exists", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateRoleRequest>,
) -> ApiResult<Json<RoleResponse>> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let new_role = NewRole {
        project_id,
        name: payload.name.clone(),
        description: payload.description,
    };

    let role: Role = diesel::insert_into(roles::table)
        .values(&new_role)
        .get_result(&mut conn)
        .map_err(|_| ApiError::conflict("Failed to create role", "ROLE_CREATE_FAILED"))?;

    info!(role_id = %role.id, role_name = %role.name, project_id = %project_id, "Created role");

    Ok(Json(RoleResponse { role }))
}

#[utoipa::path(
    get,
    path = "/roles",
    tag = "Roles",
    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of roles", body = RolesListResponse),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 403, description = "Project-scoped token required", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_roles(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(pagination): Query<PaginationParams>,
) -> ApiResult<Json<RolesListResponse>> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let total_count: i64 = roles::table
        .filter(roles::project_id.eq(project_id))
        .count()
        .get_result(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let (limit, offset) = pagination.limit_offset();

    let roles_list: Vec<Role> = roles::table
        .filter(roles::project_id.eq(project_id))
        .order(roles::name.asc())
        .limit(limit)
        .offset(offset)
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    Ok(Json(RolesListResponse {
        data: roles_list,
        pagination: pagination.into_metadata(total_count),
    }))
}

#[utoipa::path(
    put,
    path = "/roles/{role_id}",
    tag = "Roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated successfully", body = RoleResponse),
        (status = 400, description = "Invalid request", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 404, description = "Role not found", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(role_id): Path<Uuid>,
    Json(payload): Json<UpdateRoleRequest>,
) -> ApiResult<Json<RoleResponse>> {
    let project_id = get_project_id(&claims)?;

    if payload.name.is_none() && payload.description.is_none() {
        return Err(ApiError::bad_request(
            "At least one field (name or description) must be provided",
            "NO_FIELDS_TO_UPDATE",
        ));
    }

    let mut conn = get_db_conn(&state.db_pool)?;

    let query = diesel::update(
        roles::table
            .filter(roles::id.eq(role_id))
            .filter(roles::project_id.eq(project_id)),
    );

    let updated_role: Role = match (payload.name, payload.description) {
        (Some(name), Some(desc)) => query
            .set((roles::name.eq(name), roles::description.eq(desc)))
            .get_result(&mut conn),
        (Some(name), None) => query.set(roles::name.eq(name)).get_result(&mut conn),
        (None, Some(desc)) => query.set(roles::description.eq(desc)).get_result(&mut conn),
        (None, None) => unreachable!(),
    }
    .map_err(|_| ApiError::not_found("Role not found in this project", "ROLE_NOT_FOUND"))?;

    info!(role_id = %role_id, project_id = %project_id, "Updated role");

    Ok(Json(RoleResponse { role: updated_role }))
}

#[utoipa::path(
    delete,
    path = "/roles/{role_id}",
    tag = "Roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 204, description = "Role deleted successfully"),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 404, description = "Role not found", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let deleted_count = diesel::delete(
        roles::table
            .filter(roles::id.eq(role_id))
            .filter(roles::project_id.eq(project_id)),
    )
    .execute(&mut conn)
    .map_err(|_| ApiError::internal("Failed to delete role", "DELETE_FAILED"))?;

    if deleted_count == 0 {
        return Err(ApiError::not_found(
            "Role not found in this project",
            "ROLE_NOT_FOUND",
        ));
    }

    info!(role_id = %role_id, project_id = %project_id, "Deleted role");

    Ok(StatusCode::NO_CONTENT)
}
