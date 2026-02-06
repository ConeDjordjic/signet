//! Per-user permission override handlers.

use axum::{
    extract::{Path, State},
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
    models::{NewUserPermission, Permission, UserPermission},
    schema::{permissions, project_members, role_permissions, roles, user_permissions},
    AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct GrantUserPermissionRequest {
    pub user_id: Uuid,
    pub permission_id: Uuid,
    #[schema(example = true)]
    pub granted: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserPermissionOverride {
    pub permission: Permission,
    #[schema(example = true)]
    pub granted: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserPermissionsResponse {
    pub user_id: Uuid,
    pub role_permissions: Vec<Permission>,
    pub overrides: Vec<UserPermissionOverride>,
    pub effective_permissions: Vec<Permission>,
}

#[utoipa::path(
    post,
    path = "/user-permissions",
    tag = "User Permissions",
    request_body = GrantUserPermissionRequest,
    responses(
        (status = 201, description = "Permission override set"),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_user_permission_override(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<GrantUserPermissionRequest>,
) -> ApiResult<StatusCode> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let existing = user_permissions::table
        .filter(user_permissions::project_id.eq(project_id))
        .filter(user_permissions::user_id.eq(payload.user_id))
        .filter(user_permissions::permission_id.eq(payload.permission_id))
        .first::<UserPermission>(&mut conn)
        .optional()
        .map_err(|_| ApiError::db_error())?;

    if let Some(existing_perm) = existing {
        diesel::update(user_permissions::table.filter(user_permissions::id.eq(existing_perm.id)))
            .set(user_permissions::granted.eq(payload.granted))
            .execute(&mut conn)
            .map_err(|_| {
                ApiError::internal("Failed to update permission override", "UPDATE_FAILED")
            })?;

        info!(user_id = %payload.user_id, permission_id = %payload.permission_id, granted = payload.granted, "Updated user permission override");
    } else {
        diesel::insert_into(user_permissions::table)
            .values(&NewUserPermission {
                project_id,
                user_id: payload.user_id,
                permission_id: payload.permission_id,
                granted: payload.granted,
            })
            .execute(&mut conn)
            .map_err(|_| {
                ApiError::internal("Failed to create permission override", "CREATE_FAILED")
            })?;

        info!(user_id = %payload.user_id, permission_id = %payload.permission_id, granted = payload.granted, "Created user permission override");
    }

    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    delete,
    path = "/user-permissions/{user_id}/{permission_id}",
    tag = "User Permissions",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("permission_id" = Uuid, Path, description = "Permission ID")
    ),
    responses(
        (status = 204, description = "Permission override removed"),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_user_permission_override(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((user_id, permission_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let deleted = diesel::delete(
        user_permissions::table
            .filter(user_permissions::project_id.eq(project_id))
            .filter(user_permissions::user_id.eq(user_id))
            .filter(user_permissions::permission_id.eq(permission_id)),
    )
    .execute(&mut conn)
    .map_err(|_| ApiError::internal("Failed to remove permission override", "DELETE_FAILED"))?;

    if deleted > 0 {
        info!(user_id = %user_id, permission_id = %permission_id, "Removed user permission override");
    }

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/user-permissions/{user_id}",
    tag = "User Permissions",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User permissions retrieved", body = UserPermissionsResponse),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_permissions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<UserPermissionsResponse>> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let role_perms: Vec<Permission> = project_members::table
        .inner_join(roles::table.on(roles::id.eq(project_members::role_id)))
        .inner_join(role_permissions::table.on(role_permissions::role_id.eq(roles::id)))
        .inner_join(permissions::table.on(permissions::id.eq(role_permissions::permission_id)))
        .filter(project_members::project_id.eq(project_id))
        .filter(project_members::user_id.eq(user_id))
        .select(Permission::as_select())
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let user_perms: Vec<UserPermission> = user_permissions::table
        .filter(user_permissions::project_id.eq(project_id))
        .filter(user_permissions::user_id.eq(user_id))
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let override_perm_ids: Vec<Uuid> = user_perms.iter().map(|up| up.permission_id).collect();
    let override_perms: Vec<Permission> = if !override_perm_ids.is_empty() {
        permissions::table
            .filter(permissions::id.eq_any(&override_perm_ids))
            .load(&mut conn)
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let overrides: Vec<UserPermissionOverride> = user_perms
        .iter()
        .filter_map(|up| {
            override_perms
                .iter()
                .find(|p| p.id == up.permission_id)
                .map(|perm| UserPermissionOverride {
                    permission: perm.clone(),
                    granted: up.granted,
                })
        })
        .collect();

    let mut effective = role_perms.clone();
    for o in &overrides {
        if o.granted {
            if !effective.iter().any(|p| p.id == o.permission.id) {
                effective.push(o.permission.clone());
            }
        } else {
            effective.retain(|p| p.id != o.permission.id);
        }
    }

    Ok(Json(UserPermissionsResponse {
        user_id,
        role_permissions: role_perms,
        overrides,
        effective_permissions: effective,
    }))
}
