//! Permission management handlers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    auth::jwt::Claims,
    error::{get_db_conn, ApiError, ApiResult},
    helpers::get_project_id,
    models::{NewPermission, NewRolePermission, Permission, UserPermission},
    pagination::{PaginationMeta, PaginationParams},
    schema::{permissions, project_members, role_permissions, roles, user_permissions},
    telemetry::record_permission_check,
    AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePermissionRequest {
    #[schema(example = "delete_posts")]
    pub name: String,
    #[schema(example = "Allows deleting posts")]
    pub description: Option<String>,
    #[schema(example = "posts")]
    pub resource: String,
    #[schema(example = "delete")]
    pub action: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignPermissionRequest {
    pub permission_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionResponse {
    pub permission: Permission,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionsListResponse {
    pub data: Vec<Permission>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RolePermissionsResponse {
    pub role_id: Uuid,
    pub data: Vec<Permission>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckPermissionRequest {
    pub user_id: Uuid,
    #[schema(example = "delete_posts")]
    pub permission: Option<String>,
    #[schema(example = "posts")]
    pub resource: Option<String>,
    #[schema(example = "delete")]
    pub action: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CheckPermissionResponse {
    pub allowed: bool,
    pub permission: Option<Permission>,
    #[schema(example = "granted_by_role")]
    pub reason: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckPermissionsBulkRequest {
    pub user_id: Uuid,
    #[schema(example = json!(["view_content", "edit_content", "delete_posts"]))]
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BulkPermissionResult {
    #[schema(example = "view_content")]
    pub permission: String,
    pub allowed: bool,
    #[schema(example = "granted_by_role")]
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CheckPermissionsBulkResponse {
    pub results: Vec<BulkPermissionResult>,
    pub all_allowed: bool,
    pub denied: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/permissions",
    tag = "Permissions",
    request_body = CreatePermissionRequest,
    responses(
        (status = 200, description = "Permission created", body = PermissionResponse),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 409, description = "Permission already exists", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_permission(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreatePermissionRequest>,
) -> ApiResult<Json<PermissionResponse>> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let permission: Permission = diesel::insert_into(permissions::table)
        .values(&NewPermission {
            project_id,
            name: payload.name.clone(),
            description: payload.description,
            resource: payload.resource,
            action: payload.action,
        })
        .get_result(&mut conn)
        .map_err(|e| {
            warn!(error = %e, name = %payload.name, "Failed to create permission");
            ApiError::conflict("Permission already exists", "PERMISSION_EXISTS")
        })?;

    info!(permission_id = %permission.id, name = %permission.name, project_id = %project_id, "Created permission");
    Ok(Json(PermissionResponse { permission }))
}

#[utoipa::path(
    get,
    path = "/permissions",
    tag = "Permissions",
    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of permissions", body = PermissionsListResponse),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_permissions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(pagination): Query<PaginationParams>,
) -> ApiResult<Json<PermissionsListResponse>> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let total_count: i64 = permissions::table
        .filter(permissions::project_id.eq(project_id))
        .count()
        .get_result(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let (limit, offset) = pagination.limit_offset();
    let perms: Vec<Permission> = permissions::table
        .filter(permissions::project_id.eq(project_id))
        .order(permissions::name.asc())
        .limit(limit)
        .offset(offset)
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    Ok(Json(PermissionsListResponse {
        data: perms,
        pagination: pagination.into_metadata(total_count),
    }))
}

#[utoipa::path(
    delete,
    path = "/permissions/{permission_id}",
    tag = "Permissions",
    params(("permission_id" = Uuid, Path, description = "Permission ID")),
    responses(
        (status = 204, description = "Permission deleted"),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 404, description = "Permission not found", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_permission(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(permission_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let deleted = diesel::delete(
        permissions::table
            .filter(permissions::id.eq(permission_id))
            .filter(permissions::project_id.eq(project_id)),
    )
    .execute(&mut conn)
    .map_err(|_| ApiError::internal("Failed to delete permission", "DELETE_FAILED"))?;

    if deleted == 0 {
        return Err(ApiError::not_found(
            "Permission not found",
            "PERMISSION_NOT_FOUND",
        ));
    }

    info!(permission_id = %permission_id, project_id = %project_id, "Deleted permission");
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/roles/{role_id}/permissions",
    tag = "Permissions",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    request_body = AssignPermissionRequest,
    responses(
        (status = 201, description = "Permission assigned"),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 404, description = "Role or permission not found", body = crate::handlers::auth::ErrorResponse),
        (status = 409, description = "Permission already assigned", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn assign_permission_to_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(role_id): Path<Uuid>,
    Json(payload): Json<AssignPermissionRequest>,
) -> ApiResult<StatusCode> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let role_exists = roles::table
        .filter(roles::id.eq(role_id))
        .filter(roles::project_id.eq(project_id))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|_| ApiError::db_error())?
        > 0;

    if !role_exists {
        return Err(ApiError::not_found("Role not found", "ROLE_NOT_FOUND"));
    }

    let perm_exists = permissions::table
        .filter(permissions::id.eq(payload.permission_id))
        .filter(permissions::project_id.eq(project_id))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|_| ApiError::db_error())?
        > 0;

    if !perm_exists {
        return Err(ApiError::not_found(
            "Permission not found",
            "PERMISSION_NOT_FOUND",
        ));
    }

    diesel::insert_into(role_permissions::table)
        .values(&NewRolePermission {
            role_id,
            permission_id: payload.permission_id,
        })
        .execute(&mut conn)
        .map_err(|_| ApiError::conflict("Permission already assigned", "ALREADY_ASSIGNED"))?;

    info!(role_id = %role_id, permission_id = %payload.permission_id, "Assigned permission to role");
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    delete,
    path = "/roles/{role_id}/permissions/{permission_id}",
    tag = "Permissions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("permission_id" = Uuid, Path, description = "Permission ID")
    ),
    responses(
        (status = 204, description = "Permission removed"),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 404, description = "Role not found", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_permission_from_role(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((role_id, permission_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let role_exists = roles::table
        .filter(roles::id.eq(role_id))
        .filter(roles::project_id.eq(project_id))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|_| ApiError::db_error())?
        > 0;

    if !role_exists {
        return Err(ApiError::not_found("Role not found", "ROLE_NOT_FOUND"));
    }

    diesel::delete(
        role_permissions::table
            .filter(role_permissions::role_id.eq(role_id))
            .filter(role_permissions::permission_id.eq(permission_id)),
    )
    .execute(&mut conn)
    .map_err(|_| ApiError::internal("Failed to remove permission", "DELETE_FAILED"))?;

    info!(role_id = %role_id, permission_id = %permission_id, "Removed permission from role");
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/roles/{role_id}/permissions",
    tag = "Permissions",
    params(("role_id" = Uuid, Path, description = "Role ID"), PaginationParams),
    responses(
        (status = 200, description = "Paginated list of role permissions", body = RolePermissionsResponse),
        (status = 400, description = "Invalid project context", body = crate::handlers::auth::ErrorResponse),
        (status = 404, description = "Role not found", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_role_permissions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(role_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> ApiResult<Json<RolePermissionsResponse>> {
    let project_id = get_project_id(&claims)?;
    let mut conn = get_db_conn(&state.db_pool)?;

    let role_exists = roles::table
        .filter(roles::id.eq(role_id))
        .filter(roles::project_id.eq(project_id))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|_| ApiError::db_error())?
        > 0;

    if !role_exists {
        return Err(ApiError::not_found("Role not found", "ROLE_NOT_FOUND"));
    }

    let total_count: i64 = role_permissions::table
        .filter(role_permissions::role_id.eq(role_id))
        .count()
        .get_result(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let (limit, offset) = pagination.limit_offset();
    let perms: Vec<Permission> = role_permissions::table
        .inner_join(permissions::table)
        .filter(role_permissions::role_id.eq(role_id))
        .order(permissions::name.asc())
        .limit(limit)
        .offset(offset)
        .select(Permission::as_select())
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    Ok(Json(RolePermissionsResponse {
        role_id,
        data: perms,
        pagination: pagination.into_metadata(total_count),
    }))
}

#[utoipa::path(
    post,
    path = "/permissions/check",
    tag = "Permissions",
    request_body = CheckPermissionRequest,
    responses(
        (status = 200, description = "Permission check result", body = CheckPermissionResponse),
        (status = 400, description = "Invalid request", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn check_permission(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CheckPermissionRequest>,
) -> ApiResult<Json<CheckPermissionResponse>> {
    let start = std::time::Instant::now();
    let project_id = get_project_id(&claims)?;

    if payload.permission.is_none() && (payload.resource.is_none() || payload.action.is_none()) {
        return Err(ApiError::bad_request(
            "Either 'permission' or both 'resource' and 'action' must be provided",
            "INVALID_REQUEST",
        ));
    }

    let mut conn = get_db_conn(&state.db_pool)?;

    let permission: Option<Permission> = if let Some(ref name) = payload.permission {
        permissions::table
            .filter(permissions::project_id.eq(project_id))
            .filter(permissions::name.eq(name))
            .first(&mut conn)
            .optional()
            .map_err(|_| ApiError::db_error())?
    } else {
        permissions::table
            .filter(permissions::project_id.eq(project_id))
            .filter(permissions::resource.eq(payload.resource.as_ref().unwrap()))
            .filter(permissions::action.eq(payload.action.as_ref().unwrap()))
            .first(&mut conn)
            .optional()
            .map_err(|_| ApiError::db_error())?
    };

    let permission = match permission {
        Some(p) => p,
        None => {
            record_permission_check(false, false, start.elapsed());
            return Ok(Json(CheckPermissionResponse {
                allowed: false,
                permission: None,
                reason: "permission_not_found".to_string(),
            }));
        }
    };

    let user_override: Option<UserPermission> = user_permissions::table
        .filter(user_permissions::project_id.eq(project_id))
        .filter(user_permissions::user_id.eq(payload.user_id))
        .filter(user_permissions::permission_id.eq(permission.id))
        .first(&mut conn)
        .optional()
        .map_err(|_| ApiError::db_error())?;

    if let Some(o) = user_override {
        record_permission_check(false, o.granted, start.elapsed());
        return Ok(Json(CheckPermissionResponse {
            allowed: o.granted,
            permission: Some(permission),
            reason: if o.granted {
                "granted_by_override"
            } else {
                "denied_by_override"
            }
            .to_string(),
        }));
    }

    let has_role_permission = project_members::table
        .inner_join(roles::table.on(roles::id.eq(project_members::role_id)))
        .inner_join(role_permissions::table.on(role_permissions::role_id.eq(roles::id)))
        .filter(project_members::project_id.eq(project_id))
        .filter(project_members::user_id.eq(payload.user_id))
        .filter(role_permissions::permission_id.eq(permission.id))
        .count()
        .get_result::<i64>(&mut conn)
        .map_err(|_| ApiError::db_error())?
        > 0;

    if has_role_permission {
        record_permission_check(false, true, start.elapsed());
        return Ok(Json(CheckPermissionResponse {
            allowed: true,
            permission: Some(permission),
            reason: "granted_by_role".to_string(),
        }));
    }

    record_permission_check(false, false, start.elapsed());
    Ok(Json(CheckPermissionResponse {
        allowed: false,
        permission: Some(permission),
        reason: "not_granted".to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/permissions/check-bulk",
    tag = "Permissions",
    request_body = CheckPermissionsBulkRequest,
    responses(
        (status = 200, description = "Bulk permission check results", body = CheckPermissionsBulkResponse),
        (status = 400, description = "Invalid request", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn check_permissions_bulk(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CheckPermissionsBulkRequest>,
) -> ApiResult<Json<CheckPermissionsBulkResponse>> {
    let project_id = get_project_id(&claims)?;

    if payload.permissions.is_empty() {
        return Err(ApiError::bad_request(
            "At least one permission must be provided",
            "INVALID_REQUEST",
        ));
    }

    let mut conn = get_db_conn(&state.db_pool)?;

    let perms: Vec<Permission> = permissions::table
        .filter(permissions::project_id.eq(project_id))
        .filter(permissions::name.eq_any(&payload.permissions))
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let perm_map: HashMap<String, &Permission> =
        perms.iter().map(|p| (p.name.clone(), p)).collect();

    let user_overrides: Vec<UserPermission> = user_permissions::table
        .filter(user_permissions::project_id.eq(project_id))
        .filter(user_permissions::user_id.eq(payload.user_id))
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let override_map: HashMap<Uuid, bool> = user_overrides
        .iter()
        .map(|o| (o.permission_id, o.granted))
        .collect();

    let role_perm_ids: Vec<Uuid> = project_members::table
        .inner_join(roles::table.on(roles::id.eq(project_members::role_id)))
        .inner_join(role_permissions::table.on(role_permissions::role_id.eq(roles::id)))
        .filter(project_members::project_id.eq(project_id))
        .filter(project_members::user_id.eq(payload.user_id))
        .select(role_permissions::permission_id)
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let role_perm_set: HashSet<Uuid> = role_perm_ids.into_iter().collect();

    let mut results = Vec::with_capacity(payload.permissions.len());
    let mut denied = Vec::new();

    for name in &payload.permissions {
        let (allowed, reason) = match perm_map.get(name) {
            Some(perm) => {
                if let Some(&granted) = override_map.get(&perm.id) {
                    (
                        granted,
                        if granted {
                            "granted_by_override"
                        } else {
                            "denied_by_override"
                        },
                    )
                } else if role_perm_set.contains(&perm.id) {
                    (true, "granted_by_role")
                } else {
                    (false, "not_granted")
                }
            }
            None => (false, "permission_not_found"),
        };

        if !allowed {
            denied.push(name.clone());
        }
        results.push(BulkPermissionResult {
            permission: name.clone(),
            allowed,
            reason: reason.to_string(),
        });
    }

    Ok(Json(CheckPermissionsBulkResponse {
        all_allowed: denied.is_empty(),
        results,
        denied,
    }))
}
