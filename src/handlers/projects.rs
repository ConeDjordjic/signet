//! Project management handlers.

use axum::{
    extract::{Query, State},
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
    models::{NewPermission, NewProject, NewProjectMember, NewRole, NewRolePermission, Project},
    pagination::{PaginationMeta, PaginationParams},
    schema::{permissions, project_members, projects, role_permissions, roles},
    AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProjectRequest {
    #[schema(example = "Production API")]
    pub name: String,
    #[schema(example = "production-api")]
    pub slug: String,
    #[schema(example = "Main production API services")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectResponse {
    pub project: Project,
    #[schema(example = "admin")]
    pub role: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectListResponse {
    pub data: Vec<ProjectWithRole>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectWithRole {
    pub project: Project,
    #[schema(example = "editor")]
    pub role: String,
}

#[utoipa::path(
    post,
    path = "/projects",
    tag = "Projects",
    request_body = CreateProjectRequest,
    responses(
        (status = 200, description = "Project created successfully", body = ProjectResponse),
        (status = 400, description = "Invalid request", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 409, description = "Project slug already exists", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_project(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateProjectRequest>,
) -> ApiResult<Json<ProjectResponse>> {
    if payload.name.len() < 3 {
        return Err(ApiError::bad_request(
            "Project name must be at least 3 characters",
            "NAME_TOO_SHORT",
        ));
    }
    if payload.slug.len() < 3 {
        return Err(ApiError::bad_request(
            "Project slug must be at least 3 characters",
            "SLUG_TOO_SHORT",
        ));
    }

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::bad_request("Invalid user ID in token", "INVALID_USER_ID"))?;

    let mut conn = get_db_conn(&state.db_pool)?;

    let result: Result<ProjectResponse, diesel::result::Error> = conn.transaction(|conn| {
        let new_project = NewProject {
            name: payload.name,
            slug: payload.slug,
            description: payload.description,
            owner_id: user_id,
        };

        let project: Project = diesel::insert_into(projects::table)
            .values(&new_project)
            .get_result(conn)
            .map_err(|e| {
                if matches!(e, diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) {
                    diesel::result::Error::NotFound
                } else {
                    e
                }
            })?;

        let admin_role = diesel::insert_into(roles::table)
            .values(&NewRole {
                project_id: project.id,
                name: "admin".to_string(),
                description: Some("Full access to the project".to_string()),
            })
            .get_result::<crate::models::Role>(conn)?;

        let editor_role = diesel::insert_into(roles::table)
            .values(&NewRole {
                project_id: project.id,
                name: "editor".to_string(),
                description: Some("Can edit content".to_string()),
            })
            .get_result::<crate::models::Role>(conn)?;

        diesel::insert_into(roles::table)
            .values(&NewRole {
                project_id: project.id,
                name: "viewer".to_string(),
                description: Some("Read-only access".to_string()),
            })
            .execute(conn)?;

        let manage_members = diesel::insert_into(permissions::table)
            .values(&NewPermission {
                project_id: project.id,
                name: "manage_members".to_string(),
                description: Some("Add and remove project members".to_string()),
                resource: "members".to_string(),
                action: "write".to_string(),
            })
            .get_result::<crate::models::Permission>(conn)?;

        let manage_roles = diesel::insert_into(permissions::table)
            .values(&NewPermission {
                project_id: project.id,
                name: "manage_roles".to_string(),
                description: Some("Create and edit roles".to_string()),
                resource: "roles".to_string(),
                action: "write".to_string(),
            })
            .get_result::<crate::models::Permission>(conn)?;

        let edit_content = diesel::insert_into(permissions::table)
            .values(&NewPermission {
                project_id: project.id,
                name: "edit_content".to_string(),
                description: Some("Edit project content".to_string()),
                resource: "content".to_string(),
                action: "write".to_string(),
            })
            .get_result::<crate::models::Permission>(conn)?;

        let view_content = diesel::insert_into(permissions::table)
            .values(&NewPermission {
                project_id: project.id,
                name: "view_content".to_string(),
                description: Some("View project content".to_string()),
                resource: "content".to_string(),
                action: "read".to_string(),
            })
            .get_result::<crate::models::Permission>(conn)?;

        diesel::insert_into(role_permissions::table)
            .values(vec![
                NewRolePermission { role_id: admin_role.id, permission_id: manage_members.id },
                NewRolePermission { role_id: admin_role.id, permission_id: manage_roles.id },
                NewRolePermission { role_id: admin_role.id, permission_id: edit_content.id },
                NewRolePermission { role_id: admin_role.id, permission_id: view_content.id },
            ])
            .execute(conn)?;

        diesel::insert_into(role_permissions::table)
            .values(vec![
                NewRolePermission { role_id: editor_role.id, permission_id: edit_content.id },
                NewRolePermission { role_id: editor_role.id, permission_id: view_content.id },
            ])
            .execute(conn)?;

        diesel::insert_into(project_members::table)
            .values(&NewProjectMember { project_id: project.id, user_id, role_id: admin_role.id })
            .execute(conn)?;

        info!(project_id = %project.id, project_slug = %project.slug, owner_id = %user_id, "Created project");

        Ok(ProjectResponse { project, role: "admin".to_string() })
    });

    result.map(Json).map_err(|e| {
        if matches!(e, diesel::result::Error::NotFound) {
            ApiError::conflict("A project with this slug already exists", "SLUG_EXISTS")
        } else {
            ApiError::internal(format!("Project creation failed: {}", e), "CREATE_FAILED")
        }
    })
}

#[utoipa::path(
    get,
    path = "/projects",
    tag = "Projects",
    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of user projects", body = ProjectListResponse),
        (status = 400, description = "Invalid user ID in token", body = crate::handlers::auth::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::handlers::auth::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::handlers::auth::ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_user_projects(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(pagination): Query<PaginationParams>,
) -> ApiResult<Json<ProjectListResponse>> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError::bad_request("Invalid user ID in token", "INVALID_USER_ID"))?;

    let mut conn = get_db_conn(&state.db_pool)?;

    let total_count: i64 = project_members::table
        .filter(project_members::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let (limit, offset) = pagination.limit_offset();

    let projects_with_roles: Vec<(Project, String)> = projects::table
        .inner_join(project_members::table.on(project_members::project_id.eq(projects::id)))
        .inner_join(roles::table.on(roles::id.eq(project_members::role_id)))
        .filter(project_members::user_id.eq(user_id))
        .order(projects::created_at.desc())
        .limit(limit)
        .offset(offset)
        .select((Project::as_select(), roles::name))
        .load(&mut conn)
        .map_err(|_| ApiError::db_error())?;

    let data = projects_with_roles
        .into_iter()
        .map(|(project, role)| ProjectWithRole { project, role })
        .collect();

    Ok(Json(ProjectListResponse {
        data,
        pagination: pagination.into_metadata(total_count),
    }))
}
