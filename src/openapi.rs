//! OpenAPI documentation configuration.
//!
//! This module provides the OpenAPI (Swagger) documentation for the Signet API.
//! It uses `utoipa` to generate the OpenAPI specification and serves it via Swagger UI.

use axum::Router;
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

use crate::handlers::auth::{
    AuthResponse, ErrorResponse, LoginRequest, RefreshRequest, RefreshResponse, RegisterRequest,
    UserResponse,
};
use crate::pagination::PaginationMeta;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Signet API",
        version = "1.0.0",
        description = "Role-Based Access Control (RBAC) system with JWT authentication.\n\n\
        ## Features\n\
        - JWT Authentication with access and refresh tokens\n\
        - Multi-Project Support with isolated permissions\n\
        - Role-Based Access Control (RBAC)\n\
        - Fine-Grained Permissions per resource/action\n\
        - Per-User Permission Overrides\n\n\
        ## Authentication\n\
        Most endpoints require authentication via JWT bearer token.\n\
        1. Register or login to get an access token\n\
        2. Include the token in requests: `Authorization: Bearer <token>`\n\
        3. Use the refresh token to get new access tokens when expired\n\n\
        ## Project Context\n\
        Project-scoped endpoints (roles, permissions, members) require a token with project context.\n\
        Login with a `project_id` to get a project-scoped token.",
        contact(
            name = "Signet API Support"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers(
        (url = "/", description = "Current server")
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Authentication", description = "User authentication and token management"),
        (name = "Projects", description = "Project management endpoints"),
        (name = "Roles", description = "Role management within projects"),
        (name = "Permissions", description = "Permission management within projects"),
        (name = "Members", description = "Project member management"),
        (name = "User Permissions", description = "Per-user permission overrides")
    ),
    paths(
        crate::handlers::health::health_check_simple,
        crate::handlers::health::health_check,
        crate::handlers::health::ready_check,
        crate::handlers::health::live_check,

        crate::handlers::auth::register,
        crate::handlers::auth::login,
        crate::handlers::auth::refresh_token,
        crate::handlers::auth::logout,
        crate::handlers::auth::logout_all,
        crate::handlers::auth::delete_account,
        crate::handlers::auth::verify_token,
        crate::handlers::auth::get_current_user,
        crate::handlers::auth::revoke_token,
        crate::handlers::auth::forgot_password,
        crate::handlers::auth::reset_password,

        crate::handlers::projects::create_project,
        crate::handlers::projects::list_user_projects,

        crate::handlers::roles::create_role,
        crate::handlers::roles::list_roles,
        crate::handlers::roles::update_role,
        crate::handlers::roles::delete_role,

        crate::handlers::permissions::create_permission,
        crate::handlers::permissions::list_permissions,
        crate::handlers::permissions::check_permission,
        crate::handlers::permissions::check_permissions_bulk,
        crate::handlers::permissions::delete_permission,
        crate::handlers::permissions::assign_permission_to_role,
        crate::handlers::permissions::remove_permission_from_role,
        crate::handlers::permissions::list_role_permissions,

        crate::handlers::members::add_project_member,
        crate::handlers::members::list_project_members,

        crate::handlers::user_permissions::set_user_permission_override,
        crate::handlers::user_permissions::remove_user_permission_override,
        crate::handlers::user_permissions::get_user_permissions,
    ),
    components(
        schemas(
            RegisterRequest,
            LoginRequest,
            RefreshRequest,
            RefreshResponse,
            AuthResponse,
            UserResponse,
            ErrorResponse,
            crate::handlers::auth::VerifyTokenRequest,
            crate::handlers::auth::VerifyTokenResponse,
            crate::handlers::auth::CurrentUserResponse,
            crate::handlers::auth::ProjectContext,
            crate::handlers::auth::ForgotPasswordRequest,
            crate::handlers::auth::ForgotPasswordResponse,
            crate::handlers::auth::ResetPasswordRequest,
            crate::handlers::auth::ResetPasswordResponse,
            crate::handlers::auth::RevokeTokenResponse,

            PaginationMeta,

            crate::models::Project,
            crate::handlers::projects::CreateProjectRequest,
            crate::handlers::projects::ProjectResponse,
            crate::handlers::projects::ProjectListResponse,
            crate::handlers::projects::ProjectWithRole,

            crate::models::Role,
            crate::handlers::roles::CreateRoleRequest,
            crate::handlers::roles::UpdateRoleRequest,
            crate::handlers::roles::RoleResponse,
            crate::handlers::roles::RolesListResponse,

            crate::models::Permission,
            crate::handlers::permissions::CreatePermissionRequest,
            crate::handlers::permissions::AssignPermissionRequest,
            crate::handlers::permissions::PermissionResponse,
            crate::handlers::permissions::PermissionsListResponse,
            crate::handlers::permissions::RolePermissionsResponse,
            crate::handlers::permissions::CheckPermissionRequest,
            crate::handlers::permissions::CheckPermissionResponse,
            crate::handlers::permissions::CheckPermissionsBulkRequest,
            crate::handlers::permissions::CheckPermissionsBulkResponse,
            crate::handlers::permissions::BulkPermissionResult,

            crate::handlers::members::AddMemberRequest,
            crate::handlers::members::MemberResponse,
            crate::handlers::members::MembersListResponse,

            crate::handlers::user_permissions::GrantUserPermissionRequest,
            crate::handlers::user_permissions::UserPermissionOverride,
            crate::handlers::user_permissions::UserPermissionsResponse,
        )
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "JWT access token obtained from /auth/login or /auth/register.\n\
                            Include in requests as: `Authorization: Bearer <token>`",
                        ))
                        .build(),
                ),
            );
        }

        openapi.security = Some(vec![]);
    }
}

pub fn swagger_router() -> Router {
    SwaggerUi::new("/swagger-ui")
        .url("/api-docs/openapi.json", ApiDoc::openapi())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_generation() {
        let spec = ApiDoc::openapi();
        assert_eq!(spec.info.title, "Signet API");
        assert_eq!(spec.info.version, "1.0.0");
    }

    #[test]
    fn test_openapi_has_security_scheme() {
        let spec = ApiDoc::openapi();
        assert!(spec.components.is_some());
        let components = spec.components.unwrap();
        assert!(components.security_schemes.contains_key("bearer_auth"));
    }

    #[test]
    fn test_openapi_has_tags() {
        let spec = ApiDoc::openapi();
        assert!(spec.tags.is_some());
        let tags = spec.tags.unwrap();
        assert!(tags.iter().any(|t| t.name == "Authentication"));
        assert!(tags.iter().any(|t| t.name == "Health"));
    }
}
