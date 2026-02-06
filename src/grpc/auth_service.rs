//! gRPC AuthService implementation.

use diesel::prelude::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{debug, instrument};
use uuid::Uuid;

use crate::auth::jwt::JwtConfig;
use crate::schema::{permissions, project_members, role_permissions, roles, user_permissions};
use crate::DbPool;

use super::proto::auth_service_server::AuthService;
use super::proto::{
    CheckPermissionRequest, CheckPermissionResponse, CheckPermissionsRequest,
    CheckPermissionsResponse, PermissionResult, VerifyTokenRequest, VerifyTokenResponse,
};

pub struct AuthServiceImpl {
    db_pool: DbPool,
    jwt_config: Arc<JwtConfig>,
}

impl AuthServiceImpl {
    pub fn new(db_pool: DbPool, jwt_config: Arc<JwtConfig>) -> Self {
        Self {
            db_pool,
            jwt_config,
        }
    }

    #[allow(clippy::result_large_err)]
    fn get_conn(
        &self,
    ) -> Result<
        diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::PgConnection>>,
        Status,
    > {
        self.db_pool
            .get()
            .map_err(|e| Status::internal(format!("Database connection error: {}", e)))
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    #[instrument(skip(self, request), fields(token_len = request.get_ref().token.len()))]
    async fn verify_token(
        &self,
        request: Request<VerifyTokenRequest>,
    ) -> Result<Response<VerifyTokenResponse>, Status> {
        let req = request.into_inner();

        match self.jwt_config.verify_access_token(&req.token) {
            Ok(claims) => {
                debug!(user_id = %claims.sub, "Token verified successfully");
                Ok(Response::new(VerifyTokenResponse {
                    valid: true,
                    user_id: claims.sub,
                    email: claims.email,
                    project_id: claims.project_id,
                    role: claims.role,
                    expires_at: claims.exp,
                }))
            }
            Err(e) => {
                debug!(error = %e, "Token verification failed");
                Ok(Response::new(VerifyTokenResponse {
                    valid: false,
                    user_id: String::new(),
                    email: String::new(),
                    project_id: None,
                    role: None,
                    expires_at: 0,
                }))
            }
        }
    }

    #[instrument(skip(self, request))]
    async fn check_permission(
        &self,
        request: Request<CheckPermissionRequest>,
    ) -> Result<Response<CheckPermissionResponse>, Status> {
        let req = request.into_inner();

        let claims = self
            .jwt_config
            .verify_access_token(&req.token)
            .map_err(|_| Status::unauthenticated("Invalid token"))?;

        let project_id = claims
            .project_id
            .as_ref()
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(|| Status::failed_precondition("Token must have project context"))?;

        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("Invalid user ID in token"))?;

        let mut conn = self.get_conn()?;

        let allowed =
            check_user_permission(&mut conn, project_id, user_id, &req.resource, &req.action)?;

        debug!(
            user_id = %user_id,
            project_id = %project_id,
            resource = %req.resource,
            action = %req.action,
            allowed,
            "Permission check completed"
        );

        Ok(Response::new(CheckPermissionResponse {
            allowed,
            user_id: user_id.to_string(),
            project_id: Some(project_id.to_string()),
        }))
    }

    #[instrument(skip(self, request))]
    async fn check_permissions(
        &self,
        request: Request<CheckPermissionsRequest>,
    ) -> Result<Response<CheckPermissionsResponse>, Status> {
        let req = request.into_inner();

        let claims = self
            .jwt_config
            .verify_access_token(&req.token)
            .map_err(|_| Status::unauthenticated("Invalid token"))?;

        let project_id = claims
            .project_id
            .as_ref()
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(|| Status::failed_precondition("Token must have project context"))?;

        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("Invalid user ID in token"))?;

        let mut conn = self.get_conn()?;

        let mut results = Vec::with_capacity(req.permissions.len());

        for perm in req.permissions {
            let allowed = check_user_permission(
                &mut conn,
                project_id,
                user_id,
                &perm.resource,
                &perm.action,
            )?;

            results.push(PermissionResult {
                resource: perm.resource,
                action: perm.action,
                allowed,
            });
        }

        debug!(
            user_id = %user_id,
            project_id = %project_id,
            checks = results.len(),
            "Bulk permission check completed"
        );

        Ok(Response::new(CheckPermissionsResponse {
            user_id: user_id.to_string(),
            project_id: Some(project_id.to_string()),
            results,
        }))
    }
}

#[allow(clippy::result_large_err)]
fn check_user_permission(
    conn: &mut PgConnection,
    project_id: Uuid,
    user_id: Uuid,
    resource: &str,
    action: &str,
) -> Result<bool, Status> {
    let permission: Option<(Uuid,)> = permissions::table
        .filter(permissions::project_id.eq(project_id))
        .filter(permissions::resource.eq(resource))
        .filter(permissions::action.eq(action))
        .select((permissions::id,))
        .first(conn)
        .optional()
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let permission_id = match permission {
        Some((id,)) => id,
        None => return Ok(false),
    };

    let user_override: Option<bool> = user_permissions::table
        .filter(user_permissions::project_id.eq(project_id))
        .filter(user_permissions::user_id.eq(user_id))
        .filter(user_permissions::permission_id.eq(permission_id))
        .select(user_permissions::granted)
        .first(conn)
        .optional()
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    if let Some(granted) = user_override {
        return Ok(granted);
    }

    let has_role_permission: i64 = project_members::table
        .inner_join(roles::table.on(roles::id.eq(project_members::role_id)))
        .inner_join(role_permissions::table.on(role_permissions::role_id.eq(roles::id)))
        .filter(project_members::project_id.eq(project_id))
        .filter(project_members::user_id.eq(user_id))
        .filter(role_permissions::permission_id.eq(permission_id))
        .count()
        .get_result(conn)
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    Ok(has_role_permission > 0)
}
