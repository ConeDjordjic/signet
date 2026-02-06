use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Queryable, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub full_name: Option<String>,
    pub is_active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub email: String,
    pub password_hash: String,
    pub full_name: Option<String>,
}

#[derive(Debug, Queryable, Selectable, Serialize, ToSchema)]
#[diesel(table_name = crate::schema::projects)]
pub struct Project {
    pub id: Uuid,
    #[schema(example = "My Project")]
    pub name: String,
    #[schema(example = "my-project")]
    pub slug: String,
    #[schema(example = "A description of the project")]
    pub description: Option<String>,
    pub owner_id: Uuid,
    pub is_active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::projects)]
pub struct NewProject {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub owner_id: Uuid,
}

#[derive(Debug, Queryable, Selectable, Serialize, ToSchema)]
#[diesel(table_name = crate::schema::roles)]
pub struct Role {
    pub id: Uuid,
    pub project_id: Uuid,
    #[schema(example = "editor")]
    pub name: String,
    #[schema(example = "Can edit content")]
    pub description: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::roles)]
pub struct NewRole {
    pub project_id: Uuid,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Queryable, Selectable, Serialize, Clone, ToSchema)]
#[diesel(table_name = crate::schema::permissions)]
pub struct Permission {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::permissions)]
pub struct NewPermission {
    pub project_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::project_members)]
pub struct ProjectMember {
    pub id: Uuid,
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub joined_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::project_members)]
pub struct NewProjectMember {
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::role_permissions)]
pub struct RolePermission {
    pub role_id: Uuid,
    pub permission_id: Uuid,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::role_permissions)]
pub struct NewRolePermission {
    pub role_id: Uuid,
    pub permission_id: Uuid,
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::refresh_tokens)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Queryable, Selectable, Clone)]
#[diesel(table_name = crate::schema::user_permissions)]
pub struct UserPermission {
    pub id: Uuid,
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub permission_id: Uuid,
    pub granted: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::user_permissions)]
pub struct NewUserPermission {
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub permission_id: Uuid,
    pub granted: bool,
}

#[derive(Debug, Queryable, Selectable, Clone)]
#[diesel(table_name = crate::schema::outbox_events)]
pub struct OutboxEvent {
    pub id: Uuid,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: Uuid,
    pub payload: serde_json::Value,
    pub published: bool,
    pub published_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::outbox_events)]
pub struct NewOutboxEvent {
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: Uuid,
    pub payload: serde_json::Value,
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::password_reset_tokens)]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub used_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::password_reset_tokens)]
pub struct NewPasswordResetToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
}
