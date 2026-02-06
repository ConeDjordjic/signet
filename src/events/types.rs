//! Domain event types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    UserRegistered,
    LoginSuccess,
    LoginFailed,
    LogoutCompleted,
    TokenRefreshed,
    AccountLocked,
    AccountDeleted,
    PasswordResetRequested,
    PasswordResetCompleted,

    ProjectCreated,
    ProjectUpdated,
    ProjectDeleted,

    MemberAdded,
    MemberRemoved,
    MemberRoleChanged,

    PermissionCreated,
    PermissionDeleted,
    PermissionAssignedToRole,
    PermissionRemovedFromRole,
    UserPermissionOverrideSet,
    UserPermissionOverrideRemoved,

    RoleCreated,
    RoleUpdated,
    RoleDeleted,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::UserRegistered => "user.registered",
            EventType::LoginSuccess => "auth.login.success",
            EventType::LoginFailed => "auth.login.failed",
            EventType::LogoutCompleted => "auth.logout",
            EventType::TokenRefreshed => "auth.token.refreshed",
            EventType::AccountLocked => "auth.account.locked",
            EventType::AccountDeleted => "user.deleted",
            EventType::PasswordResetRequested => "auth.password.reset_requested",
            EventType::PasswordResetCompleted => "auth.password.reset_completed",
            EventType::ProjectCreated => "project.created",
            EventType::ProjectUpdated => "project.updated",
            EventType::ProjectDeleted => "project.deleted",
            EventType::MemberAdded => "project.member.added",
            EventType::MemberRemoved => "project.member.removed",
            EventType::MemberRoleChanged => "project.member.role_changed",
            EventType::PermissionCreated => "permission.created",
            EventType::PermissionDeleted => "permission.deleted",
            EventType::PermissionAssignedToRole => "permission.role.assigned",
            EventType::PermissionRemovedFromRole => "permission.role.removed",
            EventType::UserPermissionOverrideSet => "permission.user.override_set",
            EventType::UserPermissionOverrideRemoved => "permission.user.override_removed",
            EventType::RoleCreated => "role.created",
            EventType::RoleUpdated => "role.updated",
            EventType::RoleDeleted => "role.deleted",
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AggregateType {
    User,
    Project,
    Role,
    Permission,
}

impl AggregateType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AggregateType::User => "user",
            AggregateType::Project => "project",
            AggregateType::Role => "role",
            AggregateType::Permission => "permission",
        }
    }
}

impl std::fmt::Display for AggregateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainEvent {
    pub event_type: EventType,
    pub aggregate_type: AggregateType,
    pub aggregate_id: Uuid,
    pub payload: serde_json::Value,
    pub metadata: EventMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub user_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub request_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl EventMetadata {
    pub fn new() -> Self {
        Self {
            user_id: None,
            project_id: None,
            request_id: None,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn with_user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_project(mut self, project_id: Uuid) -> Self {
        self.project_id = Some(project_id);
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}

impl Default for EventMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegisteredPayload {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSuccessPayload {
    pub email: String,
    pub project_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFailedPayload {
    pub email: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLockedPayload {
    pub email: String,
    pub attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionChangedPayload {
    pub permission_name: String,
    pub project_id: Uuid,
    pub affected_role_id: Option<Uuid>,
    pub affected_user_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_as_str() {
        assert_eq!(EventType::UserRegistered.as_str(), "user.registered");
        assert_eq!(EventType::LoginSuccess.as_str(), "auth.login.success");
        assert_eq!(EventType::LoginFailed.as_str(), "auth.login.failed");
        assert_eq!(EventType::LogoutCompleted.as_str(), "auth.logout");
        assert_eq!(EventType::ProjectCreated.as_str(), "project.created");
        assert_eq!(EventType::RoleCreated.as_str(), "role.created");
        assert_eq!(EventType::PermissionCreated.as_str(), "permission.created");
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(format!("{}", EventType::UserRegistered), "user.registered");
        assert_eq!(format!("{}", EventType::LoginSuccess), "auth.login.success");
    }

    #[test]
    fn test_aggregate_type_as_str() {
        assert_eq!(AggregateType::User.as_str(), "user");
        assert_eq!(AggregateType::Project.as_str(), "project");
        assert_eq!(AggregateType::Role.as_str(), "role");
        assert_eq!(AggregateType::Permission.as_str(), "permission");
    }

    #[test]
    fn test_aggregate_type_display() {
        assert_eq!(format!("{}", AggregateType::User), "user");
        assert_eq!(format!("{}", AggregateType::Project), "project");
    }

    #[test]
    fn test_event_metadata_builder() {
        let user_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();

        let metadata = EventMetadata::new()
            .with_user(user_id)
            .with_project(project_id)
            .with_request_id("req-123");

        assert_eq!(metadata.user_id, Some(user_id));
        assert_eq!(metadata.project_id, Some(project_id));
        assert_eq!(metadata.request_id, Some("req-123".to_string()));
    }

    #[test]
    fn test_event_metadata_default() {
        let metadata = EventMetadata::default();
        assert!(metadata.user_id.is_none());
        assert!(metadata.project_id.is_none());
        assert!(metadata.request_id.is_none());
    }

    #[test]
    fn test_domain_event_serialization() {
        let event = DomainEvent {
            event_type: EventType::UserRegistered,
            aggregate_type: AggregateType::User,
            aggregate_id: Uuid::new_v4(),
            payload: serde_json::json!({"email": "test@example.com"}),
            metadata: EventMetadata::new(),
        };

        let json = serde_json::to_string(&event).expect("Serialization failed");
        assert!(json.contains("UserRegistered"));
        assert!(json.contains("test@example.com"));
    }

    #[test]
    fn test_payload_types_serialization() {
        let payload = UserRegisteredPayload {
            email: "test@example.com".to_string(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["email"], "test@example.com");

        let payload = LoginSuccessPayload {
            email: "test@example.com".to_string(),
            project_id: Some(Uuid::new_v4()),
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert!(json["project_id"].is_string());

        let payload = LoginFailedPayload {
            email: "test@example.com".to_string(),
            reason: "invalid_password".to_string(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["reason"], "invalid_password");
    }
}
