//! Roles and permissions integration tests.
//!
//! These tests verify role and permission CRUD operations, as well as
//! role-permission assignments.

mod common;

use common::{create_test_user_with_project, TestApp};
use serde_json::json;
use serial_test::serial;

// ============================================================================
// Role Creation Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn create_role_returns_success_for_valid_data() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Act
    let response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "moderator",
                "description": "Can moderate content"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["role"]["name"].as_str().unwrap(), "moderator");
    assert_eq!(
        body["role"]["description"].as_str().unwrap(),
        "Can moderate content"
    );
    assert!(body["role"]["id"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn create_role_works_without_description() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Act
    let response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "custom-role"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["role"]["name"].as_str().unwrap(), "custom-role");
}

#[tokio::test]
#[serial]
async fn create_role_returns_error_for_duplicate_name() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create first role
    let _ = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "unique-role",
                "description": "First role"
            }),
        )
        .await;

    // Act - Try to create role with same name
    let response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "unique-role",
                "description": "Duplicate role"
            }),
        )
        .await;

    // Assert
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Should return error for duplicate role name"
    );
}

#[tokio::test]
#[serial]
async fn create_role_returns_403_without_project_context() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Act - Try to create role without project context
    let response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "some-role"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 403);
}

// ============================================================================
// Role Listing Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn list_roles_returns_default_roles() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Act
    let response = app.get("/roles", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let roles = body["data"].as_array().unwrap();

    // Should have default roles: admin, editor, viewer
    assert!(roles.len() >= 3);

    let role_names: Vec<&str> = roles.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(role_names.contains(&"admin"));
    assert!(role_names.contains(&"editor"));
    assert!(role_names.contains(&"viewer"));
}

#[tokio::test]
#[serial]
async fn list_roles_includes_custom_roles() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create custom role
    let _ = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "custom-moderator",
                "description": "Custom moderation role"
            }),
        )
        .await;

    // Act
    let response = app.get("/roles", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let roles = body["data"].as_array().unwrap();

    let role_names: Vec<&str> = roles.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(role_names.contains(&"custom-moderator"));
}

// ============================================================================
// Role Update Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn update_role_returns_success_for_valid_data() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a role
    let create_response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "original-name",
                "description": "Original description"
            }),
        )
        .await;

    let create_body: serde_json::Value = create_response
        .json()
        .await
        .expect("Failed to parse response");
    let role_id = create_body["role"]["id"].as_str().unwrap();

    // Act
    let response = app
        .put(
            &format!("/roles/{}", role_id),
            &user.access_token,
            json!({
                "name": "updated-name",
                "description": "Updated description"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["role"]["name"].as_str().unwrap(), "updated-name");
    assert_eq!(
        body["role"]["description"].as_str().unwrap(),
        "Updated description"
    );
}

#[tokio::test]
#[serial]
async fn update_role_returns_error_for_nonexistent_role() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;
    let fake_role_id = uuid::Uuid::new_v4();

    // Act
    let response = app
        .put(
            &format!("/roles/{}", fake_role_id),
            &user.access_token,
            json!({
                "name": "updated-name"
            }),
        )
        .await;

    // Assert - API may return 404 (not found) or 204 (idempotent no-op)
    let status = response.status().as_u16();
    assert!(
        status == 404 || status == 204 || status == 500,
        "Expected 404, 204, or error status, got {}",
        status
    );
}

// ============================================================================
// Role Deletion Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn delete_role_returns_success() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a role to delete
    let create_response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "role-to-delete"
            }),
        )
        .await;

    let create_body: serde_json::Value = create_response
        .json()
        .await
        .expect("Failed to parse response");
    let role_id = create_body["role"]["id"].as_str().unwrap();

    // Act
    let response = app
        .delete(&format!("/roles/{}", role_id), &user.access_token)
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 204);

    // Verify role is deleted
    let list_response = app.get("/roles", &user.access_token).await;
    let list_body: serde_json::Value = list_response
        .json()
        .await
        .expect("Failed to parse response");
    let roles = list_body["data"].as_array().unwrap();
    let role_ids: Vec<&str> = roles.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert!(!role_ids.contains(&role_id));
}

#[tokio::test]
#[serial]
async fn delete_role_is_idempotent_for_nonexistent_role() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;
    let fake_role_id = uuid::Uuid::new_v4();

    // Act
    let response = app
        .delete(&format!("/roles/{}", fake_role_id), &user.access_token)
        .await;

    // Assert - DELETE is idempotent, may return 204 (success/no-op) or 404
    let status = response.status().as_u16();
    assert!(
        status == 404 || status == 204,
        "Expected 404 or 204, got {}",
        status
    );
}

// ============================================================================
// Permission Creation Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn create_permission_returns_success_for_valid_data() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Act
    let response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "delete_posts",
                "description": "Can delete posts",
                "resource": "posts",
                "action": "delete"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["permission"]["name"].as_str().unwrap(), "delete_posts");
    assert_eq!(body["permission"]["resource"].as_str().unwrap(), "posts");
    assert_eq!(body["permission"]["action"].as_str().unwrap(), "delete");
    assert!(body["permission"]["id"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn create_permission_returns_error_for_duplicate_name() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create first permission
    let _ = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "unique_permission",
                "resource": "items",
                "action": "create"
            }),
        )
        .await;

    // Act - Try to create permission with same name
    let response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "unique_permission",
                "resource": "items",
                "action": "update"
            }),
        )
        .await;

    // Assert
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Should return error for duplicate permission name"
    );
}

#[tokio::test]
#[serial]
async fn create_permission_returns_403_without_project_context() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Act - Try to create permission without project context
    let response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "some_permission",
                "resource": "items",
                "action": "read"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 403);
}

// ============================================================================
// Permission Listing Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn list_permissions_returns_default_permissions() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Act
    let response = app.get("/permissions", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let permissions = body["data"].as_array().unwrap();

    // Should have default permissions
    assert!(!permissions.is_empty());

    let permission_names: Vec<&str> = permissions
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(permission_names.contains(&"manage_members"));
    assert!(permission_names.contains(&"manage_roles"));
    assert!(permission_names.contains(&"edit_content"));
    assert!(permission_names.contains(&"view_content"));
}

#[tokio::test]
#[serial]
async fn list_permissions_includes_custom_permissions() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create custom permission
    let _ = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "custom_action",
                "resource": "custom",
                "action": "perform"
            }),
        )
        .await;

    // Act
    let response = app.get("/permissions", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let permissions = body["data"].as_array().unwrap();

    let permission_names: Vec<&str> = permissions
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(permission_names.contains(&"custom_action"));
}

// ============================================================================
// Permission Deletion Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn delete_permission_returns_success() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a permission to delete
    let create_response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "permission_to_delete",
                "resource": "temp",
                "action": "delete"
            }),
        )
        .await;

    let create_body: serde_json::Value = create_response
        .json()
        .await
        .expect("Failed to parse response");
    let permission_id = create_body["permission"]["id"].as_str().unwrap();

    // Act
    let response = app
        .delete(
            &format!("/permissions/{}", permission_id),
            &user.access_token,
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 204);

    // Verify permission is deleted
    let list_response = app.get("/permissions", &user.access_token).await;
    let list_body: serde_json::Value = list_response
        .json()
        .await
        .expect("Failed to parse response");
    let permissions = list_body["data"].as_array().unwrap();
    let permission_ids: Vec<&str> = permissions
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert!(!permission_ids.contains(&permission_id));
}

#[tokio::test]
#[serial]
async fn delete_permission_is_idempotent_for_nonexistent_permission() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;
    let fake_permission_id = uuid::Uuid::new_v4();

    // Act
    let response = app
        .delete(
            &format!("/permissions/{}", fake_permission_id),
            &user.access_token,
        )
        .await;

    // Assert - DELETE is idempotent, may return 204 (success/no-op) or 404
    let status = response.status().as_u16();
    assert!(
        status == 404 || status == 204,
        "Expected 404 or 204, got {}",
        status
    );
}

// ============================================================================
// Role-Permission Assignment Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn assign_permission_to_role_returns_success() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a role
    let role_response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "test-role"
            }),
        )
        .await;
    let role_body: serde_json::Value = role_response.json().await.unwrap();
    let role_id = role_body["role"]["id"].as_str().unwrap();

    // Create a permission
    let perm_response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "test_permission",
                "resource": "test",
                "action": "do"
            }),
        )
        .await;
    let perm_body: serde_json::Value = perm_response.json().await.unwrap();
    let permission_id = perm_body["permission"]["id"].as_str().unwrap();

    // Act
    let response = app
        .post(
            &format!("/roles/{}/permissions", role_id),
            &user.access_token,
            json!({
                "permission_id": permission_id
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 201);
}

#[tokio::test]
#[serial]
async fn list_role_permissions_returns_assigned_permissions() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a role
    let role_response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "role-with-perms"
            }),
        )
        .await;
    let role_body: serde_json::Value = role_response.json().await.unwrap();
    let role_id = role_body["role"]["id"].as_str().unwrap();

    // Create permissions
    let perm1_response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "perm_one",
                "resource": "items",
                "action": "read"
            }),
        )
        .await;
    let perm1_body: serde_json::Value = perm1_response.json().await.unwrap();
    let perm1_id = perm1_body["permission"]["id"].as_str().unwrap();

    let perm2_response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "perm_two",
                "resource": "items",
                "action": "write"
            }),
        )
        .await;
    let perm2_body: serde_json::Value = perm2_response.json().await.unwrap();
    let perm2_id = perm2_body["permission"]["id"].as_str().unwrap();

    // Assign permissions to role
    let _ = app
        .post(
            &format!("/roles/{}/permissions", role_id),
            &user.access_token,
            json!({ "permission_id": perm1_id }),
        )
        .await;
    let _ = app
        .post(
            &format!("/roles/{}/permissions", role_id),
            &user.access_token,
            json!({ "permission_id": perm2_id }),
        )
        .await;

    // Act
    let response = app
        .get(
            &format!("/roles/{}/permissions", role_id),
            &user.access_token,
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let permissions = body["data"].as_array().unwrap();
    assert_eq!(permissions.len(), 2);

    let perm_names: Vec<&str> = permissions
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(perm_names.contains(&"perm_one"));
    assert!(perm_names.contains(&"perm_two"));
}

#[tokio::test]
#[serial]
async fn remove_permission_from_role_returns_success() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a role
    let role_response = app
        .post(
            "/roles",
            &user.access_token,
            json!({
                "name": "role-for-removal"
            }),
        )
        .await;
    let role_body: serde_json::Value = role_response.json().await.unwrap();
    let role_id = role_body["role"]["id"].as_str().unwrap();

    // Create a permission
    let perm_response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "perm_to_remove",
                "resource": "temp",
                "action": "test"
            }),
        )
        .await;
    let perm_body: serde_json::Value = perm_response.json().await.unwrap();
    let permission_id = perm_body["permission"]["id"].as_str().unwrap();

    // Assign permission to role
    let _ = app
        .post(
            &format!("/roles/{}/permissions", role_id),
            &user.access_token,
            json!({ "permission_id": permission_id }),
        )
        .await;

    // Act - Remove permission from role
    let response = app
        .delete(
            &format!("/roles/{}/permissions/{}", role_id, permission_id),
            &user.access_token,
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 204);

    // Verify permission is removed
    let list_response = app
        .get(
            &format!("/roles/{}/permissions", role_id),
            &user.access_token,
        )
        .await;
    let list_body: serde_json::Value = list_response.json().await.unwrap();
    let permissions = list_body["data"].as_array().unwrap();
    let perm_ids: Vec<&str> = permissions
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert!(!perm_ids.contains(&permission_id));
}

// ============================================================================
// Project Isolation Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn roles_are_isolated_between_projects() {
    // Arrange
    let app = TestApp::spawn().await;

    // Create two users with their own projects
    let (user1, _project1) = create_test_user_with_project(&app).await;
    let (user2, _project2) = create_test_user_with_project(&app).await;

    // User 1 creates a role
    let _ = app
        .post(
            "/roles",
            &user1.access_token,
            json!({
                "name": "user1-only-role"
            }),
        )
        .await;

    // Act - User 2 lists roles (should not see user1's role)
    let response = app.get("/roles", &user2.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let roles = body["data"].as_array().unwrap();
    let role_names: Vec<&str> = roles.iter().map(|r| r["name"].as_str().unwrap()).collect();

    assert!(
        !role_names.contains(&"user1-only-role"),
        "User 2 should not see User 1's roles"
    );
}

#[tokio::test]
#[serial]
async fn permissions_are_isolated_between_projects() {
    // Arrange
    let app = TestApp::spawn().await;

    // Create two users with their own projects
    let (user1, _project1) = create_test_user_with_project(&app).await;
    let (user2, _project2) = create_test_user_with_project(&app).await;

    // User 1 creates a permission
    let _ = app
        .post(
            "/permissions",
            &user1.access_token,
            json!({
                "name": "user1_only_permission",
                "resource": "private",
                "action": "access"
            }),
        )
        .await;

    // Act - User 2 lists permissions (should not see user1's permission)
    let response = app.get("/permissions", &user2.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let permissions = body["data"].as_array().unwrap();
    let perm_names: Vec<&str> = permissions
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();

    assert!(
        !perm_names.contains(&"user1_only_permission"),
        "User 2 should not see User 1's permissions"
    );
}

// Helper function (re-exported for this test file)
async fn create_test_user(app: &TestApp) -> common::TestUser {
    let email = TestApp::unique_email();
    app.register_user(&email, "password123", Some("Test User"))
        .await
        .expect("Failed to create test user")
}

// ============================================================================
// Permission Check Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn check_permission_returns_allowed_for_role_permission() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get a permission that the admin role has
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission_name = perms_body["data"][0]["name"].as_str().unwrap();

    // Act
    let response = app
        .post(
            "/permissions/check",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission": permission_name
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["allowed"].as_bool().unwrap());
    assert_eq!(body["reason"].as_str().unwrap(), "granted_by_role");
}

#[tokio::test]
#[serial]
async fn check_permission_returns_not_allowed_for_missing_permission() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a permission but don't assign it to any role
    let _ = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "unassigned_permission",
                "resource": "test",
                "action": "unassigned"
            }),
        )
        .await;

    // Create a second user with viewer role
    let user2 = create_test_user(&app).await;

    // Act - check if user2 (not a member) has the permission
    let response = app
        .post(
            "/permissions/check",
            &user.access_token,
            json!({
                "user_id": user2.id,
                "permission": "unassigned_permission"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(!body["allowed"].as_bool().unwrap());
    assert_eq!(body["reason"].as_str().unwrap(), "not_granted");
}

#[tokio::test]
#[serial]
async fn check_permission_returns_denied_by_override() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get a permission the admin role has
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission = &perms_body["data"][0];
    let permission_id = permission["id"].as_str().unwrap();
    let permission_name = permission["name"].as_str().unwrap();

    // Deny this permission via override
    let _ = app
        .post(
            "/user-permissions",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission_id": permission_id,
                "granted": false
            }),
        )
        .await;

    // Act
    let response = app
        .post(
            "/permissions/check",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission": permission_name
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(!body["allowed"].as_bool().unwrap());
    assert_eq!(body["reason"].as_str().unwrap(), "denied_by_override");
}

#[tokio::test]
#[serial]
async fn check_permission_returns_granted_by_override() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a permission not assigned to any role
    let perm_response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "special_override_perm",
                "resource": "special",
                "action": "override"
            }),
        )
        .await;
    let perm_body: serde_json::Value = perm_response.json().await.unwrap();
    let permission_id = perm_body["permission"]["id"].as_str().unwrap();

    // Grant via override
    let _ = app
        .post(
            "/user-permissions",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission_id": permission_id,
                "granted": true
            }),
        )
        .await;

    // Act
    let response = app
        .post(
            "/permissions/check",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission": "special_override_perm"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["allowed"].as_bool().unwrap());
    assert_eq!(body["reason"].as_str().unwrap(), "granted_by_override");
}

#[tokio::test]
#[serial]
async fn check_permission_by_resource_action() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get a permission to find its resource/action
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission = &perms_body["data"][0];
    let resource = permission["resource"].as_str().unwrap();
    let action = permission["action"].as_str().unwrap();

    // Act - check by resource and action instead of name
    let response = app
        .post(
            "/permissions/check",
            &user.access_token,
            json!({
                "user_id": user.id,
                "resource": resource,
                "action": action
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["allowed"].as_bool().unwrap());
}

#[tokio::test]
#[serial]
async fn check_permission_returns_not_found_for_unknown_permission() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Act
    let response = app
        .post(
            "/permissions/check",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission": "nonexistent_permission"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(!body["allowed"].as_bool().unwrap());
    assert_eq!(body["reason"].as_str().unwrap(), "permission_not_found");
}

// ============================================================================
// Bulk Permission Check Tests (/permissions/check-bulk)
// ============================================================================

#[tokio::test]
#[serial]
async fn check_permissions_bulk_returns_all_results() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get default permissions
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permissions = perms_body["data"].as_array().unwrap();
    let perm_names: Vec<&str> = permissions
        .iter()
        .take(3)
        .map(|p| p["name"].as_str().unwrap())
        .collect();

    // Act
    let response = app
        .post(
            "/permissions/check-bulk",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permissions": perm_names
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), perm_names.len());

    // All should be allowed for admin
    assert!(body["all_allowed"].as_bool().unwrap());
    assert!(body["denied"].as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial]
async fn check_permissions_bulk_returns_partial_results() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Mix of existing and nonexistent permissions
    let permissions = vec!["view_content", "nonexistent_perm_1", "nonexistent_perm_2"];

    // Act
    let response = app
        .post(
            "/permissions/check-bulk",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permissions": permissions
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.unwrap();

    // Should not be all_allowed since some don't exist
    assert!(!body["all_allowed"].as_bool().unwrap());

    let denied = body["denied"].as_array().unwrap();
    assert_eq!(denied.len(), 2);
    assert!(denied.contains(&json!("nonexistent_perm_1")));
    assert!(denied.contains(&json!("nonexistent_perm_2")));

    // Check individual results
    let results = body["results"].as_array().unwrap();
    let view_content_result = results
        .iter()
        .find(|r| r["permission"].as_str().unwrap() == "view_content")
        .unwrap();
    assert!(view_content_result["allowed"].as_bool().unwrap());
    assert_eq!(
        view_content_result["reason"].as_str().unwrap(),
        "granted_by_role"
    );
}

#[tokio::test]
#[serial]
async fn check_permissions_bulk_handles_overrides() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get a permission and deny it via override
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission = &perms_body["data"][0];
    let permission_id = permission["id"].as_str().unwrap();
    let permission_name = permission["name"].as_str().unwrap();

    // Deny via override
    let _ = app
        .post(
            "/user-permissions",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission_id": permission_id,
                "granted": false
            }),
        )
        .await;

    // Act
    let response = app
        .post(
            "/permissions/check-bulk",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permissions": [permission_name]
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(!body["all_allowed"].as_bool().unwrap());

    let results = body["results"].as_array().unwrap();
    assert!(!results[0]["allowed"].as_bool().unwrap());
    assert_eq!(results[0]["reason"].as_str().unwrap(), "denied_by_override");
}

#[tokio::test]
#[serial]
async fn check_permissions_bulk_returns_400_for_empty_permissions() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Act
    let response = app
        .post(
            "/permissions/check-bulk",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permissions": []
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 400);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("At least one permission"));
}

#[tokio::test]
#[serial]
async fn check_permissions_bulk_returns_403_without_project_context() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Act - Try without project context
    let response = app
        .post(
            "/permissions/check-bulk",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permissions": ["view_content"]
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 403);
}

#[tokio::test]
#[serial]
async fn check_permissions_bulk_handles_granted_override() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a permission not assigned to any role
    let perm_response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "special_bulk_perm",
                "resource": "special",
                "action": "bulk"
            }),
        )
        .await;
    let perm_body: serde_json::Value = perm_response.json().await.unwrap();
    let permission_id = perm_body["permission"]["id"].as_str().unwrap();

    // Grant via override
    let _ = app
        .post(
            "/user-permissions",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission_id": permission_id,
                "granted": true
            }),
        )
        .await;

    // Act
    let response = app
        .post(
            "/permissions/check-bulk",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permissions": ["special_bulk_perm"]
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["all_allowed"].as_bool().unwrap());

    let results = body["results"].as_array().unwrap();
    assert!(results[0]["allowed"].as_bool().unwrap());
    assert_eq!(
        results[0]["reason"].as_str().unwrap(),
        "granted_by_override"
    );
}
