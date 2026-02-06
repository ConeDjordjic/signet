//! User permission override integration tests.
//!
//! These tests verify per-user permission override functionality,
//! including granting, revoking, and retrieving user permissions.

mod common;

use common::{create_test_user_with_project, TestApp};
use serde_json::json;
use serial_test::serial;

// ============================================================================
// Set User Permission Override Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn set_permission_override_grants_permission() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get the user ID and a permission ID from the project
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission_id = perms_body["data"][0]["id"].as_str().unwrap();

    // Act - Grant an additional permission to the user
    let response = app
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

    // Assert
    assert_eq!(response.status().as_u16(), 201);
}

#[tokio::test]
#[serial]
async fn set_permission_override_revokes_permission() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get a permission ID
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission_id = perms_body["data"][0]["id"].as_str().unwrap();

    // Act - Revoke a permission from the user
    let response = app
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

    // Assert
    assert_eq!(response.status().as_u16(), 201);
}

#[tokio::test]
#[serial]
async fn set_permission_override_updates_existing() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get a permission ID
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission_id = perms_body["data"][0]["id"].as_str().unwrap();

    // First, grant the permission
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

    // Act - Update to revoke it
    let response = app
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

    // Assert
    assert_eq!(response.status().as_u16(), 201);

    // Verify the override was updated
    let get_response = app
        .get(
            &format!("/user-permissions/{}", user.id),
            &user.access_token,
        )
        .await;
    let body: serde_json::Value = get_response.json().await.unwrap();
    let overrides = body["overrides"].as_array().unwrap();
    let override_item = overrides
        .iter()
        .find(|o| o["permission"]["id"].as_str().unwrap() == permission_id)
        .expect("Override should exist");
    assert!(!override_item["granted"].as_bool().unwrap());
}

#[tokio::test]
#[serial]
async fn set_permission_override_returns_403_without_project_context() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;
    let fake_permission_id = uuid::Uuid::new_v4();

    // Act
    let response = app
        .post(
            "/user-permissions",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission_id": fake_permission_id,
                "granted": true
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 403);
}

// ============================================================================
// Remove User Permission Override Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn remove_permission_override_returns_success() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get a permission ID
    let perms_response = app.get("/permissions", &user.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission_id = perms_body["data"][0]["id"].as_str().unwrap();

    // Create an override first
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

    // Act - Remove the override
    let response = app
        .delete(
            &format!("/user-permissions/{}/{}", user.id, permission_id),
            &user.access_token,
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 204);

    // Verify the override was removed
    let get_response = app
        .get(
            &format!("/user-permissions/{}", user.id),
            &user.access_token,
        )
        .await;
    let body: serde_json::Value = get_response.json().await.unwrap();
    let overrides = body["overrides"].as_array().unwrap();
    let override_exists = overrides
        .iter()
        .any(|o| o["permission"]["id"].as_str().unwrap() == permission_id);
    assert!(!override_exists, "Override should have been removed");
}

#[tokio::test]
#[serial]
async fn remove_permission_override_is_idempotent() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;
    let fake_permission_id = uuid::Uuid::new_v4();

    // Act - Try to remove non-existent override
    let response = app
        .delete(
            &format!("/user-permissions/{}/{}", user.id, fake_permission_id),
            &user.access_token,
        )
        .await;

    // Assert - DELETE should be idempotent, returning 204
    assert_eq!(response.status().as_u16(), 204);
}

// ============================================================================
// Get User Permissions Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn get_user_permissions_returns_role_permissions() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Act
    let response = app
        .get(
            &format!("/user-permissions/{}", user.id),
            &user.access_token,
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["user_id"].as_str().unwrap(), user.id.to_string());
    assert!(body["role_permissions"].as_array().is_some());
    assert!(body["overrides"].as_array().is_some());
    assert!(body["effective_permissions"].as_array().is_some());

    // Admin role should have permissions
    let role_perms = body["role_permissions"].as_array().unwrap();
    assert!(!role_perms.is_empty(), "Admin role should have permissions");
}

#[tokio::test]
#[serial]
async fn get_user_permissions_includes_granted_overrides_in_effective() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Create a new permission not assigned to any role
    let perm_response = app
        .post(
            "/permissions",
            &user.access_token,
            json!({
                "name": "special_permission",
                "resource": "special",
                "action": "access"
            }),
        )
        .await;
    let perm_body: serde_json::Value = perm_response.json().await.unwrap();
    let special_perm_id = perm_body["permission"]["id"].as_str().unwrap();

    // Grant this permission directly to the user
    let _ = app
        .post(
            "/user-permissions",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission_id": special_perm_id,
                "granted": true
            }),
        )
        .await;

    // Act
    let response = app
        .get(
            &format!("/user-permissions/{}", user.id),
            &user.access_token,
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    let effective = body["effective_permissions"].as_array().unwrap();

    // The granted override should be in effective permissions
    let has_special_perm = effective
        .iter()
        .any(|p| p["id"].as_str().unwrap() == special_perm_id);
    assert!(
        has_special_perm,
        "Granted override should appear in effective permissions"
    );
}

#[tokio::test]
#[serial]
async fn get_user_permissions_excludes_revoked_overrides_from_effective() {
    // Arrange
    let app = TestApp::spawn().await;
    let (user, _project) = create_test_user_with_project(&app).await;

    // Get a permission that the admin role has
    let initial_response = app
        .get(
            &format!("/user-permissions/{}", user.id),
            &user.access_token,
        )
        .await;
    let initial_body: serde_json::Value = initial_response.json().await.unwrap();
    let role_perms = initial_body["role_permissions"].as_array().unwrap();
    assert!(!role_perms.is_empty(), "Admin should have role permissions");
    let perm_to_revoke = role_perms[0]["id"].as_str().unwrap();

    // Revoke this permission for the user
    let _ = app
        .post(
            "/user-permissions",
            &user.access_token,
            json!({
                "user_id": user.id,
                "permission_id": perm_to_revoke,
                "granted": false
            }),
        )
        .await;

    // Act
    let response = app
        .get(
            &format!("/user-permissions/{}", user.id),
            &user.access_token,
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    let effective = body["effective_permissions"].as_array().unwrap();

    // The revoked permission should NOT be in effective permissions
    let has_revoked_perm = effective
        .iter()
        .any(|p| p["id"].as_str().unwrap() == perm_to_revoke);
    assert!(
        !has_revoked_perm,
        "Revoked permission should not appear in effective permissions"
    );
}

#[tokio::test]
#[serial]
async fn get_user_permissions_returns_403_without_project_context() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Act
    let response = app
        .get(
            &format!("/user-permissions/{}", user.id),
            &user.access_token,
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 403);
}

// ============================================================================
// Project Isolation Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn user_permission_overrides_are_project_scoped() {
    // Arrange
    let app = TestApp::spawn().await;

    // Create two users with their own projects
    let (user1, _project1) = create_test_user_with_project(&app).await;
    let (user2, _project2) = create_test_user_with_project(&app).await;

    // Get a permission from user1's project
    let perms_response = app.get("/permissions", &user1.access_token).await;
    let perms_body: serde_json::Value = perms_response.json().await.unwrap();
    let permission_id = perms_body["data"][0]["id"].as_str().unwrap();

    // Create an override in user1's project
    let _ = app
        .post(
            "/user-permissions",
            &user1.access_token,
            json!({
                "user_id": user1.id,
                "permission_id": permission_id,
                "granted": true
            }),
        )
        .await;

    // Act - User2 tries to get user1's permissions in their own project context
    // This should show no overrides since the permission is from a different project
    let response = app
        .get(
            &format!("/user-permissions/{}", user1.id),
            &user2.access_token,
        )
        .await;

    // Assert - Should return 200 but with empty role_permissions and overrides
    // since user1 is not a member of user2's project
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    let role_perms = body["role_permissions"].as_array().unwrap();
    let overrides = body["overrides"].as_array().unwrap();

    assert!(
        role_perms.is_empty(),
        "User1 should have no role permissions in User2's project"
    );
    assert!(
        overrides.is_empty(),
        "User1 should have no overrides in User2's project"
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn create_test_user(app: &TestApp) -> common::TestUser {
    let email = TestApp::unique_email();
    app.register_user(&email, "password123", Some("Test User"))
        .await
        .expect("Failed to create test user")
}
