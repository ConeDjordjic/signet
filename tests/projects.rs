//! Project management integration tests.
//!
//! These tests verify project creation, listing, validation, and access control.

mod common;

use common::{create_test_user, TestApp};
use serde_json::json;
use serial_test::serial;

// ============================================================================
// Project Creation Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn create_project_returns_success_for_valid_data() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;
    let slug = TestApp::unique_slug();

    // Act
    let response = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "My Test Project",
                "slug": slug,
                "description": "A test project description"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["project"]["name"].as_str().unwrap(), "My Test Project");
    assert_eq!(body["project"]["slug"].as_str().unwrap(), slug);
    assert_eq!(
        body["project"]["description"].as_str().unwrap(),
        "A test project description"
    );
    assert_eq!(body["role"].as_str().unwrap(), "admin");
}

#[tokio::test]
#[serial]
async fn create_project_works_without_description() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;
    let slug = TestApp::unique_slug();

    // Act
    let response = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "Project Without Description",
                "slug": slug
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(
        body["project"]["name"].as_str().unwrap(),
        "Project Without Description"
    );
    assert!(body["project"]["description"].is_null());
}

#[tokio::test]
#[serial]
async fn create_project_returns_400_for_short_name() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Act
    let response = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "ab",  // Too short (< 3 chars)
                "slug": TestApp::unique_slug()
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["error"].as_str().unwrap().contains("3 characters"));
}

#[tokio::test]
#[serial]
async fn create_project_returns_400_for_short_slug() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Act
    let response = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "Valid Project Name",
                "slug": "ab"  // Too short (< 3 chars)
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["error"].as_str().unwrap().contains("3 characters"));
}

#[tokio::test]
#[serial]
async fn create_project_returns_error_for_duplicate_slug() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;
    let slug = TestApp::unique_slug();

    // Create first project
    let _ = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "First Project",
                "slug": slug
            }),
        )
        .await;

    // Act - Try to create another project with same slug
    let response = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "Second Project",
                "slug": slug
            }),
        )
        .await;

    // Assert
    assert!(response.status().is_server_error() || response.status().as_u16() == 409);
}

#[tokio::test]
#[serial]
async fn create_project_returns_401_without_authentication() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app
        .post_public(
            "/projects",
            json!({
                "name": "Test Project",
                "slug": TestApp::unique_slug()
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);
}

// ============================================================================
// Project Listing Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn list_projects_returns_empty_for_new_user() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Act
    let response = app.get("/projects", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial]
async fn list_projects_returns_user_projects() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Create two projects
    let slug1 = TestApp::unique_slug();
    let slug2 = TestApp::unique_slug();

    let _ = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "Project One",
                "slug": slug1
            }),
        )
        .await;

    let _ = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "Project Two",
                "slug": slug2
            }),
        )
        .await;

    // Act
    let response = app.get("/projects", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let projects = body["data"].as_array().unwrap();
    assert_eq!(projects.len(), 2);

    // Verify project data
    let project_names: Vec<&str> = projects
        .iter()
        .map(|p| p["project"]["name"].as_str().unwrap())
        .collect();
    assert!(project_names.contains(&"Project One"));
    assert!(project_names.contains(&"Project Two"));

    // Verify role is included
    for project in projects {
        assert!(project["role"].as_str().is_some());
    }
}

#[tokio::test]
#[serial]
async fn list_projects_returns_401_without_authentication() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app.get_public("/projects").await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);
}

// ============================================================================
// Project Isolation Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn users_only_see_their_own_projects() {
    // Arrange
    let app = TestApp::spawn().await;

    // Create two users
    let user1 = app
        .register_user(&TestApp::unique_email(), "password123", Some("User One"))
        .await
        .expect("Failed to create user 1");

    let user2 = app
        .register_user(&TestApp::unique_email(), "password123", Some("User Two"))
        .await
        .expect("Failed to create user 2");

    // Each user creates their own project
    let _ = app
        .post(
            "/projects",
            &user1.access_token,
            json!({
                "name": "User One Project",
                "slug": TestApp::unique_slug()
            }),
        )
        .await;

    let _ = app
        .post(
            "/projects",
            &user2.access_token,
            json!({
                "name": "User Two Project",
                "slug": TestApp::unique_slug()
            }),
        )
        .await;

    // Act - User 1 lists their projects
    let response1 = app.get("/projects", &user1.access_token).await;
    let body1: serde_json::Value = response1.json().await.expect("Failed to parse response");

    // Act - User 2 lists their projects
    let response2 = app.get("/projects", &user2.access_token).await;
    let body2: serde_json::Value = response2.json().await.expect("Failed to parse response");

    // Assert - Each user only sees their own project
    let projects1 = body1["data"].as_array().unwrap();
    assert_eq!(projects1.len(), 1);
    assert_eq!(
        projects1[0]["project"]["name"].as_str().unwrap(),
        "User One Project"
    );

    let projects2 = body2["data"].as_array().unwrap();
    assert_eq!(projects2.len(), 1);
    assert_eq!(
        projects2[0]["project"]["name"].as_str().unwrap(),
        "User Two Project"
    );
}

// ============================================================================
// Project Owner Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn project_creator_is_assigned_admin_role() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Act
    let response = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "My Project",
                "slug": TestApp::unique_slug()
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["role"].as_str().unwrap(), "admin");
}

#[tokio::test]
#[serial]
async fn project_creator_can_access_project_scoped_endpoints() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();
    let password = "password123";

    let user = app
        .register_user(&email, password, Some("Test User"))
        .await
        .expect("Failed to register user");

    // Create a project
    let create_response = app
        .post(
            "/projects",
            &user.access_token,
            json!({
                "name": "My Project",
                "slug": TestApp::unique_slug()
            }),
        )
        .await;

    let create_body: serde_json::Value = create_response
        .json()
        .await
        .expect("Failed to parse response");
    let project_id = create_body["project"]["id"].as_str().unwrap();

    // Login with project context
    let user_with_context = app
        .login_user(
            &email,
            password,
            Some(project_id.parse().expect("Failed to parse project ID")),
        )
        .await
        .expect("Failed to login with project context");

    // Act - Access project-scoped endpoint
    let response = app.get("/roles", &user_with_context.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let roles = body["data"].as_array().unwrap();

    // Default roles should be created
    let role_names: Vec<&str> = roles.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(role_names.contains(&"admin"));
    assert!(role_names.contains(&"editor"));
    assert!(role_names.contains(&"viewer"));
}

// ============================================================================
// Default Project Setup Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn new_project_has_default_roles() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();
    let password = "password123";

    let user = app
        .register_user(&email, password, Some("Test User"))
        .await
        .expect("Failed to register user");

    let project = app
        .create_project(&user, "Test Project", &TestApp::unique_slug(), None)
        .await
        .expect("Failed to create project");

    // Login with project context
    let user_with_context = app
        .login_user(&email, password, Some(project.project.id))
        .await
        .expect("Failed to login with project context");

    // Act
    let response = app.get("/roles", &user_with_context.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let roles = body["data"].as_array().unwrap();

    assert!(!roles.is_empty());

    // Check for expected default roles
    let role_names: Vec<&str> = roles.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(role_names.contains(&"admin"), "Should have admin role");
    assert!(role_names.contains(&"editor"), "Should have editor role");
    assert!(role_names.contains(&"viewer"), "Should have viewer role");
}

#[tokio::test]
#[serial]
async fn new_project_has_default_permissions() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();
    let password = "password123";

    let user = app
        .register_user(&email, password, Some("Test User"))
        .await
        .expect("Failed to register user");

    let project = app
        .create_project(&user, "Test Project", &TestApp::unique_slug(), None)
        .await
        .expect("Failed to create project");

    // Login with project context
    let user_with_context = app
        .login_user(&email, password, Some(project.project.id))
        .await
        .expect("Failed to login with project context");

    // Act
    let response = app
        .get("/permissions", &user_with_context.access_token)
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let permissions = body["data"].as_array().unwrap();

    assert!(!permissions.is_empty());

    // Check for expected default permissions
    let permission_names: Vec<&str> = permissions
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(
        permission_names.contains(&"manage_members"),
        "Should have manage_members permission"
    );
    assert!(
        permission_names.contains(&"manage_roles"),
        "Should have manage_roles permission"
    );
    assert!(
        permission_names.contains(&"edit_content"),
        "Should have edit_content permission"
    );
    assert!(
        permission_names.contains(&"view_content"),
        "Should have view_content permission"
    );
}
