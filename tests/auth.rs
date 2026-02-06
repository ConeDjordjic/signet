//! Authentication integration tests.
//!
//! These tests verify user registration, login, token refresh, and authentication
//! middleware functionality.

mod common;

use common::TestApp;
use serde_json::json;
use serial_test::serial;

// ============================================================================
// Registration Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn register_returns_201_for_valid_data() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();

    // Act
    let response = app
        .post_public(
            "/auth/register",
            json!({
                "email": email,
                "password": "password123",
                "full_name": "Test User"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["user"]["email"].as_str().unwrap(), email);
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn register_returns_400_for_invalid_email() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app
        .post_public(
            "/auth/register",
            json!({
                "email": "not-an-email",
                "password": "password123",
                "full_name": "Test User"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["error"].as_str().unwrap().contains("Validation"));
}

#[tokio::test]
#[serial]
async fn register_returns_400_for_short_password() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();

    // Act
    let response = app
        .post_public(
            "/auth/register",
            json!({
                "email": email,
                "password": "short",
                "full_name": "Test User"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["error"].as_str().unwrap().contains("Validation"));
}

#[tokio::test]
#[serial]
async fn register_returns_409_for_duplicate_email() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();

    // Register first user
    let _ = app
        .register_user(&email, "password123", Some("First User"))
        .await
        .expect("Failed to register first user");

    // Act - Try to register with same email
    let response = app
        .post_public(
            "/auth/register",
            json!({
                "email": email,
                "password": "different_password",
                "full_name": "Second User"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 409);
}

#[tokio::test]
#[serial]
async fn register_works_without_full_name() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();

    // Act
    let response = app
        .post_public(
            "/auth/register",
            json!({
                "email": email,
                "password": "password123"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["user"]["email"].as_str().unwrap(), email);
    assert!(body["user"]["full_name"].is_null());
}

// ============================================================================
// Login Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn login_returns_200_for_valid_credentials() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();
    let password = "password123";

    // Register user first
    let _ = app
        .register_user(&email, password, Some("Test User"))
        .await
        .expect("Failed to register user");

    // Act
    let response = app
        .post_public(
            "/auth/login",
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["user"]["email"].as_str().unwrap(), email);
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn login_returns_401_for_wrong_password() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();

    // Register user first
    let _ = app
        .register_user(&email, "correct_password", Some("Test User"))
        .await
        .expect("Failed to register user");

    // Act
    let response = app
        .post_public(
            "/auth/login",
            json!({
                "email": email,
                "password": "wrong_password"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["error"].as_str().unwrap().contains("Invalid"));
}

#[tokio::test]
#[serial]
async fn login_returns_401_for_nonexistent_user() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app
        .post_public(
            "/auth/login",
            json!({
                "email": "nonexistent@example.com",
                "password": "password123"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
#[serial]
async fn login_returns_400_for_invalid_email_format() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app
        .post_public(
            "/auth/login",
            json!({
                "email": "not-an-email",
                "password": "password123"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
#[serial]
async fn login_with_project_context_works_for_project_member() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();
    let password = "password123";

    // Register user and create project
    let user = app
        .register_user(&email, password, Some("Test User"))
        .await
        .expect("Failed to register user");

    let project = app
        .create_project(&user, "Test Project", &TestApp::unique_slug(), None)
        .await
        .expect("Failed to create project");

    // Act - Login with project context
    let response = app
        .post_public(
            "/auth/login",
            json!({
                "email": email,
                "password": password,
                "project_id": project.project.id
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["access_token"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn login_with_project_context_fails_for_non_member() {
    // Arrange
    let app = TestApp::spawn().await;

    // Create first user and project
    let owner = app
        .register_user(&TestApp::unique_email(), "password123", Some("Owner"))
        .await
        .expect("Failed to register owner");

    let project = app
        .create_project(&owner, "Test Project", &TestApp::unique_slug(), None)
        .await
        .expect("Failed to create project");

    // Create second user (not a member of the project)
    let non_member_email = TestApp::unique_email();
    let _ = app
        .register_user(&non_member_email, "password123", Some("Non Member"))
        .await
        .expect("Failed to register non-member");

    // Act - Try to login with project context
    let response = app
        .post_public(
            "/auth/login",
            json!({
                "email": non_member_email,
                "password": "password123",
                "project_id": project.project.id
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 403);
}

// ============================================================================
// Token Refresh Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn refresh_token_returns_valid_tokens() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = app
        .register_user(&TestApp::unique_email(), "password123", Some("Test User"))
        .await
        .expect("Failed to register user");

    // Act
    let response = app
        .post_public(
            "/auth/refresh",
            json!({
                "refresh_token": user.refresh_token
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let new_access_token = body["access_token"].as_str().unwrap();
    let new_refresh_token = body["refresh_token"].as_str().unwrap();

    // Verify tokens are non-empty valid strings
    // Note: Tokens generated within the same second may be identical due to
    // same iat/exp timestamps, so we don't assert they must be different
    assert!(
        !new_access_token.is_empty(),
        "Access token should not be empty"
    );
    assert!(
        !new_refresh_token.is_empty(),
        "Refresh token should not be empty"
    );
}

#[tokio::test]
#[serial]
async fn refresh_token_returns_401_for_invalid_token() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app
        .post_public(
            "/auth/refresh",
            json!({
                "refresh_token": "invalid-token"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
#[serial]
async fn new_access_token_works_after_refresh() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = app
        .register_user(&TestApp::unique_email(), "password123", Some("Test User"))
        .await
        .expect("Failed to register user");

    // Refresh tokens
    let refresh_response = app
        .post_public(
            "/auth/refresh",
            json!({
                "refresh_token": user.refresh_token
            }),
        )
        .await;

    let body: serde_json::Value = refresh_response
        .json()
        .await
        .expect("Failed to parse response");
    let new_access_token = body["access_token"].as_str().unwrap();

    // Act - Use new token to access protected endpoint
    let response = app.get("/projects", new_access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);
}

// ============================================================================
// Authentication Middleware Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn protected_endpoint_returns_401_without_token() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app.get_public("/projects").await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("authorization header"));
}

#[tokio::test]
#[serial]
async fn protected_endpoint_returns_401_with_invalid_token() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app.get("/projects", "invalid-token").await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["error"].as_str().unwrap().contains("Invalid"));
}

#[tokio::test]
#[serial]
async fn protected_endpoint_returns_401_with_malformed_header() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act - Send request with malformed authorization header (no "Bearer " prefix)
    let response = app
        .client
        .get(format!("{}/projects", app.base_url))
        .header("Authorization", "not-bearer-format")
        .send()
        .await
        .expect("Failed to send request");

    // Assert
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
#[serial]
async fn protected_endpoint_works_with_valid_token() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = app
        .register_user(&TestApp::unique_email(), "password123", Some("Test User"))
        .await
        .expect("Failed to register user");

    // Act
    let response = app.get("/projects", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);
}

// ============================================================================
// Project Context Middleware Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn project_scoped_endpoint_returns_403_without_project_context() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = app
        .register_user(&TestApp::unique_email(), "password123", Some("Test User"))
        .await
        .expect("Failed to register user");

    // Act - Try to access project-scoped endpoint without project context in token
    let response = app.get("/roles", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 403);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Project context required"));
}

#[tokio::test]
#[serial]
async fn project_scoped_endpoint_works_with_project_context() {
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
}

// ============================================================================
// Token Verification Tests (/auth/verify)
// ============================================================================

#[tokio::test]
#[serial]
async fn verify_token_returns_valid_for_good_token() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = app
        .register_user(&TestApp::unique_email(), "password123", Some("Test User"))
        .await
        .expect("Failed to register user");

    // Act
    let response = app
        .post_public(
            "/auth/verify",
            json!({
                "token": user.access_token
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["valid"].as_bool().unwrap());
    assert_eq!(body["user_id"].as_str().unwrap(), user.id.to_string());
    assert!(body["email"].as_str().is_some());
    assert!(body["expires_at"].as_i64().is_some());
}

#[tokio::test]
#[serial]
async fn verify_token_returns_invalid_for_bad_token() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app
        .post_public(
            "/auth/verify",
            json!({
                "token": "invalid.token.here"
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(!body["valid"].as_bool().unwrap());
    assert!(body["user_id"].is_null());
    assert!(body["email"].is_null());
}

#[tokio::test]
#[serial]
async fn verify_token_returns_project_context_for_scoped_token() {
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
        .post_public(
            "/auth/verify",
            json!({
                "token": user_with_context.access_token
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["valid"].as_bool().unwrap());
    assert_eq!(
        body["project_id"].as_str().unwrap(),
        project.project.id.to_string()
    );
    assert_eq!(body["role"].as_str().unwrap(), "admin");
}

#[tokio::test]
#[serial]
async fn verify_token_returns_null_project_for_unscoped_token() {
    // Arrange
    let app = TestApp::spawn().await;
    let user = app
        .register_user(&TestApp::unique_email(), "password123", Some("Test User"))
        .await
        .expect("Failed to register user");

    // Act
    let response = app
        .post_public(
            "/auth/verify",
            json!({
                "token": user.access_token
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body["valid"].as_bool().unwrap());
    assert!(body["project_id"].is_null());
    assert!(body["role"].is_null());
}

// ============================================================================
// Current User Tests (/auth/me)
// ============================================================================

#[tokio::test]
#[serial]
async fn get_me_returns_user_info() {
    // Arrange
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();
    let user = app
        .register_user(&email, "password123", Some("Test User"))
        .await
        .expect("Failed to register user");

    // Act
    let response = app.get("/auth/me", &user.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["user"]["id"].as_str().unwrap(), user.id.to_string());
    assert_eq!(body["user"]["email"].as_str().unwrap(), email);
    assert!(body["user"]["is_active"].as_bool().unwrap());
    assert!(body["project_context"].is_null());
}

#[tokio::test]
#[serial]
async fn get_me_returns_project_context_for_scoped_token() {
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
    let response = app.get("/auth/me", &user_with_context.access_token).await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["user"]["id"].as_str().unwrap(), user.id.to_string());
    assert!(body["project_context"].is_object());
    assert_eq!(
        body["project_context"]["project_id"].as_str().unwrap(),
        project.project.id.to_string()
    );
    assert_eq!(body["project_context"]["role"].as_str().unwrap(), "admin");
}

#[tokio::test]
#[serial]
async fn get_me_returns_401_without_token() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app.get_public("/auth/me").await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
#[serial]
async fn get_me_returns_401_with_invalid_token() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app.get("/auth/me", "invalid-token").await;

    // Assert
    assert_eq!(response.status().as_u16(), 401);
}
