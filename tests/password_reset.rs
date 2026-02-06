//! Integration tests for password reset functionality.

mod common;

use common::*;
use reqwest::StatusCode;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_forgot_password_returns_token() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": user.email
            }),
        )
        .await;

    assert_status!(response, StatusCode::OK.as_u16());

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["message"].is_string());
    assert!(body["reset_token"].is_string());
}

#[tokio::test]
#[serial]
async fn test_forgot_password_nonexistent_user_still_succeeds() {
    let app = TestApp::spawn().await;

    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": "nonexistent@example.com"
            }),
        )
        .await;

    // Should succeed to prevent email enumeration
    assert_status!(response, StatusCode::OK.as_u16());

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["message"].is_string());
    // No token for nonexistent user
    assert!(body["reset_token"].is_null());
}

#[tokio::test]
#[serial]
async fn test_reset_password_with_valid_token() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Request reset token
    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": user.email
            }),
        )
        .await;

    let body: serde_json::Value = response.json().await.unwrap();
    let reset_token = body["reset_token"].as_str().unwrap();

    // Reset password
    let new_password = "newSecurePassword123!";
    let response = app
        .post_public(
            "/auth/reset-password",
            serde_json::json!({
                "token": reset_token,
                "password": new_password
            }),
        )
        .await;

    assert_status!(response, StatusCode::OK.as_u16());

    // Verify old password no longer works
    let response = app
        .post_public(
            "/auth/login",
            serde_json::json!({
                "email": user.email,
                "password": user.password
            }),
        )
        .await;
    assert_status!(response, StatusCode::UNAUTHORIZED.as_u16());

    // Verify new password works
    let response = app
        .post_public(
            "/auth/login",
            serde_json::json!({
                "email": user.email,
                "password": new_password
            }),
        )
        .await;
    assert_status!(response, StatusCode::OK.as_u16());
}

#[tokio::test]
#[serial]
async fn test_reset_password_with_invalid_token() {
    let app = TestApp::spawn().await;

    let response = app
        .post_public(
            "/auth/reset-password",
            serde_json::json!({
                "token": "invalid_token_here",
                "password": "newSecurePassword123!"
            }),
        )
        .await;

    assert_status!(response, StatusCode::BAD_REQUEST.as_u16());
}

#[tokio::test]
#[serial]
async fn test_reset_token_can_only_be_used_once() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // Request reset token
    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": user.email
            }),
        )
        .await;

    let body: serde_json::Value = response.json().await.unwrap();
    let reset_token = body["reset_token"].as_str().unwrap();

    // First reset should succeed
    let response = app
        .post_public(
            "/auth/reset-password",
            serde_json::json!({
                "token": reset_token,
                "password": "firstNewPassword123!"
            }),
        )
        .await;
    assert_status!(response, StatusCode::OK.as_u16());

    // Second reset with same token should fail
    let response = app
        .post_public(
            "/auth/reset-password",
            serde_json::json!({
                "token": reset_token,
                "password": "secondNewPassword123!"
            }),
        )
        .await;
    assert_status!(response, StatusCode::BAD_REQUEST.as_u16());
}

#[tokio::test]
#[serial]
async fn test_new_reset_request_invalidates_old_token() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // First reset request
    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": user.email
            }),
        )
        .await;
    let body: serde_json::Value = response.json().await.unwrap();
    let first_token = body["reset_token"].as_str().unwrap().to_string();

    // Second reset request
    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": user.email
            }),
        )
        .await;
    let body: serde_json::Value = response.json().await.unwrap();
    let second_token = body["reset_token"].as_str().unwrap();

    // First token should no longer work
    let response = app
        .post_public(
            "/auth/reset-password",
            serde_json::json!({
                "token": first_token,
                "password": "newPassword123!"
            }),
        )
        .await;
    assert_status!(response, StatusCode::BAD_REQUEST.as_u16());

    // Second token should work
    let response = app
        .post_public(
            "/auth/reset-password",
            serde_json::json!({
                "token": second_token,
                "password": "newPassword123!"
            }),
        )
        .await;
    assert_status!(response, StatusCode::OK.as_u16());
}

#[tokio::test]
#[serial]
async fn test_reset_password_invalidates_sessions() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    // User's token should work before reset
    let response = app.get("/auth/me", &user.access_token).await;
    assert_status!(response, StatusCode::OK.as_u16());

    // Request and use reset token
    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": user.email
            }),
        )
        .await;
    let body: serde_json::Value = response.json().await.unwrap();
    let reset_token = body["reset_token"].as_str().unwrap();

    let response = app
        .post_public(
            "/auth/reset-password",
            serde_json::json!({
                "token": reset_token,
                "password": "newSecurePassword123!"
            }),
        )
        .await;
    assert_status!(response, StatusCode::OK.as_u16());

    // Old refresh token should no longer work
    let response = app
        .post_public(
            "/auth/refresh",
            serde_json::json!({
                "refresh_token": user.refresh_token
            }),
        )
        .await;
    assert_status!(response, StatusCode::UNAUTHORIZED.as_u16());
}

#[tokio::test]
#[serial]
async fn test_forgot_password_invalid_email_format() {
    let app = TestApp::spawn().await;

    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": "not-an-email"
            }),
        )
        .await;

    assert_status!(response, StatusCode::BAD_REQUEST.as_u16());
}

#[tokio::test]
#[serial]
async fn test_reset_password_weak_password() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    let response = app
        .post_public(
            "/auth/forgot-password",
            serde_json::json!({
                "email": user.email
            }),
        )
        .await;
    let body: serde_json::Value = response.json().await.unwrap();
    let reset_token = body["reset_token"].as_str().unwrap();

    // Try to reset with short password
    let response = app
        .post_public(
            "/auth/reset-password",
            serde_json::json!({
                "token": reset_token,
                "password": "short"
            }),
        )
        .await;

    assert_status!(response, StatusCode::BAD_REQUEST.as_u16());
}
