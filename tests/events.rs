//! Integration tests for the event outbox system.

mod common;

use common::*;
use reqwest::StatusCode;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_registration_creates_event() {
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();

    let before_count = app.count_outbox_events("user.registered");

    let response = app
        .post_public(
            "/auth/register",
            serde_json::json!({
                "email": email,
                "password": "password123",
                "full_name": "Test User"
            }),
        )
        .await;

    assert_status!(response, StatusCode::OK.as_u16());

    let after_count = app.count_outbox_events("user.registered");
    assert!(after_count > before_count, "Expected new outbox event");

    let event = app.get_latest_outbox_event("user.registered");
    assert!(event.is_some(), "Should have outbox event");

    let event = event.unwrap();
    assert_eq!(event.aggregate_type, "user");
    let data = event.payload.get("data").expect("Should have data field");
    assert!(data.get("email").is_some());
}

#[tokio::test]
#[serial]
async fn test_login_creates_event() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    let before_count = app.count_outbox_events("auth.login.success");

    let response = app
        .post_public(
            "/auth/login",
            serde_json::json!({
                "email": user.email,
                "password": user.password
            }),
        )
        .await;

    assert_status!(response, StatusCode::OK.as_u16());

    let after_count = app.count_outbox_events("auth.login.success");
    assert!(after_count > before_count, "Expected new login event");

    let event = app.get_latest_outbox_event("auth.login.success");
    assert!(event.is_some());

    let event = event.unwrap();
    assert_eq!(event.aggregate_type, "user");
    assert_eq!(event.aggregate_id, user.id);
}

#[tokio::test]
#[serial]
async fn test_failed_login_creates_event() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    let before_count = app.count_outbox_events("auth.login.failed");

    let response = app
        .post_public(
            "/auth/login",
            serde_json::json!({
                "email": user.email,
                "password": "wrong_password"
            }),
        )
        .await;

    assert_status!(response, StatusCode::UNAUTHORIZED.as_u16());

    let after_count = app.count_outbox_events("auth.login.failed");
    assert!(after_count > before_count, "Expected failed login event");

    let event = app.get_latest_outbox_event("auth.login.failed");
    assert!(event.is_some());

    let event = event.unwrap();
    let data = event.payload.get("data").expect("Should have data field");
    assert!(data.get("reason").is_some());
}

#[tokio::test]
#[serial]
async fn test_logout_all_creates_event() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    let before_count = app.count_outbox_events("auth.logout");

    let response = app
        .post(
            "/auth/logout-all",
            &user.access_token,
            serde_json::json!({}),
        )
        .await;

    assert_status!(response, StatusCode::NO_CONTENT.as_u16());

    let after_count = app.count_outbox_events("auth.logout");
    assert!(after_count > before_count, "Expected logout event");
}

#[tokio::test]
#[serial]
async fn test_account_deletion_creates_event() {
    let app = TestApp::spawn().await;
    let user = create_test_user(&app).await;

    let before_count = app.count_outbox_events("user.deleted");

    let response = app.delete("/auth/account", &user.access_token).await;

    assert_status!(response, StatusCode::NO_CONTENT.as_u16());

    let after_count = app.count_outbox_events("user.deleted");
    assert!(
        after_count > before_count,
        "Expected account deletion event"
    );
}

#[tokio::test]
#[serial]
async fn test_event_contains_request_metadata() {
    let app = TestApp::spawn().await;
    let email = TestApp::unique_email();

    app.post_public(
        "/auth/register",
        serde_json::json!({
            "email": email,
            "password": "password123",
            "full_name": "Test User"
        }),
    )
    .await;

    let event = app.get_latest_outbox_event("user.registered").unwrap();

    assert!(!event.published);
    assert!(event.published_at.is_none());
    assert!(event.created_at <= chrono::Utc::now().naive_utc());
}
