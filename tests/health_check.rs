//! Health check endpoint integration tests.
//!
//! These tests verify that the application starts correctly and the health
//! check endpoint is accessible.

mod common;

use common::TestApp;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn health_check_returns_ok() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app.get_public("/health").await;

    // Assert
    assert_eq!(response.status().as_u16(), 200);

    let body = response.text().await.expect("Failed to read response body");
    assert_eq!(body, "OK");
}

#[tokio::test]
#[serial]
async fn health_check_is_accessible_without_authentication() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act - Make request without any authentication header
    let response = app
        .client
        .get(format!("{}/health", app.base_url))
        .send()
        .await
        .expect("Failed to send request");

    // Assert - Should succeed without authentication
    assert!(response.status().is_success());
}

#[tokio::test]
#[serial]
async fn nonexistent_endpoint_returns_error() {
    // Arrange
    let app = TestApp::spawn().await;

    // Act
    let response = app.get_public("/nonexistent-endpoint").await;

    // Assert
    // The router may return 401 (auth middleware catches unmatched routes)
    // or 404 depending on route configuration. Both are acceptable as they
    // indicate the endpoint doesn't exist or isn't accessible.
    let status = response.status().as_u16();
    assert!(
        status == 404 || status == 401,
        "Expected 404 or 401, got {}",
        status
    );
}
