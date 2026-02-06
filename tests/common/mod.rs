//! Common test utilities and helpers for integration tests.
//!
//! This module provides shared functionality for setting up test environments,
//! making HTTP requests, and managing test data.

#![allow(dead_code)]

use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::net::TcpListener;
use uuid::Uuid;

use diesel::prelude::*;
use signet::{create_db_pool_with_url, create_router, AppState, Config, DbPool};

/// Atomic counter for generating unique port numbers for test servers.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(9000);

/// Test database URL - uses a separate test database.
/// Set TEST_DATABASE_URL environment variable or defaults to test database.
pub static TEST_DATABASE_URL: Lazy<String> = Lazy::new(|| {
    std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://signet_test:signet_test@localhost:5433/signet_test".to_string()
    })
});

/// Pre-generated Ed25519 key pair for tests.
pub static TEST_JWT_PRIVATE_KEY: Lazy<String> = Lazy::new(|| {
    let (private_key, _) = signet::auth::jwt::JwtConfig::generate_key_pair();
    private_key
});

/// A test application instance with its own HTTP client and base URL.
pub struct TestApp {
    pub client: Client,
    pub base_url: String,
    pub db_url: String,
    pub db_pool: DbPool,
}

/// Response from user registration or login.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
}

/// User data returned from API.
#[derive(Debug, Clone, Deserialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub full_name: Option<String>,
    pub is_active: bool,
    pub created_at: chrono::NaiveDateTime,
}

/// Test user with credentials and tokens.
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub access_token: String,
    pub refresh_token: String,
}

/// Test project data.
#[derive(Debug, Clone, Deserialize)]
pub struct ProjectResponse {
    pub project: ProjectData,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProjectData {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
}

impl TestApp {
    /// Spawns a new test application on a random port.
    ///
    /// This creates a fresh application instance connected to the test database.
    /// Each test should call this to get an isolated test environment.
    pub async fn spawn() -> Self {
        // Set required environment variables for tests
        std::env::set_var("JWT_PRIVATE_KEY", TEST_JWT_PRIVATE_KEY.as_str());
        std::env::set_var("DATABASE_URL", TEST_DATABASE_URL.as_str());

        let db_pool = create_db_pool_with_url(&TEST_DATABASE_URL);
        let config = Config::default_for_testing();
        let state = AppState::new(db_pool, None, &config);
        let app = create_router(state, &config);

        // Get a unique port for this test instance
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let addr = format!("127.0.0.1:{}", port);

        let listener = TcpListener::bind(&addr)
            .await
            .expect("Failed to bind test server");

        let actual_port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        Self {
            client: Client::new(),
            base_url: format!("http://127.0.0.1:{}", actual_port),
            db_url: TEST_DATABASE_URL.clone(),
            db_pool: create_db_pool_with_url(&TEST_DATABASE_URL),
        }
    }

    /// Generates a unique email for testing.
    pub fn unique_email() -> String {
        format!("test_{}@example.com", Uuid::new_v4())
    }

    /// Generates a unique project slug for testing.
    pub fn unique_slug() -> String {
        format!("test-project-{}", Uuid::new_v4())
    }

    /// Registers a new user and returns the test user data.
    pub async fn register_user(
        &self,
        email: &str,
        password: &str,
        full_name: Option<&str>,
    ) -> Result<TestUser, reqwest::Error> {
        let response = self
            .client
            .post(format!("{}/auth/register", self.base_url))
            .json(&json!({
                "email": email,
                "password": password,
                "full_name": full_name
            }))
            .send()
            .await?;

        let auth: AuthResponse = response.json().await?;

        Ok(TestUser {
            id: auth.user.id,
            email: auth.user.email,
            password: password.to_string(),
            access_token: auth.access_token,
            refresh_token: auth.refresh_token,
        })
    }

    /// Logs in an existing user.
    pub async fn login_user(
        &self,
        email: &str,
        password: &str,
        project_id: Option<Uuid>,
    ) -> Result<TestUser, reqwest::Error> {
        let mut payload = json!({
            "email": email,
            "password": password
        });

        if let Some(pid) = project_id {
            payload["project_id"] = json!(pid);
        }

        let response = self
            .client
            .post(format!("{}/auth/login", self.base_url))
            .json(&payload)
            .send()
            .await?;

        let auth: AuthResponse = response.json().await?;

        Ok(TestUser {
            id: auth.user.id,
            email: auth.user.email,
            password: password.to_string(),
            access_token: auth.access_token,
            refresh_token: auth.refresh_token,
        })
    }

    /// Creates a new project for the given user.
    pub async fn create_project(
        &self,
        user: &TestUser,
        name: &str,
        slug: &str,
        description: Option<&str>,
    ) -> Result<ProjectResponse, reqwest::Error> {
        let response = self
            .client
            .post(format!("{}/projects", self.base_url))
            .bearer_auth(&user.access_token)
            .json(&json!({
                "name": name,
                "slug": slug,
                "description": description
            }))
            .send()
            .await?;

        response.json().await
    }

    /// Makes an authenticated GET request.
    pub async fn get(&self, path: &str, token: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .send()
            .await
            .expect("Failed to send GET request")
    }

    /// Makes an authenticated POST request with JSON body.
    pub async fn post(&self, path: &str, token: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .expect("Failed to send POST request")
    }

    /// Makes an authenticated PUT request with JSON body.
    pub async fn put(&self, path: &str, token: &str, body: Value) -> reqwest::Response {
        self.client
            .put(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .expect("Failed to send PUT request")
    }

    /// Makes an authenticated DELETE request.
    pub async fn delete(&self, path: &str, token: &str) -> reqwest::Response {
        self.client
            .delete(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .send()
            .await
            .expect("Failed to send DELETE request")
    }

    /// Makes an unauthenticated GET request.
    pub async fn get_public(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("Failed to send GET request")
    }

    /// Makes an unauthenticated POST request with JSON body.
    pub async fn post_public(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .json(&body)
            .send()
            .await
            .expect("Failed to send POST request")
    }

    /// Counts outbox events of a specific type.
    pub fn count_outbox_events(&self, event_type: &str) -> i64 {
        use signet::schema::outbox_events;

        let mut conn = self.db_pool.get().expect("Failed to get connection");
        outbox_events::table
            .filter(outbox_events::event_type.eq(event_type))
            .count()
            .get_result(&mut conn)
            .unwrap_or(0)
    }

    /// Gets the latest outbox event of a specific type.
    pub fn get_latest_outbox_event(&self, event_type: &str) -> Option<signet::models::OutboxEvent> {
        use signet::schema::outbox_events;

        let mut conn = self.db_pool.get().expect("Failed to get connection");
        outbox_events::table
            .filter(outbox_events::event_type.eq(event_type))
            .order(outbox_events::created_at.desc())
            .first(&mut conn)
            .ok()
    }
}

/// Creates a test user with a unique email.
pub async fn create_test_user(app: &TestApp) -> TestUser {
    let email = TestApp::unique_email();
    app.register_user(&email, "password123", Some("Test User"))
        .await
        .expect("Failed to create test user")
}

/// Creates a test user and project, returning the user with project context token.
pub async fn create_test_user_with_project(app: &TestApp) -> (TestUser, ProjectResponse) {
    let user = create_test_user(app).await;
    let slug = TestApp::unique_slug();

    let project = app
        .create_project(&user, "Test Project", &slug, Some("Test description"))
        .await
        .expect("Failed to create test project");

    // Re-login with project context
    let user_with_project = app
        .login_user(&user.email, &user.password, Some(project.project.id))
        .await
        .expect("Failed to login with project context");

    (user_with_project, project)
}

/// Asserts that a response has a specific status code.
#[macro_export]
macro_rules! assert_status {
    ($response:expr, $expected:expr) => {
        assert_eq!(
            $response.status().as_u16(),
            $expected,
            "Expected status {}, got {}",
            $expected,
            $response.status()
        );
    };
}

/// Asserts that a response is successful (2xx).
#[macro_export]
macro_rules! assert_success {
    ($response:expr) => {
        assert!(
            $response.status().is_success(),
            "Expected success, got status {}",
            $response.status()
        );
    };
}

/// Asserts that a response is a client error (4xx).
#[macro_export]
macro_rules! assert_client_error {
    ($response:expr) => {
        assert!(
            $response.status().is_client_error(),
            "Expected client error, got status {}",
            $response.status()
        );
    };
}
