//! Example: Simple Notes API using Signet for authentication
//!
//! This demonstrates how to integrate Signet into your backend.
//!
//! Run Signet first:
//!   cargo run
//!
//! Then run this example:
//!   cargo run --example notes_api
//!
//! Try it:
//!   # Register a user
//!   curl -X POST http://localhost:3001/register \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "user@example.com", "password": "password123"}'
//!
//!   # Login
//!   curl -X POST http://localhost:3001/login \
//!     -H "Content-Type: application/json" \
//!     -d '{"email": "user@example.com", "password": "password123"}'
//!
//!   # Create a note (use token from login response)
//!   curl -X POST http://localhost:3001/notes \
//!     -H "Content-Type: application/json" \
//!     -H "Authorization: Bearer <token>" \
//!     -d '{"title": "My Note", "content": "Hello world"}'
//!
//!   # List notes
//!   curl http://localhost:3001/notes \
//!     -H "Authorization: Bearer <token>"
//!
//!   # Get current user
//!   curl http://localhost:3001/me \
//!     -H "Authorization: Bearer <token>"

use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

const SIGNET_URL: &str = "http://localhost:8080";

#[derive(Clone)]
struct AppState {
    notes: Arc<RwLock<HashMap<Uuid, Vec<Note>>>>,
    http_client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Note {
    id: Uuid,
    title: String,
    content: String,
}

#[derive(Debug, Clone)]
struct AuthUser {
    user_id: Uuid,
    email: String,
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct CreateNoteRequest {
    title: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct SignetVerifyResponse {
    valid: bool,
    user_id: Option<Uuid>,
    email: Option<String>,
}

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    let Some(token) = token else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Missing authorization header"})),
        )
            .into_response();
    };

    let verify_response = state
        .http_client
        .post(format!("{}/auth/verify", SIGNET_URL))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await;

    let Ok(response) = verify_response else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "Failed to reach auth service"})),
        )
            .into_response();
    };

    let Ok(verify): Result<SignetVerifyResponse, _> = response.json().await else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "Invalid auth service response"})),
        )
            .into_response();
    };

    if !verify.valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid token"})),
        )
            .into_response();
    }

    let user = AuthUser {
        user_id: verify.user_id.unwrap(),
        email: verify.email.unwrap(),
    };

    request.extensions_mut().insert(user);
    next.run(request).await
}

async fn register(State(state): State<AppState>, Json(payload): Json<RegisterRequest>) -> Response {
    let response = state
        .http_client
        .post(format!("{}/auth/register", SIGNET_URL))
        .json(&serde_json::json!({
            "email": payload.email,
            "password": payload.password
        }))
        .send()
        .await;

    match response {
        Ok(res) => {
            let status = res.status();
            let body: serde_json::Value = res.json().await.unwrap_or_default();
            (StatusCode::from_u16(status.as_u16()).unwrap(), Json(body)).into_response()
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "Failed to reach auth service"})),
        )
            .into_response(),
    }
}

async fn login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Response {
    let response = state
        .http_client
        .post(format!("{}/auth/login", SIGNET_URL))
        .json(&serde_json::json!({
            "email": payload.email,
            "password": payload.password
        }))
        .send()
        .await;

    match response {
        Ok(res) => {
            let status = res.status();
            let body: serde_json::Value = res.json().await.unwrap_or_default();
            (StatusCode::from_u16(status.as_u16()).unwrap(), Json(body)).into_response()
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "Failed to reach auth service"})),
        )
            .into_response(),
    }
}

async fn create_note(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(payload): Json<CreateNoteRequest>,
) -> impl IntoResponse {
    let note = Note {
        id: Uuid::new_v4(),
        title: payload.title,
        content: payload.content,
    };

    let mut notes = state.notes.write().await;
    notes.entry(user.user_id).or_default().push(note.clone());

    (StatusCode::CREATED, Json(note))
}

async fn list_notes(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> impl IntoResponse {
    let notes = state.notes.read().await;
    let user_notes = notes.get(&user.user_id).cloned().unwrap_or_default();
    Json(user_notes)
}

async fn me(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    Json(serde_json::json!({
        "user_id": user.user_id,
        "email": user.email
    }))
}

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    let state = AppState {
        notes: Arc::new(RwLock::new(HashMap::new())),
        http_client: reqwest::Client::new(),
    };

    let protected_routes = Router::new()
        .route("/notes", post(create_note).get(list_notes))
        .route("/me", get(me))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/login", post(login));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    println!("Notes API running on http://localhost:3001");
    println!("Make sure Signet is running on http://localhost:8080");
    axum::serve(listener, app).await.unwrap();
}
