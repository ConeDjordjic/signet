//! Request ID middleware for tracing.

use axum::{
    extract::Request,
    http::{header::HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{info_span, Instrument};
use uuid::Uuid;

pub static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
pub static CORRELATION_ID_HEADER: HeaderName = HeaderName::from_static("x-correlation-id");

#[derive(Debug, Clone)]
pub struct RequestId(pub Arc<str>);

impl RequestId {
    pub fn new() -> Self {
        Self(Arc::from(Uuid::new_v4().to_string()))
    }

    pub fn from_string(id: impl Into<String>) -> Self {
        Self(Arc::from(id.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for RequestId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = extract_or_generate_request_id(&request);

    request.extensions_mut().insert(request_id.clone());

    let method = request.method().clone();
    let uri = request.uri().clone();
    let span = info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        uri = %uri,
    );

    let response = next.run(request).instrument(span).await;

    add_request_id_to_response(response, &request_id)
}

fn extract_or_generate_request_id(request: &Request) -> RequestId {
    if let Some(id) = request.headers().get(&REQUEST_ID_HEADER) {
        if let Ok(id_str) = id.to_str() {
            if is_valid_request_id(id_str) {
                return RequestId::from_string(id_str);
            }
        }
    }

    if let Some(id) = request.headers().get(&CORRELATION_ID_HEADER) {
        if let Ok(id_str) = id.to_str() {
            if is_valid_request_id(id_str) {
                return RequestId::from_string(id_str);
            }
        }
    }

    RequestId::new()
}

fn is_valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

fn add_request_id_to_response(mut response: Response, request_id: &RequestId) -> Response {
    if let Ok(header_value) = HeaderValue::from_str(request_id.as_str()) {
        response
            .headers_mut()
            .insert(REQUEST_ID_HEADER.clone(), header_value);
    }
    response
}

pub trait RequestIdExt {
    fn request_id(&self) -> RequestId;
}

impl RequestIdExt for Request {
    fn request_id(&self) -> RequestId {
        self.extensions()
            .get::<RequestId>()
            .cloned()
            .unwrap_or_else(RequestId::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_generation() {
        let id1 = RequestId::new();
        let id2 = RequestId::new();
        assert_ne!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn test_request_id_from_string() {
        let id = RequestId::from_string("test-request-id-123");
        assert_eq!(id.as_str(), "test-request-id-123");
    }

    #[test]
    fn test_request_id_display() {
        let id = RequestId::from_string("my-id");
        assert_eq!(format!("{}", id), "my-id");
    }

    #[test]
    fn test_valid_request_id() {
        assert!(is_valid_request_id("abc123"));
        assert!(is_valid_request_id("abc-123"));
        assert!(is_valid_request_id("abc_123"));
        assert!(is_valid_request_id("ABC-123_xyz"));
        assert!(is_valid_request_id("a".repeat(128).as_str()));
    }

    #[test]
    fn test_invalid_request_id() {
        assert!(!is_valid_request_id(""));
        assert!(!is_valid_request_id("abc 123"));
        assert!(!is_valid_request_id("abc@123"));
        assert!(!is_valid_request_id("abc/123"));
        assert!(!is_valid_request_id("a".repeat(129).as_str()));
    }
}
