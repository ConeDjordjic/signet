//! Request metrics middleware.

use axum::{extract::Request, middleware::Next, response::Response};

use crate::telemetry::metrics::record_request_latency;

pub async fn metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let start = std::time::Instant::now();

    let response = next.run(request).await;

    record_request_latency(&method, &path, response.status().as_u16(), start.elapsed());

    response
}
