// scope: ui — ui_security_headers reads AppState.csp; api variant lives in gtid_shared::middleware::security_headers
use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Request, header::HeaderName},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::AppState;

pub async fn ui_security_headers(State(state): State<Arc<AppState>>, request: Request<Body>, next: Next) -> Response {
    let csp = state.csp.read().unwrap_or_else(|e| e.into_inner()).clone();

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    if let Ok(csp_value) = HeaderValue::from_str(&csp) {
        headers.insert(HeaderName::from_static("content-security-policy"), csp_value);
    } else {
        tracing::error!("Invalid CSP header value, skipping");
    }
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(HeaderName::from_static("pragma"), HeaderValue::from_static("no-cache"));

    response
}
