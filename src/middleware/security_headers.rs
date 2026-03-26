use axum::{
    body::Body,
    extract::State,
    http::{header::HeaderName, HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::AppState;

pub async fn api_security_headers(request: Request<Body>, next: Next) -> Response {
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
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );

    response
}

pub async fn ui_security_headers(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let clients = state.clients.list().await.unwrap_or_default();
    let origins: Vec<String> = clients.iter()
        .filter_map(|c| extract_origin(&c.client_redirect_uri))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let form_action = if origins.is_empty() {
        "'self'".to_string()
    } else {
        format!("'self' {}", origins.join(" "))
    };
    let csp = format!(
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; form-action {form_action}; frame-ancestors 'none'; base-uri 'self'"
    );

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
        headers.insert(
            HeaderName::from_static("content-security-policy"),
            csp_value,
        );
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
    headers.insert(
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    );

    response
}

fn extract_origin(url: &str) -> Option<String> {
    let after_scheme = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let scheme = if url.starts_with("https") { "https" } else { "http" };
    let host = after_scheme.split('/').next()?;
    Some(format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_origin_https() {
        assert_eq!(
            extract_origin("https://example.com/callback"),
            Some("https://example.com".to_string()),
        );
    }

    #[test]
    fn extract_origin_http_with_port() {
        assert_eq!(
            extract_origin("http://localhost:8080/cb"),
            Some("http://localhost:8080".to_string()),
        );
    }

    #[test]
    fn extract_origin_no_path() {
        assert_eq!(
            extract_origin("https://example.com"),
            Some("https://example.com".to_string()),
        );
    }

    #[test]
    fn extract_origin_invalid() {
        assert_eq!(extract_origin("ftp://example.com"), None);
        assert_eq!(extract_origin("not-a-url"), None);
        assert_eq!(extract_origin(""), None);
    }
}
