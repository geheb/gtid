use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::net::SocketAddr;

use crate::AppState;
use crate::crypto::password;
use crate::models::client::Client;

/// Extracts the User-Agent header, returning an error if missing or empty.
pub fn require_user_agent(headers: &HeaderMap) -> Result<&str, String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "Missing User-Agent header".to_string())
}

/// Extracts the client IP, using X-Forwarded-For when trusted_proxies is enabled.
pub fn client_ip(headers: &HeaderMap, addr: &SocketAddr, trusted_proxies: bool) -> String {
    if trusted_proxies
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first_ip) = xff.split(',').next().map(|s| s.trim())
        && !first_ip.is_empty()
    {
        return first_ip.to_string();
    }
    addr.ip().to_string()
}

/// Percent-encodes a string per RFC 3986.
pub fn urlencoding(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Standard OAuth2 JSON error response.
pub fn oauth_error(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response()
}

/// Authenticates a client via Basic Auth header or form-encoded credentials.
/// Basic Auth takes precedence per RFC 6749 §2.3.1.
pub async fn verify_client_credentials(
    client_id_form: Option<&str>,
    client_secret_form: Option<&str>,
    headers: &HeaderMap,
    state: &AppState,
    key: u64,
) -> Result<Client, Response> {
    let (client_id, client_secret) = extract_basic_auth(headers).unwrap_or_else(|| {
        (
            client_id_form.unwrap_or("").to_string(),
            client_secret_form.unwrap_or("").to_string(),
        )
    });

    if client_id.is_empty() {
        return Err(oauth_error("invalid_request", "Missing client_id"));
    }
    if client_secret.is_empty() {
        return Err(oauth_error("invalid_request", "Missing client_secret"));
    }

    let client = state
        .clients
        .find_by_id(&client_id)
        .await
        .map_err(|_| oauth_error("server_error", "Database error"))?
        .ok_or_else(|| {
            tracing::warn!(event = "client_auth_failed", client_id = %client_id, reason = "not_found", "Client authentication failed: unknown client_id");
            state.login_rate_limiter.record_failure(key);
            oauth_error("invalid_client", "Invalid client credentials")
        })?;

    if !password::verify_password(&client_secret, &client.client_secret_hash) {
        tracing::warn!(event = "client_auth_failed", client_id = %client_id, reason = "invalid_secret", "Client authentication failed: wrong secret");
        state.login_rate_limiter.record_failure(key);
        return Err(oauth_error("invalid_client", "Invalid client credentials"));
    }

    Ok(client)
}

/// Parses Basic Auth header into (client_id, client_secret).
fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn require_user_agent_present() {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("TestAgent/1.0"));
        assert_eq!(require_user_agent(&headers).unwrap(), "TestAgent/1.0");
    }

    #[test]
    fn require_user_agent_missing() {
        let headers = HeaderMap::new();
        assert!(require_user_agent(&headers).is_err());
    }

    #[test]
    fn require_user_agent_empty() {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static(""));
        assert!(require_user_agent(&headers).is_err());
    }

    #[test]
    fn client_ip_without_proxy() {
        let headers = HeaderMap::new();
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, &addr, false), "192.168.1.1");
    }

    #[test]
    fn client_ip_ignores_xff_when_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1, 10.0.0.2"));
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, &addr, false), "192.168.1.1");
    }

    #[test]
    fn client_ip_uses_xff_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.5, 10.0.0.1"));
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, &addr, true), "203.0.113.5");
    }

    #[test]
    fn client_ip_falls_back_without_xff_header() {
        let headers = HeaderMap::new();
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, &addr, true), "192.168.1.1");
    }

    #[test]
    fn urlencoding_special_chars() {
        assert_eq!(urlencoding("hello world"), "hello%20world");
        assert_eq!(urlencoding("a+b=c"), "a%2Bb%3Dc");
        assert_eq!(urlencoding("test"), "test");
    }

    #[test]
    fn extract_basic_auth_valid() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("my-client:my-secret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        let (id, secret) = extract_basic_auth(&headers).unwrap();
        assert_eq!(id, "my-client");
        assert_eq!(secret, "my-secret");
    }

    #[test]
    fn extract_basic_auth_missing() {
        let headers = HeaderMap::new();
        assert!(extract_basic_auth(&headers).is_none());
    }

    #[test]
    fn extract_basic_auth_malformed() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!invalid!!!"));
        assert!(extract_basic_auth(&headers).is_none());

        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("no-colon-here");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert!(extract_basic_auth(&headers).is_none());
    }

    #[test]
    fn extract_basic_auth_bearer_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer some-token"));
        assert!(extract_basic_auth(&headers).is_none());
    }
}
