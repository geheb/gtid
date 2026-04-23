use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};

use gtid_shared::AppStateCore;
use gtid_shared::crypto::password;
use gtid_shared::entities::client::Client;

/// Parses Basic Auth header into (client_id, client_secret).
fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
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
    state: &AppStateCore,
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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
