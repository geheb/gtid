use axum::{
    Json,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};

use gtid_shared::AppStateCore;
use gtid_shared::crypto::password;
use gtid_shared::entities::client::Client;

fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

pub(crate) fn api_error_bad_request(description: &str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "bad_request", description)
}

pub(crate) fn api_error_too_many_requests() -> Response {
    api_error(StatusCode::TOO_MANY_REQUESTS, "too_many_requests", "Rate limit exceeded")
}

pub(crate) fn api_error_internal_server_error(log_msg: &str) -> Response {
    tracing::error!("{log_msg}");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_server_error", "Internal server error")
}

pub(crate) fn api_error_unauthorized(description: &str) -> Response {
    api_error(StatusCode::UNAUTHORIZED, "unauthorized", description)
}

fn api_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response()
}

pub(crate) async fn verify_client_credentials(
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
        return Err(api_error_bad_request("Missing client_id"));
    }
    if client_secret.is_empty() {
        return Err(api_error_bad_request("Missing client_secret"));
    }

    let client = state
        .clients
        .find_by_id(&client_id)
        .await
        .map_err(|e| api_error_internal_server_error(&format!("find client {client_id} failed for verify_client_credentials: {e}")))?
        .ok_or_else(|| {
            tracing::warn!(event = "client_auth_failed", client_id = %client_id, reason = "not_found", "Client authentication failed: unknown client_id");
            state.login_rate_limiter.record_failure(key);
            api_error_bad_request("Invalid client credentials")
        })?;

    if !password::verify_password(&client_secret, &client.client_secret_hash) {
        tracing::warn!(event = "client_auth_failed", client_id = %client_id, reason = "invalid_secret", "Client authentication failed: wrong secret");
        state.login_rate_limiter.record_failure(key);
        return Err(api_error_bad_request("Invalid client credentials"));
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
