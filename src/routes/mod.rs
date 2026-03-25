pub mod admin;
pub mod auth;
pub mod authorize;
pub mod authorize_url;
pub mod introspect;
pub mod jwks;
pub mod profile;
pub mod revoke;
pub mod static_files;
pub mod token;
pub mod userinfo;
pub mod well_known;

use axum::{http::{header, HeaderMap, StatusCode}, response::{Html, IntoResponse, Response}, routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::crypto::password;
use crate::models::client::Client;
use crate::AppState;

/// Extracts the User-Agent header, returning an error if missing or empty.
pub fn require_user_agent(headers: &HeaderMap) -> Result<&str, String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "Missing User-Agent header".to_string())
}

/// Builds a rate-limit key from a prefix, socket address and user-agent.
pub fn rate_limit_key(prefix: &str, addr: &SocketAddr, ua: &str) -> String {
    format!("{}|{}|{}", prefix, addr.ip(), ua)
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
    ip_key: &str,
) -> Result<Client, Response> {
    let (client_id, client_secret) = extract_basic_auth(headers)
        .unwrap_or_else(|| {
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

    let client = state.clients.find_by_id(&client_id).await
        .map_err(|_| oauth_error("server_error", "Database error"))?
        .ok_or_else(|| {
            state.login_rate_limiter.record_failure(ip_key);
            oauth_error("invalid_client", "Invalid client credentials")
        })?;

    if !password::verify_password(&client_secret, &client.client_secret_hash) {
        state.login_rate_limiter.record_failure(ip_key);
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
    fn rate_limit_key_format() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let key = rate_limit_key("login", &addr, "ua");
        assert_eq!(key, "login|127.0.0.1|ua");
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
        // Not base64
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic !!!invalid!!!"),
        );
        assert!(extract_basic_auth(&headers).is_none());

        // No colon separator
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
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-token"),
        );
        assert!(extract_basic_auth(&headers).is_none());
    }
}

pub fn build_api_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(|| async {
            Html(r#"
<!doctype html>
<html lang="en">
<head><title>GT Id</title></head>
<body>
<pre>
  ___________________ .___    .___
 /  _____/\__    ___/ |   | __| _/
/   \  ___  |    |    |   |/ __ |
\    \_\  \ |    |    |   / /_/ |
 \______  / |____|    |___\____ |
        \/                     \/
</pre>
</body>
</html>
"#)
        }))
        .route("/health", get(|| async { "ok" }))
        .route(
            "/.well-known/openid-configuration",
            get(well_known::openid_configuration),
        )
        .route("/jwks", get(jwks::jwks))
        .route("/token", axum::routing::post(token::token))
        .route("/userinfo", get(userinfo::userinfo))
        .route("/authorize-url", get(authorize_url::authorize_url))
        .route("/revoke", axum::routing::post(revoke::revoke))
        .route("/introspect", axum::routing::post(introspect::introspect))
}

pub fn build_ui_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(|| async {
            (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")]).into_response()
        }))
        .route("/static/{*path}", get(static_files::serve))
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route("/logout", axum::routing::post(auth::logout).get(auth::rp_initiated_logout))
        .route(
            "/authorize",
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route("/profile", get(profile::profile_page).post(profile::profile_submit))
        .route("/profile/password", axum::routing::post(profile::password_submit))
        .route("/admin", get(admin::dashboard))
        .route("/admin/clients", get(admin::clients_list))
        .route(
            "/admin/clients/create",
            get(admin::client_create_form).post(admin::client_create_submit),
        )
        .route(
            "/admin/clients/{id}/edit",
            get(admin::client_edit_form).post(admin::client_edit_submit),
        )
        .route(
            "/admin/clients/{id}/delete",
            axum::routing::post(admin::client_delete),
        )
        .route("/admin/users", get(admin::users_list))
        .route(
            "/admin/users/create",
            get(admin::user_create_form).post(admin::user_create_submit),
        )
        .route(
            "/admin/users/{id}/edit",
            get(admin::user_edit_form).post(admin::user_edit_submit),
        )
        .route(
            "/admin/users/{id}/delete",
            axum::routing::post(admin::user_delete),
        )
        .route("/admin/email-templates", get(admin::email_templates_list))
        .route(
            "/admin/email-templates/{template_type}/edit",
            get(admin::email_template_edit_form).post(admin::email_template_edit_submit),
        )
}
