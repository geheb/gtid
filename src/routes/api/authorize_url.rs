use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::AppState;
use crate::crypto::{id::new_id, pkce::generate_pkce};

#[derive(Debug, Deserialize)]
pub struct AuthorizeUrlParams {
    pub scope: Option<String>,
}

pub async fn authorize_url(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(params): Query<AuthorizeUrlParams>,
) -> Result<Response, Response> {
    let ua = crate::routes::require_user_agent(&headers).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing User-Agent"})),
        )
            .into_response()
    })?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("authorize-url", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        state.login_rate_limiter.record_failure(rl_key);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many requests"})),
        )
            .into_response());
    }

    // Client authentication via Basic Auth (required)
    let client =
        super::verify_client_credentials(None, None, &headers, &state, rl_key)
            .await?;

    // Scope validation: whitelist + openid mandatory, space-separated per RFC 6749
    let scope = params.scope.as_deref().unwrap_or("openid email profile");
    if let Err(msg) = crate::routes::api::validate_scope(scope) {
        return Err(super::oauth_error("invalid_scope", &msg));
    }

    tracing::info!(
        event = "authorize_url",
        client_id = %client.client_id,
        scope = %scope,
        "Generating authorize URL"
    );

    let (code_verifier, code_challenge) = generate_pkce();
    let state_param = new_id();
    let nonce = new_id();

    let authorize_url = format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&nonce={}",
        state.config.public_ui_uri,
        super::urlencoding(&client.client_id),
        super::urlencoding(&client.client_redirect_uri),
        super::urlencoding(scope),
        super::urlencoding(&state_param),
        super::urlencoding(&code_challenge),
        super::urlencoding(&nonce),
    );

    Ok(Json(serde_json::json!({
        "authorize_url": authorize_url,
        "code_verifier": code_verifier
    }))
    .into_response())
}
