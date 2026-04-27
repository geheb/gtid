use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use gtid_shared::AppStateCore;
use gtid_shared::crypto::{id::new_id, pkce::generate_pkce};
use gtid_shared::oauth::{urlencoding, validate_scope};

use crate::helpers::{api_error_bad_request, verify_client_credentials};

#[derive(Debug, Deserialize)]
pub struct AuthorizeUrlParams {
    pub scope: Option<String>,
}

pub async fn authorize_url(
    State(state): State<Arc<AppStateCore>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(params): Query<AuthorizeUrlParams>,
) -> Result<Response, Response> {
    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(|_| {
        crate::helpers::api_error_bad_request( "Missing User-Agent")
    })?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("authorize-url", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        state.login_rate_limiter.record_failure(rl_key);
        return Err(crate::helpers::api_error_too_many_requests());
    }

    // Client authentication via Basic Auth (required)
    let client =
        verify_client_credentials(None, None, &headers, &state, rl_key)
            .await?;

    // Scope validation: whitelist + openid mandatory, space-separated per RFC 6749
    let scope = params.scope.as_deref().unwrap_or("openid email profile");
    if let Err(msg) = validate_scope(scope) {
        return Err(api_error_bad_request(&msg));
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
        urlencoding(&client.client_id),
        urlencoding(&client.client_redirect_uri),
        urlencoding(scope),
        urlencoding(&state_param),
        urlencoding(&code_challenge),
        urlencoding(&nonce),
    );

    Ok(Json(serde_json::json!({
        "authorize_url": authorize_url,
        "code_verifier": code_verifier
    }))
    .into_response())
}
