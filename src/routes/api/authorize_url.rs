use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::crypto::{id::new_id, pkce::generate_pkce};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct AuthorizeUrlParams {
    pub client_id: String,
    pub scope: Option<String>,
}

pub async fn authorize_url(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(params): Query<AuthorizeUrlParams>,
) -> Result<Response, Response> {
    let ua = crate::routes::require_user_agent(&headers)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Missing User-Agent"}))).into_response())?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("authorize-url", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        state.login_rate_limiter.record_failure(rl_key);
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error": "Too many requests"}))).into_response());
    }

    let scope = params.scope.as_deref().unwrap_or("openid+email+profile");
    tracing::info!("Calling authorize-url client_id={} scope={} ...", params.client_id, scope);

    let client = state.clients.find_by_id(&params.client_id).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response())?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Unknown client_id"}))).into_response())?;

    let (code_verifier, code_challenge) = generate_pkce();
    let state_param = new_id();
    let nonce = new_id();

    let authorize_url = format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&nonce={}",
        state.config.public_ui_uri,
        crate::routes::urlencoding(&client.client_id),
        crate::routes::urlencoding(&client.client_redirect_uri),
        crate::routes::urlencoding(scope),
        crate::routes::urlencoding(&state_param),
        crate::routes::urlencoding(&code_challenge),
        crate::routes::urlencoding(&nonce),
    );

    Ok(Json(serde_json::json!({
        "authorize_url": authorize_url,
        "code_verifier": code_verifier
    })).into_response())
}
