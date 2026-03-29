use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::AppState;

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// RFC 7009 Token Revocation Endpoint.
/// Always returns 200 OK per spec, even if the token was invalid or already revoked.
/// Revokes the entire token family (cascade) to ensure derived tokens are also invalidated.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<RevokeRequest>,
) -> Result<Response, Response> {
    tracing::info!("Calling revoke client_id={} ...", form.client_id.as_deref().unwrap_or(""));

    let ua = super::require_user_agent(&headers)
        .map_err(|e| super::oauth_error("invalid_request", &e))?;
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("revoke", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return Err(super::oauth_error("slow_down", "Too many requests"));
    }

    super::verify_client_credentials(
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        &headers, &state, rl_key,
    ).await?;

    // Look up the token to find its family, then revoke the entire family
    if let Ok(crate::repositories::refresh_token::RefreshResult::Ok(rt)) =
        state.refresh_tokens.find_valid(&form.token).await
    {
        let _ = state.refresh_tokens.revoke_family(&rt.token_family).await;
    } else {
        // Token may already be revoked or not exist - revoke by token directly per spec
        let _ = state.refresh_tokens.revoke(&form.token).await;
    }

    Ok(StatusCode::OK.into_response())
}
