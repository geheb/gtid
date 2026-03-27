use axum::{
    extract::{ConnectInfo, State},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::crypto::jwt;
use crate::AppState;

#[derive(Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// RFC 7662 Token Introspection Endpoint.
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<IntrospectRequest>,
) -> Result<Response, Response> {
    tracing::info!("Calling introspect client_id={} ...", form.client_id.as_deref().unwrap_or(""));

    let ua = super::require_user_agent(&headers)
        .map_err(|e| super::oauth_error("invalid_request", &e))?;
    let ip = super::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("introspect", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return Err(super::oauth_error("slow_down", "Too many requests"));
    }

    let client = super::verify_client_credentials(
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        &headers, &state, rl_key,
    ).await?;

    let hint = form.token_type_hint.as_deref().unwrap_or("access_token");

    // Try as access token (JWT)
    if hint != "refresh_token" {
        let decoding_keys = state.key_store.decoding_keys();
        let key_refs: Vec<&jsonwebtoken::DecodingKey> = decoding_keys.iter().collect();
        if let Ok(claims) = jwt::decode_access_token_multi(
            &form.token,
            &key_refs,
            &state.config.issuer_uri,
            &client.client_id,
        ) {
            return Ok(Json(serde_json::json!({
                "active": true,
                "token_type": "Bearer",
                "scope": claims.scope,
                "client_id": claims.aud,
                "sub": claims.sub,
                "iss": claims.iss,
                "exp": claims.exp,
                "iat": claims.iat,
            }))
            .into_response());
        }
    }

    // Try as refresh token (DB lookup)
    if hint != "access_token" {
        if let Ok(crate::repositories::refresh_token::RefreshResult::Ok(rt)) =
            state.refresh_tokens.find_valid(&form.token).await
        {
            return Ok(Json(serde_json::json!({
                "active": true,
                "token_type": "refresh_token",
                "scope": rt.scope,
                "client_id": rt.client_id,
                "sub": rt.user_id,
            }))
            .into_response());
        }
    }

    // Token is not active
    Ok(Json(serde_json::json!({ "active": false })).into_response())
}
