use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::sync::Arc;

use gtid_shared::AppStateCore;
use gtid_shared::crypto::jwt;

pub(crate) async fn userinfo(
    State(state): State<Arc<AppStateCore>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Result<Response, Response> {
    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(|_| {
        crate::helpers::api_error_bad_request("Missing User-Agent")
    })?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("userinfo", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, endpoint = "userinfo", "Userinfo rate limited");
        return Err(crate::helpers::api_error_too_many_requests());
    }

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            crate::helpers::api_error_unauthorized("Missing Authorization header")
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        crate::helpers::api_error_unauthorized("Invalid Authorization header format")
    })?;

    let decoding_keys = state.key_store.decoding_keys();
    let claims = {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&[&state.config.issuer_uri]);
        validation.validate_aud = false;
        let mut result = None;
        for key in &decoding_keys {
            if let Ok(data) = jsonwebtoken::decode::<jwt::AccessTokenClaims>(token, key, &validation) {
                result = Some(data.claims);
                break;
            }
        }
        result.ok_or_else(|| {
            crate::helpers::api_error_unauthorized("Token verification failed")
        })?
    };
    state
        .clients
        .find_by_id(&claims.aud)
        .await
        .map_err(|e| crate::helpers::api_error_internal_server_error(&format!("find client {} failed for userinfo: {e}", claims.aud)))?
        .ok_or_else(|| {
            crate::helpers::api_error_unauthorized("Token verification failed")
        })?;

    let user = state
        .users
        .find_by_id(&claims.sub)
        .await
        .map_err(|e| crate::helpers::api_error_internal_server_error(&format!("find user {} failed for userinfo: {e}", claims.sub)))?
        .ok_or_else(|| {
            crate::helpers::api_error_unauthorized("Token verification failed")
        })?;

    let mut response = serde_json::json!({
        "sub": user.id,
        "roles": user.roles(),
    });

    if claims.scope.contains("email") || claims.scope.contains("openid") {
        response["email"] = serde_json::json!(user.email);
        response["email_verified"] = serde_json::json!(user.is_confirmed);
    }
    if claims.scope.contains("profile")
        && let Some(ref name) = user.display_name
    {
        response["name"] = serde_json::json!(name);
    }

    tracing::info!(event = "userinfo", sub = %user.id, scope = %claims.scope, "Returning userinfo");

    Ok(Json(response).into_response())
}
