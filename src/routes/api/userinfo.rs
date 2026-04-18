use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::AppStateCore;
use crate::crypto::jwt;

pub async fn userinfo(
    State(state): State<Arc<AppStateCore>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Result<Response, Response> {
    let ua = crate::routes::require_user_agent(&headers).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_request"})),
        )
            .into_response()
    })?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("userinfo", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, endpoint = "userinfo", "Userinfo rate limited");
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "too_many_requests"})),
        )
            .into_response());
    }

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing_token"})),
            )
                .into_response()
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response()
    })?;

    // #6: Try all available keys (current + previous) for verification
    // Decode without audience validation first, then verify client exists
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
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response()
        })?
    };
    // Verify the client in the token's audience exists
    state
        .clients
        .find_by_id(&claims.aud)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error"})),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response()
        })?;

    let user = state
        .users
        .find_by_id(&claims.sub)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response()
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
