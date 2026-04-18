use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::AppStateCore;
use crate::crypto::{constant_time, jwt, pkce};
use crate::datetime::SqliteDateTimeExt;
use crate::repositories::auth_code::ConsumeResult;
use crate::repositories::refresh_token::RefreshResult;

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

impl TokenRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        use crate::routes::ui::{
            MAX_CLIENT_ID, MAX_CLIENT_SECRET, MAX_CODE_VERIFIER, MAX_GRANT_TYPE, MAX_REFRESH_TOKEN, MAX_SCOPE, MAX_URI,
            MAX_UUID,
        };
        if self.grant_type.len() > MAX_GRANT_TYPE
            || self.code.as_ref().is_some_and(|c| c.len() > MAX_UUID)
            || self.redirect_uri.as_ref().is_some_and(|u| u.len() > MAX_URI)
            || self.client_id.as_ref().is_some_and(|c| c.len() > MAX_CLIENT_ID)
            || self.client_secret.as_ref().is_some_and(|s| s.len() > MAX_CLIENT_SECRET)
            || self.code_verifier.as_ref().is_some_and(|v| v.len() > MAX_CODE_VERIFIER)
            || self.refresh_token.as_ref().is_some_and(|t| t.len() > MAX_REFRESH_TOKEN)
            || self.scope.as_ref().is_some_and(|s| s.len() > MAX_SCOPE)
        {
            return Err("invalid request");
        }
        Ok(())
    }
}

pub async fn token(
    State(state): State<Arc<AppStateCore>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<TokenRequest>,
) -> Result<Response, Response> {
    form.validate()
        .map_err(|e| super::oauth_error("invalid_request", e))?;

    tracing::info!(
        "Calling token client_id={}, grant_type={} ...",
        form.client_id.as_deref().unwrap_or(""),
        form.grant_type
    );

    let ua =
        crate::routes::require_user_agent(&headers).map_err(|e| super::oauth_error("invalid_request", &e))?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("token", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return Err(super::oauth_error("slow_down", "Too many requests"));
    }

    // #13: Grant type restriction
    if !state.config.grant_type_allowed(&form.grant_type) {
        return Err(super::oauth_error(
            "unsupported_grant_type",
            "This grant_type is not allowed",
        ));
    }

    match form.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(state, form, &headers, rl_key).await,
        "refresh_token" => handle_refresh_token(state, form, &headers, rl_key).await,
        _ => Err(super::oauth_error(
            "unsupported_grant_type",
            "Unsupported grant_type",
        )),
    }
}

async fn handle_authorization_code(
    state: Arc<AppStateCore>,
    form: TokenRequest,
    headers: &axum::http::HeaderMap,
    key: u64,
) -> Result<Response, Response> {
    let client = super::verify_client_credentials(
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        headers,
        &state,
        key,
    )
    .await?;

    let code = form
        .code
        .as_deref()
        .ok_or_else(|| super::oauth_error("invalid_request", "Missing code"))?;
    let code_verifier = form
        .code_verifier
        .as_deref()
        .ok_or_else(||super::oauth_error("invalid_request", "Missing code_verifier"))?;
    let redirect_uri = form
        .redirect_uri
        .as_deref()
        .ok_or_else(|| super::oauth_error("invalid_request", "Missing redirect_uri"))?;

    // #4: Replay detection with cascade revocation
    let auth_code = match state
        .auth_codes
        .consume(code)
        .await
        .map_err(|_| super::oauth_error("server_error", "Database error"))?
    {
        ConsumeResult::Ok(ac) => ac,
        ConsumeResult::Replayed(ac) => {
            tracing::warn!(event = "auth_code_replay", client_id = %client.client_id, "Auth code replay detected, revoking token family");
            if let Err(e) = state.refresh_tokens.revoke_family(&ac.code).await {
                tracing::error!("Failed to revoke token family on code replay: {e}");
            }
            return Err(super::oauth_error(
                "invalid_grant",
                "Authorization code already used",
            ));
        }
        ConsumeResult::NotFound => {
            return Err(super::oauth_error(
                "invalid_grant",
                "Invalid or expired authorization code",
            ));
        }
    };

    // #2: Verify auth code was issued to this client
    if !constant_time::constant_time_str_eq(&auth_code.client_id, &client.client_id) {
        return Err(super::oauth_error(
            "invalid_grant",
            "Code was not issued to this client",
        ));
    }

    if !constant_time::constant_time_str_eq(&auth_code.redirect_uri, redirect_uri) {
        return Err(super::oauth_error("invalid_grant", "redirect_uri mismatch"));
    }

    if !pkce::verify_pkce_s256(code_verifier, &auth_code.code_challenge) {
        return Err(super::oauth_error("invalid_grant", "PKCE verification failed"));
    }

    let user = state
        .users
        .find_by_id(&auth_code.user_id)
        .await
        .map_err(|_| super::oauth_error("server_error", "Database error"))?
        .ok_or_else(|| super::oauth_error("server_error", "User not found"))?;

    let (encoding_key, kid) = state.key_store.signing_key();

    let access_token = jwt::issue_access_token(
        &encoding_key,
        &kid,
        &state.config.issuer_uri,
        &client.client_id,
        &user.id,
        &auth_code.scope,
        state.config.access_token_expiry_secs,
    )
    .map_err(|_| super::oauth_error("server_error", "Failed to issue access token"))?;

    // #1: at_hash - pass access_token to id_token issuer
    let id_token = jwt::issue_id_token(jwt::IdTokenParams {
        encoding_key: &encoding_key,
        kid: &kid,
        issuer: &state.config.issuer_uri,
        client_id: &client.client_id,
        user_id: &user.id,
        email: &user.email,
        email_verified: user.is_confirmed,
        display_name: user.display_name.as_deref(),
        nonce: auth_code.nonce.as_deref(),
        access_token: &access_token,
        roles: user.roles().into_iter().map(String::from).collect(),
        expiry_secs: state.config.id_token_expiry_secs,
    })
    .map_err(|_| super::oauth_error("server_error", "Failed to issue ID token"))?;

    // #3 + #12: Refresh token bound to client_id and token family (auth code)
    let refresh_token_value = crate::crypto::id::new_id();
    let refresh_expires = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(state.config.refresh_token_expiry_days))
        .ok_or_else(|| super::oauth_error("server_error", "Token expiry overflow"))?
        .to_sqlite();

    state
        .refresh_tokens
        .create(
            &refresh_token_value,
            &client.client_id,
            &user.id,
            &auth_code.scope,
            &auth_code.code, // token_family = auth code
            &refresh_expires,
        )
        .await
        .map_err(|_| super::oauth_error("server_error", "Failed to create refresh token"))?;

    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": state.config.access_token_expiry_secs,
            "id_token": id_token,
            "refresh_token": refresh_token_value,
            "scope": auth_code.scope
        })),
    )
        .into_response())
}

async fn handle_refresh_token(
    state: Arc<AppStateCore>,
    form: TokenRequest,
    headers: &axum::http::HeaderMap,
    key: u64,
) -> Result<Response, Response> {
    let client = super::verify_client_credentials(
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        headers,
        &state,
        key,
    )
    .await?;

    let refresh_token_str = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| super::oauth_error("invalid_request", "Missing refresh_token"))?;

    // #12: Detect refresh token reuse -> revoke entire family
    let refresh_token = match state
        .refresh_tokens
        .find_valid(refresh_token_str)
        .await
        .map_err(|_| super::oauth_error("server_error", "Database error"))?
    {
        RefreshResult::Ok(rt) => rt,
        RefreshResult::Reused(family) => {
            tracing::warn!(event = "refresh_token_reuse", client_id = %client.client_id, family = %family, "Refresh token reuse detected, revoking token family");
            if let Err(e) = state.refresh_tokens.revoke_family(&family).await {
                tracing::error!("Failed to revoke token family on token reuse: {e}");
            }
            return Err(super::oauth_error(
                "invalid_grant",
                "Token reuse detected, all tokens revoked",
            ));
        }
        RefreshResult::NotFound => {
            return Err(super::oauth_error(
                "invalid_grant",
                "Invalid or expired refresh token",
            ));
        }
    };

    // #3: Verify refresh token was issued to this client
    if !constant_time::constant_time_str_eq(&refresh_token.client_id, &client.client_id) {
        return Err(super::oauth_error(
            "invalid_grant",
            "Token was not issued to this client",
        ));
    }

    // Revoke old token before issuing new one
    state
        .refresh_tokens
        .revoke(refresh_token_str)
        .await
        .map_err(|_| super::oauth_error("server_error", "Database error"))?;

    let user = state
        .users
        .find_by_id(&refresh_token.user_id)
        .await
        .map_err(|_| super::oauth_error("server_error", "Database error"))?
        .ok_or_else(|| super::oauth_error("server_error", "User not found"))?;

    // #7: Scope downscoping - client may request a subset of the original scope
    let effective_scope = if let Some(ref requested_scope) = form.scope {
        let original_scopes: std::collections::HashSet<&str> = refresh_token.scope.split_whitespace().collect();
        for s in requested_scope.split_whitespace() {
            if !original_scopes.contains(s) {
                return Err(super::oauth_error(
                    "invalid_scope",
                    &format!("Scope '{s}' exceeds original grant"),
                ));
            }
        }
        requested_scope.clone()
    } else {
        refresh_token.scope.clone()
    };

    let (encoding_key, kid) = state.key_store.signing_key();

    let access_token = jwt::issue_access_token(
        &encoding_key,
        &kid,
        &state.config.issuer_uri,
        &client.client_id,
        &user.id,
        &effective_scope,
        state.config.access_token_expiry_secs,
    )
    .map_err(|_| super::oauth_error("server_error", "Failed to issue access token"))?;

    // #12: New refresh token inherits token_family for chain tracking
    let new_refresh_token = crate::crypto::id::new_id();
    let refresh_expires = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(state.config.refresh_token_expiry_days))
        .ok_or_else(|| super::oauth_error("server_error", "Token expiry overflow"))?
        .to_sqlite();

    state
        .refresh_tokens
        .create(
            &new_refresh_token,
            &client.client_id,
            &user.id,
            &effective_scope,
            &refresh_token.token_family, // preserve family
            &refresh_expires,
        )
        .await
        .map_err(|_| super::oauth_error("server_error", "Failed to create refresh token"))?;

    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": state.config.access_token_expiry_secs,
            "refresh_token": new_refresh_token,
            "scope": effective_scope
        })),
    )
        .into_response())
}
