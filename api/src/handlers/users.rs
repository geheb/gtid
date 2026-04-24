use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use gtid_shared::AppStateCore;
use gtid_shared::crypto::password;
use gtid_shared::limits::{MAX_DISPLAY_NAME, MAX_EMAIL, MAX_PASSWORD, MAX_ROLE};
use gtid_shared::middleware::language::Lang;
use std::collections::HashSet;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    #[serde(default)]
    pub is_confirmed: bool,
}

pub async fn create_user(
    State(state): State<Arc<AppStateCore>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    lang: Lang,
    Json(body): Json<CreateUserRequest>,
) -> Result<Response, Response> {
    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(|_| {
        crate::helpers::api_error(StatusCode::BAD_REQUEST, "invalid_request", "Missing User-Agent")
    })?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("create_user", &ip, ua);

    if state.login_rate_limiter.is_limited(rl_key) {
        return Err(crate::helpers::api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Rate limit exceeded",
        ));
    }

    let _client = crate::helpers::verify_client_credentials(None, None, &headers, &state, rl_key)
        .await
        .map_err(|e| e)?;

    if body.email.len() > MAX_EMAIL
        || body.password.len() > MAX_PASSWORD
        || body.display_name.as_ref().is_some_and(|n| n.len() > MAX_DISPLAY_NAME)
        || body.roles.iter().any(|r| r.len() > MAX_ROLE)
    {
        return Err(crate::helpers::api_error(StatusCode::BAD_REQUEST, "invalid_request", "Field too long"));
    }

    let email = gtid_shared::email::normalize_email(&body.email);
    if email.is_empty() || !email.contains('@') {
        return Err(crate::helpers::api_error(StatusCode::BAD_REQUEST, "invalid_request", "Invalid email"));
    }

    if let Err(e) = password::validate_password_strength(&body.password) {
        let t = state.locales.get(&lang.tag);
        let msg = t.password_msg(e);
        return Err(crate::helpers::api_error(StatusCode::BAD_REQUEST, "invalid_request", msg));
    }

    if body.roles.is_empty() {
        return Err(crate::helpers::api_error(StatusCode::BAD_REQUEST, "invalid_request", "At least one role is required"));
    }

    let allowed_roles: HashSet<&str> =
        state.config.roles.iter().map(|r| r.as_str()).collect();
    for role in &body.roles {
        if !allowed_roles.contains(role.as_str()) {
            return Err(crate::helpers::api_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("Invalid role: {}", role),
            ));
        }
    }

    if state
        .users
        .find_by_email(&email)
        .await
        .map_err(|_| crate::helpers::api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Database error"))?
        .is_some()
    {
        return Err(crate::helpers::api_error(StatusCode::CONFLICT, "invalid_request", "Email already exists"));
    }

    let id = gtid_shared::crypto::id::new_id();
    let hash = password::hash_password(&body.password).map_err(|_| {
        crate::helpers::api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Password hashing failed")
    })?;
    let roles_str = body.roles.join(",");

    state
        .users
        .create(&id, &email, &hash, body.display_name.as_deref(), &roles_str, body.is_confirmed)
        .await
        .map_err(|_| crate::helpers::api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Database error"))?;

    tracing::info!(
        event = "user_created_api",
        user_id = %id,
        email = %email,
        roles = %roles_str,
        is_confirmed = body.is_confirmed,
        "User created via API"
    );

    if !body.is_confirmed {
        gtid_shared::email::enqueue_confirmation_email(&state, &id, &email, body.display_name.as_deref(), &lang.tag).await;
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}
