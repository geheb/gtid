use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tera::Context;

use crate::{errors::AppError, routes::ui::anonymize_email};
use crate::middleware::language::Lang;
use crate::routes::ctx::{ConfirmEmailChangeSuccessCtx, ErrorCtx};
use crate::AppState;

#[derive(Deserialize)]
pub struct ConfirmQuery {
    #[serde(default)]
    pub token: String,
}

pub async fn confirm_email_change(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ConfirmQuery>,
    lang: Lang,
) -> Result<Response, AppError> {
    let ua = crate::routes::require_user_agent(&headers)
        .map_err(|e| AppError::BadRequest(e))?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("email_change", &ip, ua);

    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, endpoint = "confirm_email_change", "Email change confirmation rate limited");
        let t = state.locales.get(&lang.tag);
        let ctx = Context::from_serialize(ErrorCtx {
            t,
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
            error_message: &t.login_error_rate_limited,
        })?;
        let rendered = state.tera.render("error.html", &ctx)?;
        return Ok((StatusCode::TOO_MANY_REQUESTS, Html(rendered)).into_response());
    }

    let change = state.email_changes.find_valid(&query.token).await?;

    let change = match change {
        Some(c) => c,
        None => {
            state.login_rate_limiter.record_failure(rl_key);
            tracing::warn!(event = "email_change_invalid", ip = %ip, "Invalid or expired email change token");
            let t = state.locales.get(&lang.tag);
            let ctx = Context::from_serialize(ErrorCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
                error_message: &t.confirm_email_change_invalid,
            })?;
            let rendered = state.tera.render("error.html", &ctx)?;
            return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
        }
    };

    // Race condition guard: check new email is still available
    if state.users.find_by_email(&change.new_email).await?.is_some() {
        state.email_changes.delete_by_user_id(&change.user_id).await?;
        let t = state.locales.get(&lang.tag);
        let ctx = Context::from_serialize(ErrorCtx {
            t,
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
            error_message: &t.profile_change_email_error_taken,
        })?;
        let rendered = state.tera.render("error.html", &ctx)?;
        return Ok((StatusCode::CONFLICT, Html(rendered)).into_response());
    }

    state.users.update_email(&change.user_id, &change.new_email).await?;
    state.email_changes.delete_by_user_id(&change.user_id).await?;

    // Invalidate all sessions — force re-login
    state.sessions.delete_by_user_id(&change.user_id).await?;

    state.login_rate_limiter.clear(rl_key);
    tracing::info!(event = "email_changed", user_id = %change.user_id, new_email = %change.new_email, "User email changed via confirmation token");

    let anonymized = anonymize_email(&change.new_email);

    let ctx = Context::from_serialize(ConfirmEmailChangeSuccessCtx {
        t: state.locales.get(&lang.tag),
        lang: &lang.tag,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        anonymized_email: &anonymized,
    })?;
    let rendered = state.tera.render("confirm_email_change_success.html", &ctx)?;
    Ok(Html(rendered).into_response())
}
