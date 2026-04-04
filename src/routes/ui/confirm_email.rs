use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tera::Context;

use crate::errors::AppError;
use crate::middleware::language::Lang;
use crate::routes::ctx::{ConfirmEmailSuccessCtx, ErrorCtx};
use crate::AppState;

#[derive(Deserialize)]
pub struct ConfirmQuery {
    #[serde(default)]
    pub token: String,
}

pub async fn confirm_email(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ConfirmQuery>,
    lang: Lang,
) -> Result<Response, AppError> {
    let ua = crate::routes::require_user_agent(&headers)
        .map_err(|e| AppError::BadRequest(e))?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("confirm", &ip, ua);

    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, endpoint = "confirm_email", "Confirm email rate limited");
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

    let confirmation = state.confirmation_tokens.find_valid(&query.token).await?;

    let confirmation = match confirmation {
        Some(c) => c,
        None => {
            state.login_rate_limiter.record_failure(rl_key);
            tracing::warn!(event = "confirm_invalid", ip = %ip, "Invalid or expired confirmation token");
            let t = state.locales.get(&lang.tag);
            let ctx = Context::from_serialize(ErrorCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
                error_message: &t.confirm_email_invalid,
            })?;
            let rendered = state.tera.render("error.html", &ctx)?;
            return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
        }
    };

    let user = state.users.find_by_id(&confirmation.user_id).await?
        .ok_or_else(|| AppError::Internal("User not found".into()))?;

    state.users.confirm(&confirmation.user_id).await?;
    state.confirmation_tokens.delete_for_user(&confirmation.user_id).await?;
    state.login_rate_limiter.clear(rl_key);
    tracing::info!(event = "email_confirmed", user_id = %confirmation.user_id, "Email confirmed via token");

    let anonymized = anonymize_email(&user.email);
    let ctx = Context::from_serialize(ConfirmEmailSuccessCtx {
        t: state.locales.get(&lang.tag),
        lang: &lang.tag,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        anonymized_email: &anonymized,
    })?;
    let rendered = state.tera.render("confirm_email_success.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

/// Anonymize an email address: `thomas@example.com` → `t...s@example.com`
fn anonymize_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "***".to_string();
    };
    let masked = match local.len() {
        0 => "***".to_string(),
        1 => format!("{}...", &local[..1]),
        _ => format!("{}...{}", &local[..1], &local[local.len() - 1..]),
    };
    format!("{masked}@{domain}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymize() {
        assert_eq!(anonymize_email("thomas@example.com"), "t...s@example.com");
        assert_eq!(anonymize_email("ab@test.de"), "a...b@test.de");
        assert_eq!(anonymize_email("a@test.de"), "a...@test.de");
        assert_eq!(anonymize_email("invalid"), "***");
    }
}
