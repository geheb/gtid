use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tera::Context;
use tower_cookies::Cookies;

use crate::AppState;
use gtid_shared::crypto::password;
use gtid_shared::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use gtid_shared::middleware::language::Lang;
use crate::ctx::{
    BaseCtx, ErrorCtx, ForgotPasswordCtx, ForgotPasswordSentCtx, ResetPasswordCtx, ResetPasswordSuccessCtx,
};

use super::{get_field, parse_form_fields, validate_password};

// ── GET /forgot-password ─────────────────────────────────────────────────────

pub async fn forgot_password_form(
    State(state): State<Arc<AppState>>,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let t = state.locales.get(&lang.tag);
    let ctx = Context::from_serialize(ForgotPasswordCtx {
        base: BaseCtx {
            t,
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        csrf_token: &csrf.form_token,
        error: false,
        error_message: "",
        form_email: "",
    })?;
    let rendered = state.tera.render("forgot_password.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

// ── POST /forgot-password ────────────────────────────────────────────────────

pub async fn forgot_password_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let email = super::normalize_email(&get_field(&fields, "email"));

    validate_forgot_fields(&csrf_token, &email).map_err(|e| AppError::BadRequest(e.into()))?;

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(AppError::BadRequest)?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("forgot", &ip, ua);

    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, endpoint = "forgot_password", "Forgot password rate limited");
        let t = state.locales.get(&lang.tag);
        let ctx = Context::from_serialize(ErrorCtx {
            base: BaseCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            error_message: &t.login_error_rate_limited,
        })?;
        let rendered = state.tera.render("error.html", &ctx)?;
        return Ok((StatusCode::TOO_MANY_REQUESTS, Html(rendered)).into_response());
    }

    let render_sent = || -> Result<Response, AppError> {
        let t = state.locales.get(&lang.tag);
        let ctx = Context::from_serialize(ForgotPasswordSentCtx {
            base: BaseCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
        })?;
        let rendered = state.tera.render("forgot_password_sent.html", &ctx)?;
        Ok(Html(rendered).into_response())
    };

    let user = state.users.find_by_email(&email).await?;

    match user {
        Some(user) if user.is_confirmed => {
            // Valid user — create token and send email
            let expiry_hours = state.config.password_reset_token_expiry_hours;
            let expires_at = match chrono::Utc::now().checked_add_signed(chrono::Duration::hours(expiry_hours as i64)) {
                Some(t) => {
                    use gtid_shared::datetime::SqliteDateTimeExt;
                    t.to_sqlite()
                }
                None => return render_sent(),
            };

            if let Err(e) = state.password_reset_tokens.delete_by_user_id(&user.id).await {
                tracing::error!("Failed to delete old password reset tokens: {e}");
            }
            let token = match state.password_reset_tokens.create(&user.id, &expires_at).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(event = "reset_token_failed", error = %e, "Failed to create password reset token");
                    return render_sent();
                }
            };

            let link = format!("{}/reset-password?token={}", state.config.public_ui_uri, token);
            let name = user.display_name.as_deref().unwrap_or(&user.email);

            let template = state
                .email_templates
                .find_by_type_and_lang("reset_password", &lang.tag)
                .await
                .ok()
                .flatten();

            let t = state.locales.get(&lang.tag);
            let (subject, body_html) = super::render_email_template(
                template.as_ref(),
                name,
                &link,
                &t.email_default_reset_password_subject,
                &t.email_default_reset_password_body,
            );

            if let Err(e) = state.email_queue.enqueue(&user.email, &subject, &body_html).await {
                tracing::error!(event = "reset_email_failed", error = %e, "Failed to enqueue password reset email");
            }

            tracing::info!(event = "password_reset_requested", user_id = %user.id, "Password reset email enqueued");
        }
        _ => {
            // User not found or not confirmed — timing attack prevention
            password::dummy_verify("timing_equalization");
            state.login_rate_limiter.record_failure(rl_key);
            tracing::info!(event = "forgot_password_no_user", email = %email, "Password reset requested for non-existent/unconfirmed email");
        }
    }

    render_sent()
}

// ── GET /reset-password?token=xxx ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ResetQuery {
    #[serde(default)]
    pub token: String,
}

pub async fn reset_password_form(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ResetQuery>,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(AppError::BadRequest)?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("reset", &ip, ua);

    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, endpoint = "reset_password", "Reset password rate limited");
        let t = state.locales.get(&lang.tag);
        let ctx = Context::from_serialize(ErrorCtx {
            base: BaseCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            error_message: &t.login_error_rate_limited,
        })?;
        let rendered = state.tera.render("error.html", &ctx)?;
        return Ok((StatusCode::TOO_MANY_REQUESTS, Html(rendered)).into_response());
    }

    let reset_token = state.password_reset_tokens.find_valid(&query.token).await?;

    if reset_token.is_none() {
        state.login_rate_limiter.record_failure(rl_key);
        tracing::warn!(event = "reset_token_invalid", ip = %ip, "Invalid or expired password reset token");
        let t = state.locales.get(&lang.tag);
        let ctx = Context::from_serialize(ErrorCtx {
            base: BaseCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            error_message: &t.reset_password_invalid_token,
        })?;
        let rendered = state.tera.render("error.html", &ctx)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    let t = state.locales.get(&lang.tag);
    let ctx = Context::from_serialize(ResetPasswordCtx {
        base: BaseCtx {
            t,
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        csrf_token: &csrf.form_token,
        token: &query.token,
        error: false,
        error_message: "",
    })?;
    let rendered = state.tera.render("reset_password.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

// ── POST /reset-password ─────────────────────────────────────────────────────

pub async fn reset_password_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let token = get_field(&fields, "token");
    let pw = get_field(&fields, "password");
    let pw_confirm = get_field(&fields, "password_confirm");

    validate_reset_fields(&csrf_token, &token, &pw, &pw_confirm).map_err(|e| AppError::BadRequest(e.into()))?;

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(AppError::BadRequest)?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("reset", &ip, ua);

    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, endpoint = "reset_password_submit", "Reset password submit rate limited");
        let t = state.locales.get(&lang.tag);
        let ctx = Context::from_serialize(ErrorCtx {
            base: BaseCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            error_message: &t.login_error_rate_limited,
        })?;
        let rendered = state.tera.render("error.html", &ctx)?;
        return Ok((StatusCode::TOO_MANY_REQUESTS, Html(rendered)).into_response());
    }

    let reset_token = state.password_reset_tokens.find_valid(&token).await?;

    let reset_token = match reset_token {
        Some(rt) => rt,
        None => {
            state.login_rate_limiter.record_failure(rl_key);
            tracing::warn!(event = "reset_token_invalid", ip = %ip, "Invalid or expired password reset token on submit");
            let t = state.locales.get(&lang.tag);
            let ctx = Context::from_serialize(ErrorCtx {
                base: BaseCtx {
                    t,
                    lang: &lang.tag,
                    css_hash: &state.css_hash,
                    js_hash: &state.js_hash,
                },
                error_message: &t.reset_password_invalid_token,
            })?;
            let rendered = state.tera.render("error.html", &ctx)?;
            return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
        }
    };

    let render_form_error = |msg: &str| -> Result<Response, AppError> {
        let t = state.locales.get(&lang.tag);
        let ctx = Context::from_serialize(ResetPasswordCtx {
            base: BaseCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            csrf_token: &csrf_token,
            token: &token,
            error: true,
            error_message: msg,
        })?;
        let rendered = state.tera.render("reset_password.html", &ctx)?;
        Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
    };

    if pw != pw_confirm {
        let t = state.locales.get(&lang.tag);
        return render_form_error(&t.reset_password_error_mismatch);
    }

    if let Err(msg) = validate_password(&pw, state.locales.get(&lang.tag)) {
        return render_form_error(&msg);
    }

    let hash = password::hash_password(&pw)?;
    state.users.update_password(&reset_token.user_id, &hash).await?;

    // Single-use: delete all reset tokens for this user
    state
        .password_reset_tokens
        .delete_by_user_id(&reset_token.user_id)
        .await?;

    // Invalidate all sessions (force re-login on all devices)
    state.sessions.delete_by_user_id(&reset_token.user_id).await?;

    state.login_rate_limiter.clear(rl_key);

    tracing::info!(
        event = "password_reset_completed",
        user_id = %reset_token.user_id,
        "Password reset completed, all sessions invalidated"
    );

    let t = state.locales.get(&lang.tag);
    let ctx = Context::from_serialize(ResetPasswordSuccessCtx {
        base: BaseCtx {
            t,
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
    })?;
    let rendered = state.tera.render("reset_password_success.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

fn validate_forgot_fields(csrf_token: &str, email: &str) -> Result<(), &'static str> {
    if csrf_token.len() > super::MAX_CSRF_TOKEN || email.len() > super::MAX_EMAIL {
        return Err("invalid request");
    }
    Ok(())
}

fn validate_reset_fields(
    csrf_token: &str,
    token: &str,
    password: &str,
    password_confirm: &str,
) -> Result<(), &'static str> {
    if csrf_token.len() > super::MAX_CSRF_TOKEN
        || token.len() > super::MAX_RESET_TOKEN
        || password.len() > super::MAX_PASSWORD
        || password_confirm.len() > super::MAX_PASSWORD
    {
        return Err("invalid request");
    }
    Ok(())
}
