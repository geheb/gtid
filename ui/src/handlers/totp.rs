use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use tera::Context;

use crate::AppState;
use gtid_shared::datetime::SqliteDateTimeExt;
use gtid_shared::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use gtid_shared::middleware::language::Lang;
use crate::ctx::{BaseCtx, TotpSetupCtx, TotpVerifyCtx};
use gtid_shared::crypto::totp;

use crate::middleware::{SESSION_ID_COOKIE_NAME, TRUST_DEVICE_COOKIE_NAME};

use super::{get_field, parse_form_fields, redirect};

/// Validates that a TOTP code is exactly 6 ASCII digits.
fn is_valid_totp_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

use super::{MAX_CSRF_TOKEN, MAX_UUID};

#[derive(Deserialize)]
pub struct PendingQuery {
    #[serde(default)]
    pub p: Option<String>,
}

// ── GET /2fa/setup?p=<id> ───────────────────────────────────────────────────

pub async fn totp_setup_form(
    State(state): State<Arc<AppState>>,
    csrf: CsrfToken,
    lang: Lang,
    Query(query): Query<PendingQuery>,
) -> Result<Response, AppError> {
    let pending_id = query.p.as_deref().unwrap_or("");
    let t = state.locales.get(&lang.tag);

    let entry = match state.pending_2fa.get(pending_id) {
        Some(e) => e,
        None => {
            let ctx = Context::from_serialize(TotpSetupCtx {
                base: BaseCtx {
                    t,
                    lang: &lang.tag,
                    css_hash: &state.css_hash,
                    js_hash: &state.js_hash,
                },
                csrf_token: "",
                qr_data_uri: "",
                secret_display: "",
                pending_id: "",
                error: true,
                error_message: &t.totp_setup_error_expired,
            })?;
            let rendered = state.tera.render("totp_setup.html", &ctx)?;
            return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
        }
    };

    let user_id = entry.user_id.clone();
    let secret = match &entry.totp_secret {
        Some(s) => s.clone(),
        None => {
            let s = totp::generate_secret();
            drop(entry); // release borrow before mutating
            state.pending_2fa.set_totp_secret(pending_id, s.clone());
            s
        }
    };

    let user = state
        .users
        .find_by_id(&user_id)
        .await?
        .ok_or_else(|| AppError::Internal("pending 2fa user not found".into()))?;

    let issuer = &state.config.public_ui_uri;
    let totp = totp::build_totp(&secret, &user.email, issuer).map_err(AppError::Internal)?;
    let qr_data_uri = totp::generate_qr_data_uri(&totp).map_err(AppError::Internal)?;
    let secret_display = totp::format_secret_for_display(&secret);

    let ctx = Context::from_serialize(TotpSetupCtx {
        base: BaseCtx {
            t,
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        csrf_token: &csrf.form_token,
        qr_data_uri: &qr_data_uri,
        secret_display: &secret_display,
        pending_id,
        error: false,
        error_message: "",
    })?;
    let rendered = state.tera.render("totp_setup.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

// ── POST /2fa/setup ─────────────────────────────────────────────────────────

pub async fn totp_setup_submit(
    State(state): State<Arc<AppState>>,
    cookies: tower_cookies::Cookies,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let pending_id = get_field(&fields, "p");
    let code = get_field(&fields, "code");

    validate_totp_fields(&csrf_token, &pending_id).map_err(|e| AppError::BadRequest(e.into()))?;

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(AppError::BadRequest)?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let t = state.locales.get(&lang.tag);

    // Look up pending entry early so we can re-render the form on any error
    let entry = match state.pending_2fa.get(&pending_id) {
        Some(e) => e,
        None => return Err(AppError::BadRequest(t.totp_setup_error_expired.clone())),
    };

    let secret = match &entry.totp_secret {
        Some(s) => s.clone(),
        None => return Err(AppError::BadRequest(t.totp_setup_error_expired.clone())),
    };

    let user_id = entry.user_id.clone();
    let rid = entry.rid.clone();
    drop(entry); // release borrow

    let user = state
        .users
        .find_by_id(&user_id)
        .await?
        .ok_or_else(|| AppError::Internal("pending 2fa user not found".into()))?;

    let issuer = &state.config.public_ui_uri;
    let totp = totp::build_totp(&secret, &user.email, issuer).map_err(AppError::Internal)?;

    // Helper: re-render setup form with error message
    let render_setup_error = |state: &AppState,
                              cookies: &tower_cookies::Cookies,
                              totp: &totp_rs::TOTP,
                              secret: &str,
                              pending_id: &str,
                              t: &gtid_shared::i18n::I18n,
                              lang: &str,
                              error_message: &str|
     -> Result<Response, AppError> {
        let qr_data_uri = totp::generate_qr_data_uri(totp).map_err(AppError::Internal)?;
        let secret_display = totp::format_secret_for_display(secret);
        let csrf_form_token = csrf::set_new_csrf_cookie(cookies, state.config.secure_cookies);
        let ctx = Context::from_serialize(TotpSetupCtx {
            base: BaseCtx {
                t,
                lang,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            csrf_token: &csrf_form_token,
            qr_data_uri: &qr_data_uri,
            secret_display: &secret_display,
            pending_id,
            error: true,
            error_message,
        })?;
        let rendered = state.tera.render("totp_setup.html", &ctx)?;
        Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
    };

    if !is_valid_totp_code(&code) {
        return render_setup_error(
            &state,
            &cookies,
            &totp,
            &secret,
            &pending_id,
            t,
            &lang.tag,
            &t.totp_setup_error_invalid_code,
        );
    }

    // Rate limiting (shared with login/2fa-verify)
    let rl_key = state.login_rate_limiter.key("2fa-setup", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return render_setup_error(
            &state,
            &cookies,
            &totp,
            &secret,
            &pending_id,
            t,
            &lang.tag,
            &t.login_error_rate_limited,
        );
    }

    // Replay prevention: reject codes already used in this pending session
    if state.pending_2fa.is_code_used(&pending_id, &code) {
        return render_setup_error(
            &state,
            &cookies,
            &totp,
            &secret,
            &pending_id,
            t,
            &lang.tag,
            &t.totp_setup_error_invalid_code,
        );
    }

    if !totp::verify_code(&totp, &code) {
        state.login_rate_limiter.record_failure(rl_key);
        state.pending_2fa.mark_code_used(&pending_id, &code);
        tracing::warn!(event = "2fa_setup_failed", user_id = %user_id, ip = %ip, "Failed 2FA setup code verification");
        return render_setup_error(
            &state,
            &cookies,
            &totp,
            &secret,
            &pending_id,
            t,
            &lang.tag,
            &t.totp_setup_error_invalid_code,
        );
    }

    // Mark valid code as used before consuming the entry
    state.pending_2fa.mark_code_used(&pending_id, &code);

    // Success - clear rate limit, encrypt and store secret
    state.login_rate_limiter.clear(rl_key);

    let user_key =
        totp::derive_user_key(&state.config.totp_encryption_key, &user_id).map_err(AppError::Internal)?;
    let encrypted = totp::encrypt_secret(&secret, &user_key).map_err(AppError::Internal)?;
    state.users.set_totp_secret(&user_id, Some(&encrypted)).await?;

    // Consume the pending entry
    state.pending_2fa.take(&pending_id);

    tracing::info!(event = "totp_setup_complete", user_id = %user_id, "2FA setup completed");

    // Redirect: resume OIDC flow if rid present, otherwise login
    let redirect_to = match rid {
        Some(ref rid) if !rid.is_empty() => match state.pending_redirects.take(rid) {
            Some(url) => url,
            None => "/login".into(),
        },
        _ => "/login".into(),
    };

    Ok(redirect(&redirect_to))
}

// ── GET /2fa/verify?p=<id> ──────────────────────────────────────────────────

pub async fn totp_verify_form(
    State(state): State<Arc<AppState>>,
    csrf: CsrfToken,
    lang: Lang,
    Query(query): Query<PendingQuery>,
) -> Result<Response, AppError> {
    let pending_id = query.p.as_deref().unwrap_or("");
    let t = state.locales.get(&lang.tag);

    if state.pending_2fa.get(pending_id).is_none() {
        let ctx = Context::from_serialize(TotpVerifyCtx {
            base: BaseCtx {
                t,
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            csrf_token: "",
            pending_id: "",
            error: true,
            error_message: &t.totp_verify_error_expired,
        })?;
        let rendered = state.tera.render("totp_verify.html", &ctx)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    let ctx = Context::from_serialize(TotpVerifyCtx {
        base: BaseCtx {
            t,
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        csrf_token: &csrf.form_token,
        pending_id,
        error: false,
        error_message: "",
    })?;
    let rendered = state.tera.render("totp_verify.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

// ── POST /2fa/verify ────────────────────────────────────────────────────────

pub async fn totp_verify_submit(
    State(state): State<Arc<AppState>>,
    cookies: tower_cookies::Cookies,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let pending_id = get_field(&fields, "p");
    let code = get_field(&fields, "code");
    let trust_device = get_field(&fields, "trust_device") == "1";

    validate_totp_fields(&csrf_token, &pending_id).map_err(|e| AppError::BadRequest(e.into()))?;

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(AppError::BadRequest)?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let t = state.locales.get(&lang.tag);

    // Helper: re-render verify form with error message
    let render_verify_error = |state: &AppState,
                               cookies: &tower_cookies::Cookies,
                               pending_id: &str,
                               t: &gtid_shared::i18n::I18n,
                               lang: &str,
                               error_message: &str|
     -> Result<Response, AppError> {
        let csrf_form_token = csrf::set_new_csrf_cookie(cookies, state.config.secure_cookies);
        let ctx = Context::from_serialize(TotpVerifyCtx {
            base: BaseCtx {
                t,
                lang,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            csrf_token: &csrf_form_token,
            pending_id,
            error: true,
            error_message,
        })?;
        let rendered = state.tera.render("totp_verify.html", &ctx)?;
        Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
    };

    if !is_valid_totp_code(&code) {
        return render_verify_error(
            &state,
            &cookies,
            &pending_id,
            t,
            &lang.tag,
            &t.totp_verify_error_invalid_code,
        );
    }

    // Rate limiting
    let rl_key = state.login_rate_limiter.key("2fa", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return render_verify_error(&state, &cookies, &pending_id, t, &lang.tag, &t.login_error_rate_limited);
    }

    // Look up pending entry
    let entry = match state.pending_2fa.get(&pending_id) {
        Some(e) => e,
        None => return Err(AppError::BadRequest(t.totp_verify_error_expired.clone())),
    };

    let user_id = entry.user_id.clone();
    let rid = entry.rid.clone();
    drop(entry);

    // Account lockout check
    if state.account_lockout.is_locked(&user_id) {
        return render_verify_error(
            &state,
            &cookies,
            &pending_id,
            t,
            &lang.tag,
            &t.login_error_account_locked,
        );
    }

    let user = state
        .users
        .find_by_id(&user_id)
        .await?
        .ok_or_else(|| AppError::Internal("pending 2fa user not found".into()))?;

    let encrypted_secret = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::Internal("user has no totp secret".into()))?;

    let user_key =
        totp::derive_user_key(&state.config.totp_encryption_key, &user_id).map_err(AppError::Internal)?;
    let secret = totp::decrypt_secret(encrypted_secret, &user_key)
        .map_err(|e| AppError::Internal(format!("totp decrypt: {e}")))?;

    let issuer = &state.config.public_ui_uri;
    let totp = totp::build_totp(&secret, &user.email, issuer).map_err(AppError::Internal)?;

    // Replay prevention: reject codes already used in this pending session
    if state.pending_2fa.is_code_used(&pending_id, &code) {
        return render_verify_error(
            &state,
            &cookies,
            &pending_id,
            t,
            &lang.tag,
            &t.totp_verify_error_invalid_code,
        );
    }

    if !totp::verify_code(&totp, &code) {
        state.login_rate_limiter.record_failure(rl_key);
        state.account_lockout.record_failure(&user_id);
        state.pending_2fa.mark_code_used(&pending_id, &code);
        tracing::warn!(event = "2fa_verify_failed", user_id = %user_id, ip = %ip, "Failed 2FA verification");
        return render_verify_error(
            &state,
            &cookies,
            &pending_id,
            t,
            &lang.tag,
            &t.totp_verify_error_invalid_code,
        );
    }

    // Mark valid code as used (entry is consumed next, but defense-in-depth)
    state.pending_2fa.mark_code_used(&pending_id, &code);

    // Success - clear rate limit/lockout, consume entry, create session
    state.login_rate_limiter.clear(rl_key);
    state.account_lockout.clear(&user_id);
    state.pending_2fa.take(&pending_id);

    // Session fixation prevention
    state.sessions.delete_by_user_id(&user_id).await?;

    let session_id = gtid_shared::crypto::id::new_id();
    let lifetime = state.config.session_lifetime_secs;
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(lifetime))
        .ok_or_else(|| AppError::Internal("session expiry overflow".into()))?
        .to_sqlite();

    state.sessions.create(&session_id, &user_id, &expires_at).await?;

    let mut builder = tower_cookies::Cookie::build((SESSION_ID_COOKIE_NAME, session_id))
        .http_only(true)
        .same_site(tower_cookies::cookie::SameSite::Strict)
        .path("/")
        .max_age(tower_cookies::cookie::time::Duration::seconds(lifetime));
    if state.config.secure_cookies {
        builder = builder.secure(true);
    }
    cookies.add(builder.build());

    if trust_device {
        let trust_lifetime = state.config.trust_device_lifetime_secs;
        let trust_expires = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(trust_lifetime))
            .ok_or_else(|| AppError::Internal("trust expiry overflow".into()))?
            .to_sqlite();
        let trust_token = state.trusted_devices.create(&user_id, &trust_expires).await?;

        let mut trust_builder = tower_cookies::Cookie::build((TRUST_DEVICE_COOKIE_NAME, trust_token))
            .http_only(true)
            .same_site(tower_cookies::cookie::SameSite::Strict)
            .path("/")
            .max_age(tower_cookies::cookie::time::Duration::seconds(trust_lifetime));
        if state.config.secure_cookies {
            trust_builder = trust_builder.secure(true);
        }
        cookies.add(trust_builder.build());
    }

    tracing::info!(event = "2fa_verify_success", user_id = %user_id, "2FA verification successful");

    // Redirect: resume OIDC flow if rid present, otherwise role-based default
    let default_redirect = if user.is_admin() { "/admin" } else { "/profile" };
    let redirect_to = match rid {
        Some(ref rid) if !rid.is_empty() => match state.pending_redirects.take(rid) {
            Some(url) => url,
            None => default_redirect.into(),
        },
        _ => default_redirect.into(),
    };

    Ok(redirect(&redirect_to))
}

fn validate_totp_fields(csrf_token: &str, pending_id: &str) -> Result<(), &'static str> {
    if csrf_token.len() > MAX_CSRF_TOKEN || pending_id.len() > MAX_UUID {
        return Err("invalid request");
    }
    Ok(())
}
