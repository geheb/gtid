use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tera::Context;
use tower_cookies::cookie::SameSite;
use tower_cookies::cookie::time::Duration;
use tower_cookies::{Cookie, Cookies};

use crate::AppState;
use gtid_shared::datetime::SqliteDateTimeExt;
use gtid_shared::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use gtid_shared::middleware::language::Lang;
use crate::middleware::session::{OptionalSessionUser, SessionUser};
use gtid_shared::oauth::urlencoding;
use crate::ctx::{BaseCtx, LoginCtx};
use crate::handlers::redirect;
use gtid_shared::crypto::{jwt, password};

use crate::middleware::{SESSION_ID_COOKIE_NAME, TRUST_DEVICE_COOKIE_NAME};

#[derive(Deserialize)]
pub struct RpLogoutQuery {
    #[serde(default)]
    pub id_token_hint: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

pub async fn rp_initiated_logout(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    optional_user: OptionalSessionUser,
    Query(query): Query<RpLogoutQuery>,
) -> Result<Response, AppError> {
    // Validate id_token_hint if provided - decode without audience to extract client_id
    let hint_client_id = if let Some(ref hint) = query.id_token_hint {
        // Reject oversized tokens to prevent DoS
        if hint.len() > 2048 {
            return Err(AppError::BadRequest("id_token_hint too large".into()));
        }
        let decoding_keys = state.key_store.decoding_keys();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&[&state.config.issuer_uri]);
        validation.validate_aud = false; // we validate aud against DB below
        let mut decoded_aud = None;
        for key in &decoding_keys {
            if let Ok(token_data) = jsonwebtoken::decode::<jwt::IdTokenClaims>(hint, key, &validation) {
                decoded_aud = Some(token_data.claims.aud);
                break;
            }
        }
        let aud = decoded_aud.ok_or_else(|| AppError::BadRequest("Invalid id_token_hint".into()))?;
        // Verify the client exists in DB
        state
            .clients
            .find_by_id(&aud)
            .await
            .map_err(|_| AppError::Internal("Database error".into()))?
            .ok_or_else(|| AppError::BadRequest("Invalid id_token_hint".into()))?;
        Some(aud)
    } else {
        None
    };

    // Validate post_logout_redirect_uri - requires id_token_hint for client identification
    let redirect_to = if let Some(ref uri) = query.post_logout_redirect_uri {
        let client_id = hint_client_id.as_deref().ok_or_else(|| {
            AppError::BadRequest("id_token_hint required when post_logout_redirect_uri is provided".into())
        })?;
        let client = state
            .clients
            .find_by_id(client_id)
            .await
            .map_err(|_| AppError::Internal("Database error".into()))?
            .ok_or_else(|| AppError::BadRequest("Invalid post_logout_redirect_uri".into()))?;
        let uri_valid = gtid_shared::crypto::constant_time::constant_time_str_eq(uri, &client.client_redirect_uri)
            || client
                .client_post_logout_redirect_uri
                .as_ref()
                .map(|allowed| gtid_shared::crypto::constant_time::constant_time_str_eq(uri, allowed))
                .unwrap_or(false);
        if !uri_valid {
            return Err(AppError::BadRequest("Invalid post_logout_redirect_uri".into()));
        }
        let mut url = uri.clone();
        if let Some(ref s) = query.state {
            if s.len() > 1024 {
                return Err(AppError::BadRequest("state parameter too long".into()));
            }
            url.push_str(&format!("?state={}", urlencoding(s)));
        }
        url
    } else {
        "/login".to_string()
    };

    // End session
    if let Some(user) = optional_user.0 {
        state.sessions.delete_by_user_id(&user.id).await?;
    }
    cookies.remove(Cookie::from(SESSION_ID_COOKIE_NAME));

    Ok(redirect(&redirect_to))
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub rid: Option<String>,
    #[serde(default)]
    pub csrf_token: String,
}

impl LoginForm {
    pub fn validate(&self) -> Result<(), &'static str> {
        use crate::handlers::{MAX_CSRF_TOKEN, MAX_EMAIL, MAX_PASSWORD, MAX_UUID};
        if self.email.len() > MAX_EMAIL
            || self.password.len() > MAX_PASSWORD
            || self.rid.as_ref().is_some_and(|r| r.len() > MAX_UUID)
            || self.csrf_token.len() > MAX_CSRF_TOKEN
        {
            return Err("invalid request");
        }
        Ok(())
    }
}

#[derive(Deserialize, Default)]
pub struct LoginQuery {
    #[serde(default)]
    pub rid: Option<String>,
}

pub async fn login_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
    optional_user: OptionalSessionUser,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    if state.setup_needed.load(Ordering::Acquire) {
        return Ok(redirect("/setup"));
    }

    // Already logged in -> redirect to appropriate page
    if let Some(user) = optional_user.0 {
        let target = if user.is_admin() { "/admin" } else { "/profile" };
        return Ok(redirect(target));
    }

    let rid = match query.rid.as_deref() {
        Some(r) if r.len() <= crate::handlers::MAX_UUID => r,
        _ => "",
    };
    let ctx = Context::from_serialize(LoginCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        error: false,
        error_message: "",
        rid,
        csrf_token: &csrf.form_token,
        form_email: "",
        show_imprint: has_legal_content(&state, "imprint").await,
        show_privacy: has_legal_content(&state, "privacy").await,
    })?;
    let rendered = state.tera.render("login.html", &ctx)?;

    Ok(Html(rendered).into_response())
}

pub async fn login_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    lang: Lang,
    axum::Form(form): axum::Form<LoginForm>,
) -> Result<Response, AppError> {
    // CSRF verification
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let ua = gtid_shared::routes::require_user_agent(&headers).map_err(AppError::BadRequest)?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    // Generate fresh CSRF token for error pages
    let csrf_form_token = csrf::set_new_csrf_cookie(&cookies, state.config.secure_cookies);

    form.validate().map_err(|e| AppError::BadRequest(e.into()))?;

    let rl_key = state.login_rate_limiter.key("login", &ip, ua);
    let rid = form.rid.as_deref().unwrap_or("");
    let email = crate::handlers::normalize_email(&form.email);
    let t = state.locales.get(&lang.tag);

    let show_imprint = has_legal_content(&state, "imprint").await;
    let show_privacy = has_legal_content(&state, "privacy").await;

    let render_login_error =
        |msg: &str, status: StatusCode, rid: &str, csrf: &str, email: &str| -> Result<Response, AppError> {
            let ctx = Context::from_serialize(LoginCtx {
                base: BaseCtx {
                    t,
                    lang: &lang.tag,
                    css_hash: &state.css_hash,
                    js_hash: &state.js_hash,
                },
                error: true,
                error_message: msg,
                rid,
                csrf_token: csrf,
                form_email: email,
                show_imprint,
                show_privacy,
            })?;
            let rendered = state.tera.render("login.html", &ctx)?;
            Ok((status, Html(rendered)).into_response())
        };

    // Check rate limit (IP + User-Agent)
    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, email = %email, "Login rate limited");
        return render_login_error(
            &t.login_error_rate_limited,
            StatusCode::TOO_MANY_REQUESTS,
            rid,
            &csrf_form_token,
            &email,
        );
    }

    // Check account lockout (per email)
    if state.account_lockout.is_locked(&email) {
        tracing::warn!(event = "account_locked", ip = %ip, email = %email, "Login blocked by account lockout");
        return render_login_error(
            &t.login_error_account_locked,
            StatusCode::FORBIDDEN,
            rid,
            &csrf_form_token,
            &email,
        );
    }

    let user = state.users.find_by_email(&email).await?;

    let user = match &user {
        Some(u) if password::verify_password(&form.password, &u.password_hash) => u.clone(),
        _ => {
            if user.is_none() {
                password::dummy_verify(&form.password);
            }
            tracing::warn!(event = "login_failed", ip = %ip, email = %email, "Failed login attempt");
            state.login_rate_limiter.record_failure(rl_key);
            state.account_lockout.record_failure(&email);
            return render_login_error(
                &t.login_error_invalid,
                StatusCode::UNAUTHORIZED,
                rid,
                &csrf_form_token,
                &email,
            );
        }
    };

    // Block unconfirmed users with same generic error (prevent account enumeration)
    if !user.is_confirmed {
        tracing::warn!(event = "login_unconfirmed", ip = %ip, email = %email, "Login attempt with unconfirmed email");
        return render_login_error(
            &t.login_error_invalid,
            StatusCode::UNAUTHORIZED,
            rid,
            &csrf_form_token,
            &email,
        );
    }

    // Successful login - clear rate limit and lockout, update last login
    state.login_rate_limiter.clear(rl_key);
    state.account_lockout.clear(&email);
    state.users.update_last_login(&user.id).await?;

    // 2FA: all users with TOTP, or forced setup for admins without TOTP
    let needs_2fa = if user.has_totp() {
        match cookies.get(TRUST_DEVICE_COOKIE_NAME).map(|c| c.value().to_string()) {
            Some(token) => state.trusted_devices.find_valid(&token).await?.is_none(),
            None => true,
        }
    } else if user.is_admin() {
        true // admin without TOTP -> forced setup
    } else {
        false // non-admin without TOTP -> no 2FA
    };

    if needs_2fa {
        let rid_for_2fa = form.rid.as_deref().filter(|r| !r.is_empty()).map(String::from);
        let pending_id = state
            .pending_2fa
            .store(user.id.clone(), rid_for_2fa, None)
            .ok_or_else(|| AppError::Internal("pending 2fa store full".into()))?;

        if user.has_totp() {
            return Ok(redirect(&format!("/2fa/verify?p={pending_id}")));
        } else {
            return Ok(redirect(&format!("/2fa/setup?p={pending_id}")));
        }
    }

    // #8: Session fixation prevention - invalidate all existing sessions for this user
    state.sessions.delete_by_user_id(&user.id).await?;

    let session_id = gtid_shared::crypto::id::new_id();
    let lifetime = state.config.session_lifetime_secs;
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(lifetime))
        .ok_or_else(|| AppError::Internal("session expiry overflow".into()))?
        .to_sqlite();

    state.sessions.create(&session_id, &user.id, &expires_at).await?;

    let mut builder = Cookie::build((SESSION_ID_COOKIE_NAME, session_id.clone()))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(lifetime));
    if state.config.secure_cookies {
        builder = builder.secure(true);
    }
    cookies.add(builder.build());

    let redirect_to = match form.rid {
        Some(ref rid) if !rid.is_empty() => {
            match state.pending_redirects.take(rid) {
                Some(url) => url,
                None => {
                    // Expired or invalid rid - destroy the session just created
                    state.sessions.delete(&session_id).await?;
                    cookies.remove(Cookie::from(SESSION_ID_COOKIE_NAME));

                    let csrf_form_token = csrf::set_new_csrf_cookie(&cookies, state.config.secure_cookies);
                    return render_login_error(
                        &t.login_error_session_expired,
                        StatusCode::UNAUTHORIZED,
                        "",
                        &csrf_form_token,
                        &email,
                    );
                }
            }
        }
        _ => {
            if user.is_admin() {
                "/admin".into()
            } else {
                "/profile".into()
            }
        }
    };

    Ok(redirect(&redirect_to))
}

#[derive(Deserialize)]
pub struct LogoutForm {
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<LogoutForm>,
) -> Result<Response, AppError> {
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    state.sessions.delete_by_user_id(&session_user.0.id).await?;

    cookies.remove(Cookie::from(SESSION_ID_COOKIE_NAME));

    Ok(redirect("/login"))
}

async fn has_legal_content(state: &AppState, page_type: &str) -> bool {
    state.legal_pages.has_any_content(page_type).await.unwrap_or(false)
}
