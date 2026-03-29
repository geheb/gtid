use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tera::Context;
use tower_cookies::cookie::time::Duration;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

use crate::crypto::{jwt, password};
use crate::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::session::{OptionalSessionUser, SessionUser};
use crate::routes::ctx::LoginCtx;
use crate::AppState;

/// RP-Initiated Logout per OpenID Connect RP-Initiated Logout 1.0.
/// GET /logout?id_token_hint=...&post_logout_redirect_uri=...&state=...
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
        state.clients.find_by_id(&aud).await
            .map_err(|_| AppError::Internal("Database error".into()))?
            .ok_or_else(|| AppError::BadRequest("Invalid id_token_hint".into()))?;
        Some(aud)
    } else {
        None
    };

    // Validate post_logout_redirect_uri - requires id_token_hint for client identification
    let redirect_to = if let Some(ref uri) = query.post_logout_redirect_uri {
        let client_id = hint_client_id.as_deref()
            .ok_or_else(|| AppError::BadRequest(
                "id_token_hint required when post_logout_redirect_uri is provided".into(),
            ))?;
        let client = state.clients.find_by_id(client_id).await
            .map_err(|_| AppError::Internal("Database error".into()))?
            .ok_or_else(|| AppError::BadRequest("Invalid post_logout_redirect_uri".into()))?;
        let uri_valid = crate::crypto::constant_time::constant_time_str_eq(uri, &client.client_redirect_uri)
            || client.client_post_logout_redirect_uri.as_ref()
                .map(|allowed| crate::crypto::constant_time::constant_time_str_eq(uri, allowed))
                .unwrap_or(false);
        if !uri_valid {
            return Err(AppError::BadRequest("Invalid post_logout_redirect_uri".into()));
        }
        let mut url = uri.clone();
        if let Some(ref s) = query.state {
            if s.len() > 1024 {
                return Err(AppError::BadRequest("state parameter too long".into()));
            }
            url.push_str(&format!("?state={}", crate::routes::urlencoding(s)));
        }
        url
    } else {
        "/login".to_string()
    };

    // End session
    if let Some(user) = optional_user.0 {
        state.sessions.delete_by_user_id(&user.id).await?;
    }
    cookies.remove(Cookie::from("session"));

    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, redirect_to)]).into_response())
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
) -> Result<Response, AppError> {
    // Already logged in → redirect to appropriate page
    if let Some(user) = optional_user.0 {
        let target = if user.is_admin() { "/admin" } else { "/profile" };
        return Ok((StatusCode::SEE_OTHER, [(header::LOCATION, target)]).into_response());
    }

    let rid = query.rid.as_deref().unwrap_or("");
    let ctx = Context::from_serialize(LoginCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        error: false,
        error_message: "",
        rid,
        csrf_token: &csrf.form_token,
        form_email: "",
    })?;
    let rendered = state.tera.render("login.html", &ctx)?;

    Ok(Html(rendered).into_response())
}

pub async fn login_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<LoginForm>,
) -> Result<Response, AppError> {
    // CSRF verification
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    let ua = crate::routes::require_user_agent(&headers)
        .map_err(|e| AppError::BadRequest(e))?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    // Generate fresh CSRF token for error pages
    let csrf_form_token = csrf::set_new_csrf_cookie(&cookies, state.config.secure_cookies);

    let rl_key = state.login_rate_limiter.key("login", &ip, ua);
    let rid = form.rid.as_deref().unwrap_or("");

    let render_login_error =
        |msg: &str, status: StatusCode, rid: &str, csrf: &str, email: &str| -> Result<Response, AppError> {
            let ctx = Context::from_serialize(LoginCtx {
                t: &state.i18n,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
                error: true,
                error_message: msg,
                rid,
                csrf_token: csrf,
                form_email: email,
            })?;
            let rendered = state.tera.render("login.html", &ctx)?;
            Ok((status, Html(rendered)).into_response())
        };

    // Check rate limit (IP + User-Agent)
    if state.login_rate_limiter.is_limited(rl_key) {
        tracing::warn!(event = "rate_limited", ip = %ip, email = %form.email, "Login rate limited");
        return render_login_error(&state.i18n.login_error_rate_limited, StatusCode::TOO_MANY_REQUESTS, rid, &csrf_form_token, &form.email);
    }

    // Check account lockout (per email)
    if state.account_lockout.is_locked(&form.email) {
        tracing::warn!(event = "account_locked", ip = %ip, email = %form.email, "Login blocked by account lockout");
        return render_login_error(&state.i18n.login_error_account_locked, StatusCode::FORBIDDEN, rid, &csrf_form_token, &form.email);
    }

    let user = state.users.find_by_email(&form.email).await?;

    let user = match &user {
        Some(u) if password::verify_password(&form.password, &u.password_hash) => u.clone(),
        _ => {
            if user.is_none() {
                password::dummy_verify(&form.password);
            }
            tracing::warn!(event = "login_failed", ip = %ip, email = %form.email, "Failed login attempt");
            state.login_rate_limiter.record_failure(rl_key);
            state.account_lockout.record_failure(&form.email);
            return render_login_error(&state.i18n.login_error_invalid, StatusCode::UNAUTHORIZED, rid, &csrf_form_token, &form.email);
        }
    };

    // Successful login - clear rate limit and lockout, update last login
    state.login_rate_limiter.clear(rl_key);
    state.account_lockout.clear(&form.email);
    state.users.update_last_login(&user.id).await?;

    // #8: Session fixation prevention - invalidate all existing sessions for this user
    state.sessions.delete_by_user_id(&user.id).await?;

    let session_id = crate::crypto::id::new_id();
    let lifetime = state.config.session_lifetime_secs;
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(lifetime))
        .ok_or_else(|| AppError::Internal("session expiry overflow".into()))?
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    state
        .sessions
        .create(&session_id, &user.id, &expires_at)
        .await?;

    let mut builder = Cookie::build(("session", session_id.clone()))
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
                    cookies.remove(Cookie::from("session"));

                    let csrf_form_token = csrf::set_new_csrf_cookie(&cookies, state.config.secure_cookies);
                    return render_login_error(&state.i18n.login_error_session_expired, StatusCode::UNAUTHORIZED, "", &csrf_form_token, &form.email);
                }
            }
        }
        _ => {
            if user.is_admin() { "/admin".into() } else { "/profile".into() }
        }
    };

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, redirect_to)],
    )
        .into_response())
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
    axum::Form(form): axum::Form<LogoutForm>,
) -> Result<Response, AppError> {
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    state
        .sessions
        .delete_by_user_id(&session_user.0.id)
        .await?;

    cookies.remove(Cookie::from("session"));

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/login")],
    )
        .into_response())
}

