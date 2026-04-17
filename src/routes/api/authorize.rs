use axum::{
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
use crate::crypto::constant_time;
use crate::datetime::SqliteDateTimeExt;
use crate::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::language::Lang;
use crate::middleware::session::OptionalSessionUser;
use crate::entities::client::Client;
use crate::routes::ctx::{AuthorizeCtx, BaseCtx, ErrorCtx};
use crate::routes::ui::redirect;

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

pub async fn authorize_get(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(params): Query<AuthorizeParams>,
    session: OptionalSessionUser,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let ua = crate::routes::require_user_agent(&headers).map_err(AppError::BadRequest)?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("authorize", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return Err(AppError::BadRequest("Too many requests".into()));
    }

    if let Err(e) = validate_authorize_params(&params, &state).await {
        state.login_rate_limiter.record_failure(rl_key);
        return error_response(&state, &e, &lang.tag);
    }

    let user = match session.0 {
        Some(u) => u,
        None => {
            let query = build_query_string(&params);
            let redirect_url = format!("/authorize?{query}");
            let rid = state
                .pending_redirects
                .store(redirect_url)
                .ok_or_else(|| AppError::Internal("Server overloaded, please try again".into()))?;
            let login_url = format!("/login?rid={rid}");
            return Ok(redirect(&login_url));
        }
    };

    // Check if user already granted consent for this client + scope
    let client_id = params.client_id.as_deref().unwrap_or("");
    let scope = params.scope.as_deref().unwrap_or("openid");
    if state.consents.has_grant(&user.id, client_id, scope).await? {
        let code = crate::crypto::id::new_id();
        let code_challenge = params.code_challenge.as_deref().unwrap_or("");
        let redirect_uri = params.redirect_uri.as_deref().unwrap_or("");
        let expires_at = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(60))
            .ok_or_else(|| AppError::Internal("auth code expiry overflow".into()))?
            .to_sqlite();
        state
            .auth_codes
            .create(&crate::entities::authorization_code::NewAuthorizationCode {
                code: &code,
                client_id,
                user_id: &user.id,
                redirect_uri,
                scope,
                code_challenge,
                nonce: params.nonce.as_deref(),
                expires_at: &expires_at,
            })
            .await?;
        let mut redirect_url = format!("{}?code={}", redirect_uri, code);
        if let Some(ref s) = params.state {
            redirect_url.push_str(&format!("&state={}", super::urlencoding(s)));
        }
        return Ok(redirect(&redirect_url));
    }

    // No grant -> render the consent page
    let ctx = Context::from_serialize(AuthorizeCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        csrf_token: &csrf.form_token,
        response_type: params.response_type.as_deref().unwrap_or("code"),
        client_id: params.client_id.as_deref().unwrap_or(""),
        redirect_uri: params.redirect_uri.as_deref().unwrap_or(""),
        scope: params.scope.as_deref().unwrap_or("openid"),
        state: params.state.as_deref(),
        nonce: params.nonce.as_deref(),
        code_challenge: params.code_challenge.as_deref().unwrap_or(""),
        code_challenge_method: params.code_challenge_method.as_deref().unwrap_or("S256"),
        user_email: &user.email,
    })?;
    let rendered = state.tera.render("authorize.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    #[allow(dead_code)]
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub consent: String,
    #[serde(default)]
    pub csrf_token: String,
}

impl ConsentForm {
    pub fn validate(&self) -> Result<(), &'static str> {
        use crate::routes::ui::{MAX_CLIENT_ID, MAX_CSRF_TOKEN, MAX_SCOPE, MAX_URI};
        if self.csrf_token.len() > MAX_CSRF_TOKEN
            || self.client_id.len() > MAX_CLIENT_ID
            || self.redirect_uri.len() > MAX_URI
            || self.scope.as_ref().is_some_and(|s| s.len() > MAX_SCOPE)
            || self.consent.len() > 10
        {
            return Err("invalid request");
        }
        Ok(())
    }
}

pub async fn authorize_post(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    session: crate::middleware::session::SessionUser,
    headers: axum::http::HeaderMap,
    lang: Lang,
    axum::Form(form): axum::Form<ConsentForm>,
) -> Result<Response, AppError> {
    form.validate().map_err(|e| AppError::BadRequest(e.into()))?;

    let ua = crate::routes::require_user_agent(&headers).map_err(AppError::BadRequest)?;
    let ip = crate::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("authorize", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return Err(AppError::BadRequest("Too many requests".into()));
    }

    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        state.login_rate_limiter.record_failure(rl_key);
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    // Validate client_id, redirect_uri, code_challenge_method, and scope BEFORE
    // checking consent - prevents open redirect via the deny path.
    let client = state
        .clients
        .find_by_id(&form.client_id)
        .await
        .map_err(|_| AppError::Internal("Database error".into()))?
        .ok_or_else(|| {
            state.login_rate_limiter.record_failure(rl_key);
            AppError::BadRequest("Invalid client_id or redirect_uri".into())
        })?;
    if !constant_time::constant_time_str_eq(&form.redirect_uri, &client.client_redirect_uri) {
        state.login_rate_limiter.record_failure(rl_key);
        return Err(AppError::BadRequest("Invalid client_id or redirect_uri".into()));
    }
    if form.code_challenge_method != "S256" {
        return Err(AppError::BadRequest("Only S256 code_challenge_method supported".into()));
    }
    if form.code_challenge.len() < 43 || form.code_challenge.len() > 128 {
        return Err(AppError::BadRequest("code_challenge must be 43–128 characters".into()));
    }

    // #11: Nonce required
    if form.nonce.as_ref().is_none_or(|n| n.is_empty()) {
        return Err(AppError::BadRequest("Missing nonce".into()));
    }

    if let Some(ref s) = form.state
        && s.len() > 1024
    {
        return Err(AppError::BadRequest("state parameter too long".into()));
    }

    let scope = form.scope.as_deref().unwrap_or("openid");
    if let Err(msg) = crate::routes::api::validate_scope(scope) {
        return Err(AppError::BadRequest(msg));
    }

    if form.consent != "allow" {
        let state_encoded = form
            .state
            .as_deref()
            .map(super::urlencoding)
            .unwrap_or_default();
        let deny_url = format!("{}?error=access_denied&state={}", form.redirect_uri, state_encoded);
        return Ok(redirect(&deny_url));
    }

    let code = crate::crypto::id::new_id();
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .ok_or_else(|| AppError::Internal("auth code expiry overflow".into()))?
        .to_sqlite();

    state
        .auth_codes
        .create(&crate::entities::authorization_code::NewAuthorizationCode {
            code: &code,
            client_id: &form.client_id,
            user_id: &session.0.id,
            redirect_uri: &form.redirect_uri,
            scope,
            code_challenge: &form.code_challenge,
            nonce: form.nonce.as_deref(),
            expires_at: &expires_at,
        })
        .await?;

    // Persist consent grant
    state.consents.save_grant(&session.0.id, &form.client_id, scope).await?;

    let mut redirect_url = format!("{}?code={}", form.redirect_uri, code);
    if let Some(ref s) = form.state {
        redirect_url.push_str(&format!("&state={}", super::urlencoding(s)));
    }

    Ok(redirect(&redirect_url))
}

async fn validate_authorize_params(params: &AuthorizeParams, state: &AppState) -> Result<Client, String> {
    let response_type = params.response_type.as_deref().ok_or("Missing response_type")?;
    if response_type != "code" {
        return Err("Unsupported response_type, must be 'code'".into());
    }

    let client_id = params.client_id.as_deref().ok_or("Missing client_id")?;
    let client = state
        .clients
        .find_by_id(client_id)
        .await
        .map_err(|_| "Database error".to_string())?
        .ok_or_else(|| "Unknown client_id".to_string())?;

    let redirect_uri = params.redirect_uri.as_deref().ok_or("Missing redirect_uri")?;
    if !constant_time::constant_time_str_eq(redirect_uri, &client.client_redirect_uri) {
        return Err("Invalid redirect_uri".into());
    }

    let scope = params.scope.as_deref().ok_or("Missing scope")?;
    crate::routes::api::validate_scope(scope)?;

    let state_val = params.state.as_deref().ok_or("Missing state")?;
    if state_val.len() > 1024 {
        return Err("state parameter too long".into());
    }

    // #11: Nonce is required to prevent replay attacks on ID tokens
    let nonce = params.nonce.as_deref().ok_or("Missing nonce")?;
    if nonce.is_empty() || nonce.len() > 512 {
        return Err("nonce must be 1–512 characters".into());
    }

    // #5: PKCE code_challenge must be 43–128 base64url characters (RFC 7636 §4.2)
    let code_challenge = params.code_challenge.as_deref().ok_or("Missing code_challenge")?;
    if code_challenge.len() < 43 || code_challenge.len() > 128 {
        return Err("code_challenge must be 43–128 characters".into());
    }

    let method = params
        .code_challenge_method
        .as_deref()
        .ok_or("Missing code_challenge_method")?;
    if method != "S256" {
        return Err("Only S256 code_challenge_method supported".into());
    }

    Ok(client)
}

fn error_response(state: &AppState, message: &str, lang: &str) -> Result<Response, AppError> {
    let ctx = Context::from_serialize(ErrorCtx {
        base: BaseCtx {
            t: state.locales.get(lang),
            lang,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        error_message: message,
    })?;
    let rendered = state.tera.render("error.html", &ctx)?;
    Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
}

fn build_query_string(params: &AuthorizeParams) -> String {
    let enc = super::urlencoding;
    let mut parts = Vec::new();
    if let Some(ref v) = params.response_type {
        parts.push(format!("response_type={}", enc(v)));
    }
    if let Some(ref v) = params.client_id {
        parts.push(format!("client_id={}", enc(v)));
    }
    if let Some(ref v) = params.redirect_uri {
        parts.push(format!("redirect_uri={}", enc(v)));
    }
    if let Some(ref v) = params.scope {
        parts.push(format!("scope={}", enc(v)));
    }
    if let Some(ref v) = params.state {
        parts.push(format!("state={}", enc(v)));
    }
    if let Some(ref v) = params.code_challenge {
        parts.push(format!("code_challenge={}", enc(v)));
    }
    if let Some(ref v) = params.code_challenge_method {
        parts.push(format!("code_challenge_method={}", enc(v)));
    }
    if let Some(ref v) = params.nonce {
        parts.push(format!("nonce={}", enc(v)));
    }
    parts.join("&")
}
