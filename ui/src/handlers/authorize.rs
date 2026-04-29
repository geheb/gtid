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
use gtid_shared::crypto::constant_time;
use gtid_shared::datetime::SqliteDateTimeExt;
use gtid_shared::entities::client::Client;
use gtid_shared::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use gtid_shared::middleware::language::Lang;
use crate::middleware::session::OptionalSessionUser;
use gtid_shared::oauth::urlencoding;
use crate::ctx::{AuthorizeCtx, BaseCtx, ErrorCtx};
use crate::handlers::redirect;

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
    let t = state.locales.get(&lang.tag);
    let ua = gtid_shared::routes::require_user_agent(&headers)
        .map_err(AppError::BadRequest)?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("authorize", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return Err(AppError::BadRequest(t.error_too_many_requests.clone()));
    }

    if let Err(e) = validate_authorize_params(&params, &state, t, &lang.tag).await {
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
                .ok_or_else(|| AppError::Internal("pending_redirect store full for authorize".into()))?;
            let login_url = format!("/login?rid={rid}");
            return Ok(redirect(&login_url));
        }
    };

    // Check if user already granted consent for this client + scope
    let client_id = params.client_id.as_deref().unwrap_or("");
    let scope = params.scope.as_deref().unwrap_or("openid");
    if state.consents.has_grant(&user.id, client_id, scope).await? {
        let code = gtid_shared::crypto::id::new_id();
        let code_challenge = params.code_challenge.as_deref().unwrap_or("");
        let redirect_uri = params.redirect_uri.as_deref().unwrap_or("");
        let expires_at = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(60))
            .ok_or_else(|| AppError::Internal("auth code expiry overflow for authorize_get".into()))?
        .to_sqlite();
    state
        .auth_codes
        .create(&gtid_shared::entities::authorization_code::NewAuthorizationCode {
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
            redirect_url.push_str(&format!("&state={}", urlencoding(s)));
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
    pub fn validate(&self, t: &gtid_shared::i18n::I18n) -> Result<(), String> {
        use crate::handlers::{MAX_CLIENT_ID, MAX_CSRF_TOKEN, MAX_SCOPE, MAX_URI};
        if self.csrf_token.len() > MAX_CSRF_TOKEN
            || self.client_id.len() > MAX_CLIENT_ID
            || self.redirect_uri.len() > MAX_URI
            || self.scope.as_ref().is_some_and(|s| s.len() > MAX_SCOPE)
            || self.consent.len() > 10
        {
            return Err(t.error_field_length_exceeded.clone());
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
    let t = state.locales.get(&lang.tag);
    form.validate(t).map_err(AppError::BadRequest)?;

    let ua = gtid_shared::routes::require_user_agent(&headers)
        .map_err(AppError::BadRequest)?;
    let ip = gtid_shared::routes::client_ip(&headers, &addr, state.config.trusted_proxies);
    let rl_key = state.login_rate_limiter.key("authorize", &ip, ua);
    if state.login_rate_limiter.is_limited(rl_key) {
        return Err(AppError::BadRequest(t.error_too_many_requests.clone()));
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
        .map_err(|e| AppError::Internal(format!("find client {} failed for authorize_post: {e}", form.client_id)))?
        .ok_or_else(|| {
            state.login_rate_limiter.record_failure(rl_key);
            AppError::BadRequest(t.error_invalid_client_id_or_redirect_uri.clone())
        })?;
    if !constant_time::constant_time_str_eq(&form.redirect_uri, &client.client_redirect_uri) {
        state.login_rate_limiter.record_failure(rl_key);
        return Err(AppError::BadRequest(t.error_invalid_client_id_or_redirect_uri.clone()));
    }
    if form.code_challenge_method != "S256" {
        return Err(AppError::BadRequest(t.error_only_s256_supported.clone()));
    }
    if form.code_challenge.len() < 43 || form.code_challenge.len() > 128 {
        return Err(AppError::BadRequest(t.error_code_challenge_length.clone()));
    }

    // #11: Nonce required
    if form.nonce.as_ref().is_none_or(|n| n.is_empty()) {
        return Err(AppError::BadRequest(t.error_missing_nonce.clone()));
    }

    if let Some(ref s) = form.state
        && s.len() > 1024
    {
        return Err(AppError::BadRequest(t.error_state_too_long.clone()));
    }

    let scope = form.scope.as_deref().unwrap_or("openid");
    if let Err(msg) = gtid_shared::oauth::validate_scope(scope, &lang.tag) {
        return Err(AppError::BadRequest(msg));
    }

    if form.consent != "allow" {
        let state_encoded = form
            .state
            .as_deref()
            .map(urlencoding)
            .unwrap_or_default();
        let deny_url = format!("{}?error=access_denied&state={}", form.redirect_uri, state_encoded);
        return Ok(redirect(&deny_url));
    }

    let code = gtid_shared::crypto::id::new_id();
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .ok_or_else(|| AppError::Internal("auth code expiry overflow for authorize_post".into()))?
        .to_sqlite();

    state
        .auth_codes
        .create(&gtid_shared::entities::authorization_code::NewAuthorizationCode {
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
        redirect_url.push_str(&format!("&state={}", urlencoding(s)));
    }

    Ok(redirect(&redirect_url))
}

async fn validate_authorize_params(
    params: &AuthorizeParams,
    state: &AppState,
    t: &gtid_shared::i18n::I18n,
    lang: &str,
) -> Result<Client, String> {
    let response_type = params.response_type.as_deref().ok_or_else(|| t.error_missing_response_type.clone())?;
    if response_type != "code" {
        return Err(t.error_unsupported_response_type.clone());
    }

    let client_id = params.client_id.as_deref().ok_or_else(|| t.error_missing_client_id.clone())?;
    let client = state
        .clients
        .find_by_id(client_id)
        .await
        .map_err(|_| "Query failed".to_string())?
        .ok_or_else(|| t.error_unknown_client_id.clone())?;

    let redirect_uri = params.redirect_uri.as_deref().ok_or_else(|| t.error_missing_redirect_uri.clone())?;
    if !constant_time::constant_time_str_eq(redirect_uri, &client.client_redirect_uri) {
        return Err(t.error_invalid_redirect_uri.clone());
    }

    let scope = params.scope.as_deref().ok_or_else(|| t.error_missing_scope.clone())?;
    gtid_shared::oauth::validate_scope(scope, lang)?;

    let state_val = params.state.as_deref().ok_or_else(|| t.error_missing_state.clone())?;
    if state_val.len() > 1024 {
        return Err(t.error_state_too_long.clone());
    }

    // #11: Nonce is required to prevent replay attacks on ID tokens
    let nonce = params.nonce.as_deref().ok_or_else(|| t.error_missing_nonce.clone())?;
    if nonce.is_empty() || nonce.len() > 512 {
        return Err(t.error_nonce_length.clone());
    }

    // #5: PKCE code_challenge must be 43–128 base64url characters (RFC 7636 §4.2)
    let code_challenge = params.code_challenge.as_deref().ok_or_else(|| t.error_missing_code_challenge.clone())?;
    if code_challenge.len() < 43 || code_challenge.len() > 128 {
        return Err(t.error_code_challenge_length.clone());
    }

    let method = params
        .code_challenge_method
        .as_deref()
        .ok_or_else(|| t.error_missing_code_challenge_method.clone())?;
    if method != "S256" {
        return Err(t.error_only_s256_supported.clone());
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
    let enc = urlencoding;
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
