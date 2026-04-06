use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use tera::Context;
use tower_cookies::Cookies;

use crate::crypto::password;
use crate::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::language::Lang;
use crate::routes::ctx::SetupCtx;
use crate::AppState;

use super::{get_field, get_field_opt, parse_form_fields, redirect, validate_password};

pub async fn root_redirect(State(state): State<Arc<AppState>>) -> Response {
    let target = if state.setup_needed.load(Ordering::Acquire) {
        "/setup"
    } else {
        "/login"
    };
    redirect(target)
}

pub async fn setup_form(
    State(state): State<Arc<AppState>>,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    if !state.setup_needed.load(Ordering::Acquire) {
        return Ok(redirect("/login"));
    }

    let ctx = Context::from_serialize(SetupCtx {
        t: state.locales.get(&lang.tag),
        lang: &lang.tag,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        csrf_token: &csrf.form_token,
        error: false,
        error_message: "",
        form_email: "",
        form_display_name: "Administrator",
        form_token: "",
    })?;
    let rendered = state.tera.render("setup.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn setup_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    if !state.setup_needed.load(Ordering::Acquire) {
        return Ok(redirect("/login"));
    }

    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let setup_token = get_field(&fields, "setup_token");
    let email = super::normalize_email(&get_field(&fields, "email"));
    let display_name = get_field_opt(&fields, "display_name");
    let pw = get_field(&fields, "password");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let t = state.locales.get(&lang.tag);

    let render_error = |msg: &str, status: StatusCode| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(SetupCtx {
            t,
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
            csrf_token: &csrf_token,
            error: true,
            error_message: msg,
            form_email: &email,
            form_display_name: display_name.as_deref().unwrap_or(""),
            form_token: &setup_token,
        })?;
        let rendered = state.tera.render("setup.html", &ctx)?;
        Ok((status, Html(rendered)).into_response())
    };

    // Double-check DB to prevent race condition
    if state.users.has_admin().await.unwrap_or(false) {
        state.setup_needed.store(false, Ordering::Release);
        return render_error(&t.setup_error_already_configured, StatusCode::CONFLICT);
    }

    // Validate setup token
    let valid_token = state.setup_token.as_deref().unwrap_or("");
    if !crate::crypto::constant_time::constant_time_str_eq(&setup_token, valid_token) {
        return render_error(&t.setup_error_invalid_token, StatusCode::FORBIDDEN);
    }

    if let Err(msg) = validate_password(&pw, t) {
        return render_error(&msg, StatusCode::BAD_REQUEST);
    }

    if state.users.find_by_email(&email).await?.is_some() {
        return render_error(&t.setup_error_email_exists, StatusCode::CONFLICT);
    }

    let id = crate::crypto::id::new_id();
    let hash = password::hash_password(&pw)?;
    state
        .users
        .create(&id, &email, &hash, display_name.as_deref(), "admin", true)
        .await?;

    state.setup_needed.store(false, Ordering::Release);
    tracing::info!(event = "setup_complete", user_id = %id, email = %email, "Initial admin user created via setup");

    Ok(redirect("/login"))
}
