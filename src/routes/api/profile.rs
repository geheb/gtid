use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use tera::Context;
use tower_cookies::Cookies;

use crate::crypto::password;
use crate::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::language::Lang;
use crate::middleware::session::SessionUser;
use crate::routes::ctx::ProfileCtx;
use crate::routes::ui::redirect;
use crate::AppState;

#[derive(Deserialize)]
pub struct ProfileQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub pw_saved: Option<String>,
}

fn render_profile(
    state: &AppState,
    user: &crate::models::user::User,
    csrf_token: &str,
    saved: bool,
    pw_saved: bool,
    pw_error_message: &str,
    lang: &str,
) -> Result<String, AppError> {
    let user_roles: Vec<String> = user.roles().into_iter().map(String::from).collect();
    let display_name = user.display_name.clone().unwrap_or_default();
    let ctx = Context::from_serialize(ProfileCtx {
        t: state.locales.get(lang),
        lang,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        user,
        user_roles,
        csrf_token,
        saved,
        pw_saved,
        pw_error: !pw_error_message.is_empty(),
        pw_error_message,
        form_display_name: &display_name,
    })?;
    Ok(state.tera.render("profile.html", &ctx)?)
}

pub async fn profile_page(
    State(state): State<Arc<AppState>>,
    session_user: SessionUser,
    csrf: CsrfToken,
    axum::extract::Query(query): axum::extract::Query<ProfileQuery>,
    lang: Lang,
) -> Result<Response, AppError> {
    let user = state
        .users
        .find_by_id(&session_user.0.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let rendered = render_profile(
        &state, &user, &csrf.form_token,
        query.saved.is_some(), query.pw_saved.is_some(), "", &lang.tag,
    )?;

    Ok(Html(rendered).into_response())
}

#[derive(Deserialize)]
pub struct ProfileForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub display_name: String,
}

pub async fn profile_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<ProfileForm>,
) -> Result<Response, AppError> {
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(state.locales.get(&lang.tag).csrf_token_invalid.clone()));
    }

    let display_name = if form.display_name.trim().is_empty() {
        None
    } else {
        Some(form.display_name.trim())
    };
    state
        .users
        .update_display_name(&session_user.0.id, display_name)
        .await?;

    Ok(redirect("/profile?saved=1"))
}

#[derive(Deserialize)]
pub struct PasswordForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub current_password: String,
    #[serde(default)]
    pub new_password: String,
    #[serde(default)]
    pub new_password_confirm: String,
}

pub async fn password_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<PasswordForm>,
) -> Result<Response, AppError> {
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(state.locales.get(&lang.tag).csrf_token_invalid.clone()));
    }

    let t = state.locales.get(&lang.tag);
    let user = state
        .users
        .find_by_id(&session_user.0.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    // Verify current password
    if !password::verify_password(&form.current_password, &user.password_hash) {
        let msg = &t.profile_password_error_wrong;
        let rendered = render_profile(&state, &user, &form.csrf_token, false, false, msg, &lang.tag)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    // Check that new passwords match
    if form.new_password != form.new_password_confirm {
        let msg = &t.profile_password_error_mismatch;
        let rendered = render_profile(&state, &user, &form.csrf_token, false, false, msg, &lang.tag)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    // Validate new password strength
    if let Err(msg) = crate::routes::ui::validate_password(&form.new_password, t) {
        let rendered = render_profile(&state, &user, &form.csrf_token, false, false, &msg, &lang.tag)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    let hash = password::hash_password(&form.new_password)?;
    state.users.update_password(&user.id, &hash).await?;

    Ok(redirect("/profile?pw_saved=1"))
}
