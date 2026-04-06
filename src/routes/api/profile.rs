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
    #[serde(default)]
    pub email_saved: Option<String>,
}

fn render_profile(
    state: &AppState,
    user: &crate::models::user::User,
    csrf_token: &str,
    saved: bool,
    pw_saved: bool,
    pw_error_message: &str,
    email_saved: bool,
    email_error_message: &str,
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
        email_saved,
        email_error: !email_error_message.is_empty(),
        email_error_message,
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
        query.saved.is_some(), query.pw_saved.is_some(), "",
        query.email_saved.is_some(), "",
        &lang.tag,
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
        let rendered = render_profile(&state, &user, &form.csrf_token, false, false, msg, false, "", &lang.tag)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    // Check that new passwords match
    if form.new_password != form.new_password_confirm {
        let msg = &t.profile_password_error_mismatch;
        let rendered = render_profile(&state, &user, &form.csrf_token, false, false, msg, false, "", &lang.tag)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    // Validate new password strength
    if let Err(msg) = crate::routes::ui::validate_password(&form.new_password, t) {
        let rendered = render_profile(&state, &user, &form.csrf_token, false, false, &msg, false, "", &lang.tag)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    let hash = password::hash_password(&form.new_password)?;
    state.users.update_password(&user.id, &hash).await?;

    Ok(redirect("/profile?pw_saved=1"))
}

#[derive(Deserialize)]
pub struct EmailChangeForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub current_password: String,
    #[serde(default)]
    pub new_email: String,
}

pub async fn email_change_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<EmailChangeForm>,
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

    let render_email_error = |msg: &str| -> Result<Response, AppError> {
        let rendered = render_profile(
            &state, &user, &form.csrf_token,
            false, false, "", false, msg, &lang.tag,
        )?;
        Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
    };

    // Verify current password
    if !password::verify_password(&form.current_password, &user.password_hash) {
        return render_email_error(&t.profile_change_email_error_wrong_password);
    }

    let new_email = crate::routes::ui::normalize_email(&form.new_email);

    // Check email is different
    if new_email == user.email.to_lowercase() {
        return render_email_error(&t.profile_change_email_error_same);
    }

    // Check email not already taken
    if state.users.find_by_email(&new_email).await?.is_some() {
        return render_email_error(&t.profile_change_email_error_taken);
    }

    // Create email change token
    let expiry_hours = state.config.email_confirm_token_expiry_hours;
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(expiry_hours as i64))
        .ok_or_else(|| AppError::Internal("Token expiry overflow".into()))?;
    let expires_at = {
        use crate::datetime::SqliteDateTimeExt;
        expires_at.to_sqlite()
    };

    let _ = state.email_changes.delete_for_user(&user.id).await;
    let token = state
        .email_changes
        .create(&user.id, &new_email, &expires_at)
        .await?;

    let link = format!(
        "{}/confirm-email-change?token={}",
        state.config.public_ui_uri, token
    );
    let name = user.display_name.as_deref().unwrap_or(&user.email);

    // Load email template
    let template = state
        .email_templates
        .find_by_type_and_lang("change_email", &lang.tag)
        .await
        .ok()
        .flatten();

    let t_loc = state.locales.get(&lang.tag);
    let (subject, body_html) = crate::routes::ui::render_email_template(
        template.as_ref(), name, &link,
        &t_loc.email_default_change_email_subject,
        &t_loc.email_default_change_email_body,
    );

    if let Err(e) = state.email_queue.enqueue(&new_email, &subject, &body_html).await {
        tracing::error!(event = "email_change_email_failed", error = %e, "Failed to enqueue email change confirmation");
    }

    tracing::info!(event = "email_change_requested", user_id = %user.id, "Email change confirmation enqueued");

    Ok(redirect("/profile?email_saved=1"))
}
