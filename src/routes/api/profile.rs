use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use tera::Context;
use tower_cookies::Cookies;

use crate::AppState;
use crate::crypto::password;
use crate::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::language::Lang;
use crate::middleware::session::SessionUser;
use crate::routes::ctx::{BaseCtx, ProfileCtx};
use crate::routes::ui::redirect;

#[derive(Deserialize)]
pub struct ProfileQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub pw_saved: Option<String>,
    #[serde(default)]
    pub email_saved: Option<String>,
    #[serde(default)]
    pub totp_saved: Option<String>,
}

#[derive(Default)]
struct ProfileRenderOpts<'a> {
    saved: bool,
    pw_saved: bool,
    pw_error_message: &'a str,
    email_saved: bool,
    email_error_message: &'a str,
    totp_saved: bool,
    totp_error_message: &'a str,
}

fn render_profile(
    state: &AppState,
    user: &crate::models::user::User,
    csrf_token: &str,
    opts: &ProfileRenderOpts<'_>,
    lang: &str,
) -> Result<String, AppError> {
    let user_roles: Vec<String> = user.roles().into_iter().map(String::from).collect();
    let display_name = user.display_name.clone().unwrap_or_default();
    let ctx = Context::from_serialize(ProfileCtx {
        base: BaseCtx {
            t: state.locales.get(lang),
            lang,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        user,
        user_roles,
        csrf_token,
        saved: opts.saved,
        pw_saved: opts.pw_saved,
        pw_error: !opts.pw_error_message.is_empty(),
        pw_error_message: opts.pw_error_message,
        email_saved: opts.email_saved,
        email_error: !opts.email_error_message.is_empty(),
        email_error_message: opts.email_error_message,
        form_display_name: &display_name,
        has_totp: user.has_totp(),
        is_admin: user.is_admin(),
        totp_saved: opts.totp_saved,
        totp_error: !opts.totp_error_message.is_empty(),
        totp_error_message: opts.totp_error_message,
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
        &state,
        &user,
        &csrf.form_token,
        &ProfileRenderOpts {
            saved: query.saved.is_some(),
            pw_saved: query.pw_saved.is_some(),
            email_saved: query.email_saved.is_some(),
            totp_saved: query.totp_saved.is_some(),
            ..Default::default()
        },
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

impl ProfileForm {
    pub fn validate(&self) -> Result<(), &'static str> {
        use crate::routes::ui::{MAX_CSRF_TOKEN, MAX_DISPLAY_NAME};
        if self.csrf_token.len() > MAX_CSRF_TOKEN || self.display_name.len() > MAX_DISPLAY_NAME {
            return Err("invalid request");
        }
        Ok(())
    }
}

pub async fn profile_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<ProfileForm>,
) -> Result<Response, AppError> {
    form.validate().map_err(|e| AppError::BadRequest(e.into()))?;
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
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

impl PasswordForm {
    pub fn validate(&self) -> Result<(), &'static str> {
        use crate::routes::ui::{MAX_CSRF_TOKEN, MAX_PASSWORD};
        if self.csrf_token.len() > MAX_CSRF_TOKEN
            || self.current_password.len() > MAX_PASSWORD
            || self.new_password.len() > MAX_PASSWORD
            || self.new_password_confirm.len() > MAX_PASSWORD
        {
            return Err("invalid request");
        }
        Ok(())
    }
}

pub async fn password_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<PasswordForm>,
) -> Result<Response, AppError> {
    form.validate().map_err(|e| AppError::BadRequest(e.into()))?;
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
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
        let rendered = render_profile(
            &state,
            &user,
            &form.csrf_token,
            &ProfileRenderOpts {
                pw_error_message: msg,
                ..Default::default()
            },
            &lang.tag,
        )?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    // Check that new passwords match
    if form.new_password != form.new_password_confirm {
        let msg = &t.profile_password_error_mismatch;
        let rendered = render_profile(
            &state,
            &user,
            &form.csrf_token,
            &ProfileRenderOpts {
                pw_error_message: msg,
                ..Default::default()
            },
            &lang.tag,
        )?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    // Validate new password strength
    if let Err(msg) = crate::routes::ui::validate_password(&form.new_password, t) {
        let rendered = render_profile(
            &state,
            &user,
            &form.csrf_token,
            &ProfileRenderOpts {
                pw_error_message: &msg,
                ..Default::default()
            },
            &lang.tag,
        )?;
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

impl EmailChangeForm {
    pub fn validate(&self) -> Result<(), &'static str> {
        use crate::routes::ui::{MAX_CSRF_TOKEN, MAX_EMAIL, MAX_PASSWORD};
        if self.csrf_token.len() > MAX_CSRF_TOKEN
            || self.current_password.len() > MAX_PASSWORD
            || self.new_email.len() > MAX_EMAIL
        {
            return Err("invalid request");
        }
        Ok(())
    }
}

pub async fn email_change_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<EmailChangeForm>,
) -> Result<Response, AppError> {
    form.validate().map_err(|e| AppError::BadRequest(e.into()))?;
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let t = state.locales.get(&lang.tag);
    let user = state
        .users
        .find_by_id(&session_user.0.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let render_email_error = |msg: &str| -> Result<Response, AppError> {
        let rendered = render_profile(
            &state,
            &user,
            &form.csrf_token,
            &ProfileRenderOpts {
                email_error_message: msg,
                ..Default::default()
            },
            &lang.tag,
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

    let _ = state.email_changes.delete_by_user_id(&user.id).await;
    let token = state.email_changes.create(&user.id, &new_email, &expires_at).await?;

    let link = format!("{}/confirm-email-change?token={}", state.config.public_ui_uri, token);
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
        template.as_ref(),
        name,
        &link,
        &t_loc.email_default_change_email_subject,
        &t_loc.email_default_change_email_body,
    );

    if let Err(e) = state.email_queue.enqueue(&new_email, &subject, &body_html).await {
        tracing::error!(event = "email_change_email_failed", error = %e, "Failed to enqueue email change confirmation");
    }

    tracing::info!(event = "email_change_requested", user_id = %user.id, "Email change confirmation enqueued");

    Ok(redirect("/profile?email_saved=1"))
}

// ── POST /profile/2fa/setup ────────────────────────────────────────────────

pub async fn totp_setup_initiate(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<CsrfOnlyForm>,
) -> Result<Response, AppError> {
    form.validate().map_err(|e| AppError::BadRequest(e.into()))?;
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let user = &session_user.0;
    if user.has_totp() {
        return Ok(redirect("/profile"));
    }

    // Create a pending redirect back to profile
    let rid = state.pending_redirects.store("/profile?totp_saved=1".into());
    let pending_id = state
        .pending_2fa
        .store(user.id.clone(), rid, None)
        .ok_or_else(|| AppError::Internal("pending 2fa store full".into()))?;

    Ok(redirect(&format!("/2fa/setup?p={pending_id}")))
}

// ── POST /profile/2fa/disable ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TotpDisableForm {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub current_password: String,
}

impl TotpDisableForm {
    pub fn validate(&self) -> Result<(), &'static str> {
        use crate::routes::ui::{MAX_CSRF_TOKEN, MAX_PASSWORD};
        if self.csrf_token.len() > MAX_CSRF_TOKEN || self.current_password.len() > MAX_PASSWORD {
            return Err("invalid request");
        }
        Ok(())
    }
}

pub async fn totp_disable_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    session_user: SessionUser,
    lang: Lang,
    axum::Form(form): axum::Form<TotpDisableForm>,
) -> Result<Response, AppError> {
    form.validate().map_err(|e| AppError::BadRequest(e.into()))?;
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let t = state.locales.get(&lang.tag);
    let user = state
        .users
        .find_by_id(&session_user.0.id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    // Admins cannot disable 2FA
    if user.is_admin() {
        return Err(AppError::BadRequest(t.profile_2fa_admin_required.clone()));
    }

    if !user.has_totp() {
        return Ok(redirect("/profile"));
    }

    // Verify current password
    if !password::verify_password(&form.current_password, &user.password_hash) {
        let csrf_form_token = csrf::set_new_csrf_cookie(&cookies, state.config.secure_cookies);
        let rendered = render_profile(
            &state,
            &user,
            &csrf_form_token,
            &ProfileRenderOpts {
                totp_error_message: &t.profile_2fa_error_wrong_password,
                ..Default::default()
            },
            &lang.tag,
        )?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    // Disable 2FA: clear secret + trusted devices
    state.users.set_totp_secret(&user.id, None).await?;
    state.trusted_devices.delete_by_user_id(&user.id).await?;

    // Remove trust device cookie
    cookies.remove(tower_cookies::Cookie::from(crate::middleware::TRUST_DEVICE_COOKIE_NAME));

    tracing::info!(event = "totp_disabled", user_id = %user.id, "2FA disabled by user");

    Ok(redirect("/profile?totp_saved=1"))
}

#[derive(Deserialize)]
pub struct CsrfOnlyForm {
    #[serde(default)]
    pub csrf_token: String,
}

impl CsrfOnlyForm {
    pub fn validate(&self) -> Result<(), &'static str> {
        use crate::routes::ui::MAX_CSRF_TOKEN;
        if self.csrf_token.len() > MAX_CSRF_TOKEN {
            return Err("invalid request");
        }
        Ok(())
    }
}
