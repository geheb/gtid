use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;
use tera::Context;
use tower_cookies::Cookies;

use crate::AppState;
use gtid_shared::crypto::password;
use gtid_shared::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use gtid_shared::middleware::language::Lang;
use crate::middleware::session::AdminUser;
use crate::ctx::{BaseCtx, UserCreateCtx, UserEditCtx, UsersListCtx};

use super::{DeleteForm, get_all, get_field, get_field_opt, parse_form_fields, redirect, validate_password};

pub async fn users_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let users = state.users.list().await?;
    let locked_until: std::collections::HashMap<String, String> = users
        .iter()
        .filter_map(|u| {
            state
                .account_lockout
                .locked_until_utc(&u.email)
                .map(|until| (u.id.clone(), until))
        })
        .collect();
    let ctx = Context::from_serialize(UsersListCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        active_page: "users",
        csrf_token: &csrf.form_token,
        users: &users,
        locked_until,
    })?;
    let rendered = state.tera.render("admin/users.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn user_create_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let ctx = Context::from_serialize(UserCreateCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        active_page: "create",
        csrf_token: &csrf.form_token,
        error: false,
        error_message: "",
        form_email: "",
        form_display_name: "",
        available_roles: &state.config.roles,
        form_roles: &[],
    })?;
    let rendered = state.tera.render("admin/user_create.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn user_create_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    _admin: AdminUser,
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let email = super::normalize_email(&get_field(&fields, "email"));
    let display_name = get_field_opt(&fields, "display_name");
    let pw = get_field(&fields, "password");
    let roles = get_all(&fields, "roles");

    validate_user_fields(&csrf_token, None, &email, display_name.as_deref(), &pw, &roles)
        .map_err(|e| AppError::BadRequest(e.into()))?;

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let render_error = |msg: &str, status: StatusCode| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(UserCreateCtx {
            base: BaseCtx {
                t: state.locales.get(&lang.tag),
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            active_page: "create",
            csrf_token: &csrf_token,
            error: true,
            error_message: msg,
            form_email: &email,
            form_display_name: display_name.as_deref().unwrap_or(""),
            available_roles: &state.config.roles,
            form_roles: &roles,
        })?;
        let rendered = state.tera.render("admin/user_create.html", &ctx)?;
        Ok((status, Html(rendered)).into_response())
    };

    if roles.is_empty() {
        return render_error(
            &state.locales.get(&lang.tag).user_create_error_no_roles,
            StatusCode::BAD_REQUEST,
        );
    }

    if let Err(msg) = validate_password(&pw, state.locales.get(&lang.tag)) {
        return render_error(&msg, StatusCode::BAD_REQUEST);
    }

    if state.users.find_by_email(&email).await?.is_some() {
        return render_error(
            &state.locales.get(&lang.tag).user_create_error_email_exists,
            StatusCode::CONFLICT,
        );
    }

    let id = gtid_shared::crypto::id::new_id();
    let hash = password::hash_password(&pw)?;
    let roles_str = roles.join(",");
    state
        .users
        .create(&id, &email, &hash, display_name.as_deref(), &roles_str, false)
        .await?;
    tracing::info!(event = "user_created", user_id = %id, email = %email, roles = %roles_str, "Admin created user");

    gtid_shared::email::enqueue_confirmation_email(&state, &id, &email, display_name.as_deref(), &lang.tag).await;

    Ok(redirect("/admin/users"))
}

pub async fn user_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(id): Path<String>,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let user = state
        .users
        .find_by_id(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let user_roles: Vec<String> = user.roles().into_iter().map(String::from).collect();
    let locked_until = state.account_lockout.locked_until_utc(&user.email);
    let display_name = user.display_name.as_deref().unwrap_or("");

    let ctx = Context::from_serialize(UserEditCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        active_page: "users",
        csrf_token: &csrf.form_token,
        error: false,
        error_message: "",
        user: &user,
        form_email: &user.email,
        form_display_name: display_name,
        available_roles: &state.config.roles,
        form_roles: &user_roles,
        locked_until,
        has_totp: user.has_totp(),
    })?;
    let rendered = state.tera.render("admin/user_edit.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn user_edit_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    _admin: AdminUser,
    Path(id): Path<String>,
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let email = super::normalize_email(&get_field(&fields, "email"));
    let display_name = get_field_opt(&fields, "display_name");
    let pw = get_field(&fields, "password");
    let roles = get_all(&fields, "roles");

    validate_user_fields(&csrf_token, Some(&id), &email, display_name.as_deref(), &pw, &roles)
        .map_err(|e| AppError::BadRequest(e.into()))?;

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let user = state
        .users
        .find_by_id(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let render_error = |msg: &str| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(UserEditCtx {
            base: BaseCtx {
                t: state.locales.get(&lang.tag),
                lang: &lang.tag,
                css_hash: &state.css_hash,
                js_hash: &state.js_hash,
            },
            active_page: "users",
            csrf_token: &csrf_token,
            error: true,
            error_message: msg,
            user: &user,
            form_email: &email,
            form_display_name: display_name.as_deref().unwrap_or(""),
            available_roles: &state.config.roles,
            form_roles: &roles,
            locked_until: state.account_lockout.locked_until_utc(&user.email),
            has_totp: user.has_totp(),
        })?;
        let rendered = state.tera.render("admin/user_edit.html", &ctx)?;
        Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
    };

    if email != user.email.to_lowercase() {
        if email.is_empty() || !email.contains('@') {
            return render_error(&state.locales.get(&lang.tag).profile_change_email_error_same);
        }
        if state.users.find_by_email(&email).await?.is_some() {
            return render_error(&state.locales.get(&lang.tag).user_create_error_email_exists);
        }
        state.users.update_email(&id, &email).await?;
        tracing::info!(event = "user_email_changed", user_id = %id, new_email = %email, "Admin changed user email");
    }

    if !pw.is_empty() {
        if let Err(msg) = validate_password(&pw, state.locales.get(&lang.tag)) {
            return render_error(&msg);
        }
        let hash = password::hash_password(&pw)?;
        state.users.update_password(&id, &hash).await?;
    }

    if get_field_opt(&fields, "unlock").is_some() {
        state.account_lockout.clear(&user.email);
    }

    if get_field_opt(&fields, "manual_confirm").is_some() && !user.is_confirmed {
        state.users.confirm(&id).await?;
        state.confirmation_tokens.delete_by_user_id(&id).await?;
        tracing::info!(event = "user_confirmed_manually", user_id = %id, "Admin manually confirmed user");
    }

    if get_field_opt(&fields, "resend_confirmation").is_some() && !user.is_confirmed {
        gtid_shared::email::enqueue_confirmation_email(&state, &id, &user.email, user.display_name.as_deref(), &lang.tag).await;
        tracing::info!(event = "confirmation_resent", user_id = %id, "Admin resent confirmation email");
    }

    let roles_str = roles.join(",");
    state.users.update(&id, display_name.as_deref(), &roles_str).await?;
    tracing::info!(event = "user_updated", user_id = %id, roles = %roles_str, "Admin updated user");

    Ok(redirect("/admin/users"))
}

pub async fn user_delete(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    _admin: AdminUser,
    Path(id): Path<String>,
    lang: Lang,
    axum::Form(form): axum::Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    state.auth_codes.delete_by_user_id(&id).await?;
    state.refresh_tokens.delete_by_user_id(&id).await?;
    state.consents.delete_by_user_id(&id).await?;
    state.password_reset_tokens.delete_by_user_id(&id).await?;
    state.confirmation_tokens.delete_by_user_id(&id).await?;
    state.email_changes.delete_by_user_id(&id).await?;
    state.sessions.delete_by_user_id(&id).await?;
    state.trusted_devices.delete_by_user_id(&id).await?;
    state.users.delete(&id).await?;

    tracing::info!(event = "user_deleted", user_id = %id, "Admin deleted user");

    Ok(redirect("/admin/users"))
}

pub async fn user_reset_2fa(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    admin: AdminUser,
    Path(id): Path<String>,
    lang: Lang,
    axum::Form(form): axum::Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    let user = state
        .users
        .find_by_id(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    if user.has_totp() {
        state.users.set_totp_secret(&id, None).await?;
        state.trusted_devices.delete_by_user_id(&id).await?;
        tracing::info!(event = "totp_reset_by_admin", user_id = %id, "Admin reset 2FA for user");
    }

    if admin.0.id == id {
        cookies.remove(tower_cookies::Cookie::from(
            crate::middleware::session::TRUST_DEVICE_COOKIE_NAME,
        ));
        let pending_id = state
            .pending_2fa
            .store(id, None, None)
            .ok_or_else(|| AppError::Internal("pending 2fa store full".into()))?;
        return Ok(redirect(&format!("/2fa/setup?p={pending_id}")));
    }

    Ok(redirect(&format!("/admin/users/{id}/edit")))
}

fn validate_user_fields(
    csrf_token: &str,
    id: Option<&str>,
    email: &str,
    display_name: Option<&str>,
    password: &str,
    roles: &[String],
) -> Result<(), &'static str> {
    if csrf_token.len() > super::MAX_CSRF_TOKEN
        || id.is_some_and(|i| i.len() > super::MAX_UUID)
        || email.len() > super::MAX_EMAIL
        || display_name.is_some_and(|n| n.len() > super::MAX_DISPLAY_NAME)
        || password.len() > super::MAX_PASSWORD
        || roles.iter().any(|r| r.len() > super::MAX_ROLE)
    {
        return Err("Field length exceeded");
    }
    Ok(())
}
