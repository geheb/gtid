use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;
use tera::Context;
use tower_cookies::Cookies;

use crate::crypto::password;
use crate::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::language::Lang;
use crate::middleware::session::AdminUser;
use crate::routes::ctx::{UserCreateCtx, UserEditCtx, UsersListCtx};
use crate::AppState;

use super::{get_all, get_field, get_field_opt, parse_form_fields, redirect, validate_password, DeleteForm};

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
            state.account_lockout.locked_until_utc(&u.email)
                .map(|until| (u.id.clone(), until))
        })
        .collect();
    let ctx = Context::from_serialize(UsersListCtx {
        t: state.locales.get(&lang.tag),
        lang: &lang.tag,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
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
        t: state.locales.get(&lang.tag),
        lang: &lang.tag,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
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
    let email = get_field(&fields, "email");
    let display_name = get_field_opt(&fields, "display_name");
    let pw = get_field(&fields, "password");
    let roles = get_all(&fields, "roles");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(state.locales.get(&lang.tag).csrf_token_invalid.clone()));
    }

    let render_error = |msg: &str, status: StatusCode| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(UserCreateCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
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

    if let Err(msg) = validate_password(&pw, state.locales.get(&lang.tag)) {
        return render_error(&msg, StatusCode::BAD_REQUEST);
    }

    if state.users.find_by_email(&email).await?.is_some() {
        return render_error(&state.locales.get(&lang.tag).user_create_error_email_exists, StatusCode::CONFLICT);
    }

    let id = crate::crypto::id::new_id();
    let hash = password::hash_password(&pw)?;
    let roles_str = roles.join(",");
    state.users.create(&id, &email, &hash, display_name.as_deref(), &roles_str, false).await?;
    tracing::info!(event = "user_created", user_id = %id, email = %email, roles = %roles_str, "Admin created user");

    // Enqueue confirmation email
    enqueue_confirmation_email(&state, &id, &email, display_name.as_deref(), &lang.tag).await;

    Ok(redirect("/admin/users"))
}

pub async fn user_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(id): Path<String>,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let user = state.users.find_by_id(&id).await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let user_roles: Vec<String> = user.roles().into_iter().map(String::from).collect();
    let locked_until = state.account_lockout.locked_until_utc(&user.email);
    let display_name = user.display_name.as_deref().unwrap_or("");

    let ctx = Context::from_serialize(UserEditCtx {
        t: state.locales.get(&lang.tag),
        lang: &lang.tag,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "users",
        csrf_token: &csrf.form_token,
        error: false,
        error_message: "",
        user: &user,
        form_display_name: display_name,
        available_roles: &state.config.roles,
        form_roles: &user_roles,
        locked_until,
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
    let display_name = get_field_opt(&fields, "display_name");
    let pw = get_field(&fields, "password");
    let roles = get_all(&fields, "roles");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(state.locales.get(&lang.tag).csrf_token_invalid.clone()));
    }

    let user = state.users.find_by_id(&id).await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let render_error = |msg: &str| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(UserEditCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
            active_page: "users",
            csrf_token: &csrf_token,
            error: true,
            error_message: msg,
            user: &user,
            form_display_name: display_name.as_deref().unwrap_or(""),
            available_roles: &state.config.roles,
            form_roles: &roles,
            locked_until: state.account_lockout.locked_until_utc(&user.email),
        })?;
        let rendered = state.tera.render("admin/user_edit.html", &ctx)?;
        Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
    };

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

    // Manual confirm
    if get_field_opt(&fields, "manual_confirm").is_some() && !user.is_confirmed {
        state.users.confirm(&id).await?;
        state.confirmation_tokens.delete_for_user(&id).await?;
        tracing::info!(event = "user_confirmed_manually", user_id = %id, "Admin manually confirmed user");
    }

    // Resend confirmation email
    if get_field_opt(&fields, "resend_confirmation").is_some() && !user.is_confirmed {
        enqueue_confirmation_email(&state, &id, &user.email, user.display_name.as_deref(), &lang.tag).await;
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
        return Err(AppError::BadRequest(state.locales.get(&lang.tag).csrf_token_invalid.clone()));
    }

    // Clean up cross-DB references before deleting the user
    state.auth_codes.delete_by_user_id(&id).await?;
    state.refresh_tokens.delete_by_user_id(&id).await?;
    state.consents.delete_by_user_id(&id).await?;

    state.users.delete(&id).await?;
    tracing::info!(event = "user_deleted", user_id = %id, "Admin deleted user");

    Ok(redirect("/admin/users"))
}

async fn enqueue_confirmation_email(
    state: &AppState,
    user_id: &str,
    email: &str,
    display_name: Option<&str>,
    lang: &str,
) {
    let expiry_hours = state.config.email_confirm_token_expiry_hours;
    let expires_at = match chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(expiry_hours as i64))
    {
        Some(t) => {
            use crate::datetime::SqliteDateTimeExt;
            t.to_sqlite()
        }
        None => return,
    };

    // Delete old tokens and create a new one
    let _ = state.confirmation_tokens.delete_for_user(user_id).await;
    let token = match state.confirmation_tokens.create(user_id, &expires_at).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(event = "confirmation_token_failed", error = %e, "Failed to create confirmation token");
            return;
        }
    };

    let link = format!("{}/confirm-email?token={}", state.config.public_ui_uri, token);
    let name = display_name.unwrap_or(email);

    // Load template and enqueue email
    let template = state.email_templates
        .find_by_type_and_lang("confirm_registration", lang)
        .await
        .ok()
        .flatten();

    let (subject, body_html) = match template {
        Some(t) => {
            let body = t.body_html.replace("{{name}}", name).replace("{{link}}", &link);
            let subject = t.subject.replace("{{name}}", name);
            (subject, body)
        }
        None => {
            let subject = "Confirm your email".to_string();
            let body = format!("<p>Hi {name},</p><p>Please confirm your email: <a href=\"{link}\">{link}</a></p>");
            (subject, body)
        }
    };

    if let Err(e) = state.email_queue.enqueue(email, &subject, &body_html).await {
        tracing::error!(event = "confirmation_email_failed", error = %e, "Failed to enqueue confirmation email");
    }
}
