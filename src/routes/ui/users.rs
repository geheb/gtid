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
use crate::middleware::session::AdminUser;
use crate::routes::ctx::{UserCreateCtx, UserEditCtx, UsersListCtx};
use crate::AppState;

use super::{get_all, get_field, get_field_opt, parse_form_fields, redirect, validate_password, DeleteForm};

pub async fn users_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
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
        t: &state.i18n,
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
) -> Result<Response, AppError> {
    let ctx = Context::from_serialize(UserCreateCtx {
        t: &state.i18n,
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
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let email = get_field(&fields, "email");
    let display_name = get_field_opt(&fields, "display_name");
    let pw = get_field(&fields, "password");
    let roles = get_all(&fields, "roles");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    let render_error = |msg: &str, status: StatusCode| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(UserCreateCtx {
            t: &state.i18n,
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

    if let Err(msg) = validate_password(&pw, &state.i18n) {
        return render_error(&msg, StatusCode::BAD_REQUEST);
    }

    if state.users.find_by_email(&email).await?.is_some() {
        return render_error(&state.i18n.user_create_error_email_exists, StatusCode::CONFLICT);
    }

    let id = crate::crypto::id::new_id();
    let hash = password::hash_password(&pw)?;
    let roles_str = roles.join(",");
    state.users.create(&id, &email, &hash, display_name.as_deref(), &roles_str).await?;
    tracing::info!(event = "user_created", user_id = %id, email = %email, roles = %roles_str, "Admin created user");

    Ok(redirect("/admin/users"))
}

pub async fn user_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(id): Path<String>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let user = state.users.find_by_id(&id).await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let user_roles: Vec<String> = user.roles().into_iter().map(String::from).collect();
    let locked_until = state.account_lockout.locked_until_utc(&user.email);
    let display_name = user.display_name.as_deref().unwrap_or("");

    let ctx = Context::from_serialize(UserEditCtx {
        t: &state.i18n,
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
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let display_name = get_field_opt(&fields, "display_name");
    let pw = get_field(&fields, "password");
    let roles = get_all(&fields, "roles");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    let user = state.users.find_by_id(&id).await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let render_error = |msg: &str| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(UserEditCtx {
            t: &state.i18n,
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
        if let Err(msg) = validate_password(&pw, &state.i18n) {
            return render_error(&msg);
        }
        let hash = password::hash_password(&pw)?;
        state.users.update_password(&id, &hash).await?;
    }

    if get_field_opt(&fields, "unlock").is_some() {
        state.account_lockout.clear(&user.email);
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
    axum::Form(form): axum::Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    state.users.delete(&id).await?;
    tracing::info!(event = "user_deleted", user_id = %id, "Admin deleted user");

    Ok(redirect("/admin/users"))
}
