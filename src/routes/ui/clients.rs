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
use crate::routes::ctx::{ClientCreateCtx, ClientEditCtx, ClientsListCtx};
use crate::AppState;

use super::{get_field, get_field_opt, parse_form_fields, redirect, validate_client_secret, validate_redirect_uri, DeleteForm};

pub async fn clients_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let clients = state.clients.list().await?;
    let ctx = Context::from_serialize(ClientsListCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "clients",
        csrf_token: &csrf.form_token,
        clients: &clients,
    })?;
    let rendered = state.tera.render("admin/clients.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn client_create_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let ctx = Context::from_serialize(ClientCreateCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "create_client",
        csrf_token: &csrf.form_token,
        error: false,
        error_message: "",
        form_client_id: "",
        form_redirect_uri: "http://localhost/signin-oidc",
        form_post_logout_uri: "http://localhost/signout-callback-oidc",
    })?;
    let rendered = state.tera.render("admin/client_create.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn client_create_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    _admin: AdminUser,
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let client_id = get_field(&fields, "client_id");
    let client_secret = get_field(&fields, "client_secret");
    let redirect_uri = get_field(&fields, "client_redirect_uri");
    let post_logout_uri = get_field_opt(&fields, "client_post_logout_redirect_uri");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    let render_error = |msg: &str| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(ClientCreateCtx {
            t: &state.i18n,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
            active_page: "create_client",
            csrf_token: &csrf_token,
            error: true,
            error_message: msg,
            form_client_id: &client_id,
            form_redirect_uri: &redirect_uri,
            form_post_logout_uri: post_logout_uri.as_deref().unwrap_or(""),
        })?;
        let rendered = state.tera.render("admin/client_create.html", &ctx)?;
        Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
    };

    if client_id.is_empty() {
        return render_error("Client-ID is required");
    }
    if let Err(msg) = validate_client_secret(&client_secret, &state.i18n) {
        return render_error(&msg);
    }
    if let Err(msg) = validate_redirect_uri(&redirect_uri) {
        return render_error(&msg);
    }
    if let Some(ref plu) = post_logout_uri {
        if let Err(msg) = validate_redirect_uri(plu) {
            return render_error(&msg);
        }
    }
    if state.clients.find_by_id(&client_id).await?.is_some() {
        return render_error(&state.i18n.client_create_error_id_exists);
    }

    let hash = password::hash_password(&client_secret)?;
    state.clients.create(&client_id, &hash, &redirect_uri, post_logout_uri.as_deref()).await?;
    tracing::info!(event = "client_created", client_id = %client_id, redirect_uri = %redirect_uri, "Admin created client");

    if let Ok(updated_clients) = state.clients.list().await {
        if let Ok(mut csp) = state.csp.write() {
            *csp = crate::middleware::security_headers::build_csp(&updated_clients);
        }
    }

    Ok(redirect("/admin/clients"))
}

pub async fn client_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(id): Path<String>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let client = state.clients.find_by_id(&id).await?
        .ok_or_else(|| AppError::NotFound("Client not found".into()))?;

    let ctx = Context::from_serialize(ClientEditCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "clients",
        csrf_token: &csrf.form_token,
        error: false,
        error_message: "",
        client: &client,
        form_redirect_uri: &client.client_redirect_uri,
        form_post_logout_uri: client.client_post_logout_redirect_uri.as_deref().unwrap_or(""),
    })?;
    let rendered = state.tera.render("admin/client_edit.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn client_edit_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    _admin: AdminUser,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let client_secret = get_field(&fields, "client_secret");
    let redirect_uri = get_field(&fields, "client_redirect_uri");
    let post_logout_uri = get_field_opt(&fields, "client_post_logout_redirect_uri");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    if let Err(msg) = validate_redirect_uri(&redirect_uri) {
        return Err(AppError::BadRequest(msg));
    }
    if let Some(ref plu) = post_logout_uri {
        if let Err(msg) = validate_redirect_uri(plu) {
            return Err(AppError::BadRequest(msg));
        }
    }

    let client = state.clients.find_by_id(&id).await?
        .ok_or_else(|| AppError::NotFound("Client not found".into()))?;

    let render_error = |msg: &str| -> Result<Response, AppError> {
        let ctx = Context::from_serialize(ClientEditCtx {
            t: &state.i18n,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
            active_page: "clients",
            csrf_token: &csrf_token,
            error: true,
            error_message: msg,
            client: &client,
            form_redirect_uri: &redirect_uri,
            form_post_logout_uri: post_logout_uri.as_deref().unwrap_or(""),
        })?;
        let rendered = state.tera.render("admin/client_edit.html", &ctx)?;
        Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
    };

    if !client_secret.is_empty() {
        if let Err(msg) = validate_client_secret(&client_secret, &state.i18n) {
            return render_error(&msg);
        }
        let hash = password::hash_password(&client_secret)?;
        state.clients.update_secret(&id, &hash).await?;
    }

    state.clients.update(&id, &redirect_uri, post_logout_uri.as_deref()).await?;
    tracing::info!(event = "client_updated", client_id = %id, redirect_uri = %redirect_uri, "Admin updated client");

    if let Ok(updated_clients) = state.clients.list().await {
        if let Ok(mut csp) = state.csp.write() {
            *csp = crate::middleware::security_headers::build_csp(&updated_clients);
        }
    }

    Ok(redirect("/admin/clients"))
}

pub async fn client_delete(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    _admin: AdminUser,
    Path(id): Path<String>,
    axum::Form(form): axum::Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !csrf::verify_csrf(&cookies, &form.csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    state.clients.delete(&id).await?;
    tracing::info!(event = "client_deleted", client_id = %id, "Admin deleted client");

    if let Ok(updated_clients) = state.clients.list().await {
        if let Ok(mut csp) = state.csp.write() {
            *csp = crate::middleware::security_headers::build_csp(&updated_clients);
        }
    }

    Ok(redirect("/admin/clients"))
}
