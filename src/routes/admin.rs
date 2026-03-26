use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use tower_cookies::Cookies;

use crate::crypto::password;
use crate::errors::AppError;

fn parse_form_fields(body: &[u8]) -> Vec<(String, String)> {
    form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn get_field(fields: &[(String, String)], key: &str) -> String {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).unwrap_or_default()
}

fn get_field_opt(fields: &[(String, String)], key: &str) -> Option<String> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).filter(|v| !v.is_empty())
}

fn get_all(fields: &[(String, String)], key: &str) -> Vec<String> {
    fields.iter().filter(|(k, _)| k == key).map(|(_, v)| v.clone()).collect()
}
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::session::AdminUser;
use crate::AppState;

fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    if uri.is_empty() {
        return Err("Redirect URI is required".into());
    }
    let lower = uri.to_lowercase();
    if !lower.starts_with("https://") && !lower.starts_with("http://") {
        return Err("Redirect URI must use http:// or https:// scheme".into());
    }
    if lower.contains("..") || lower.contains("\\") {
        return Err("Redirect URI contains invalid characters".into());
    }
    Ok(())
}

#[cfg(test)]
mod redirect_uri_tests {
    use super::*;

    #[test]
    fn valid_https() {
        assert!(validate_redirect_uri("https://example.com/cb").is_ok());
    }

    #[test]
    fn valid_http() {
        assert!(validate_redirect_uri("http://localhost:8080/cb").is_ok());
    }

    #[test]
    fn rejects_javascript_scheme() {
        assert!(validate_redirect_uri("javascript://alert(1)").is_err());
    }

    #[test]
    fn rejects_mixed_case_javascript() {
        assert!(validate_redirect_uri("JavaScript://alert(1)").is_err());
    }

    #[test]
    fn rejects_data_scheme() {
        assert!(validate_redirect_uri("data:text/html,<h1>hi</h1>").is_err());
    }

    #[test]
    fn rejects_ftp_scheme() {
        assert!(validate_redirect_uri("ftp://example.com").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_redirect_uri("").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_redirect_uri("https://example.com/../secret").is_err());
    }

    #[test]
    fn rejects_backslash() {
        assert!(validate_redirect_uri("https://example.com\\@evil.com").is_err());
    }

    #[test]
    fn accepts_mixed_case_http() {
        assert!(validate_redirect_uri("HTTP://localhost/cb").is_ok());
        assert!(validate_redirect_uri("HTTPS://example.com/cb").is_ok());
    }
}

pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let users = state.users.list().await?;
    let active_users = state.sessions.count_active_users().await.unwrap_or(0);
    let locked_users = state.account_lockout.locked_count();
    let mut ctx = state.context();
    ctx.insert("user_count", &users.len());
    ctx.insert("active_users", &active_users);
    ctx.insert("locked_users", &locked_users);
    ctx.insert("active_page", "dashboard");
    ctx.insert("csrf_token", &csrf.form_token);
    let rendered = state.tera.render("admin/dashboard.html", &ctx)?;

    Ok(Html(rendered).into_response())
}

pub async fn users_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let users = state.users.list().await?;
    let mut ctx = state.context();
    ctx.insert("users", &users);
    ctx.insert("active_page", "users");
    ctx.insert("csrf_token", &csrf.form_token);
    let rendered = state.tera.render("admin/users.html", &ctx)?;

    Ok(Html(rendered).into_response())
}

pub async fn user_create_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let mut ctx = state.context();
    ctx.insert("error", &false);
    ctx.insert("active_page", "create");
    ctx.insert("csrf_token", &csrf.form_token);
    ctx.insert("form_email", &"");
    ctx.insert("form_display_name", &"");
    ctx.insert("available_roles", &state.config.roles);
    ctx.insert("form_roles", &Vec::<String>::new());
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

    if let Err(msg) = validate_password(&pw, &state.i18n) {
        let mut ctx = state.context();
        ctx.insert("error", &true);
        ctx.insert("error_message", &msg);
        ctx.insert("active_page", "create");
        ctx.insert("csrf_token", &csrf_token);
        ctx.insert("form_email", &email);
        ctx.insert("form_display_name", &display_name.as_deref().unwrap_or(""));
        ctx.insert("available_roles", &state.config.roles);
        ctx.insert("form_roles", &roles);
        let rendered = state.tera.render("admin/user_create.html", &ctx)?;
        return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
    }

    if state.users.find_by_email(&email).await?.is_some() {
        let mut ctx = state.context();
        ctx.insert("error", &true);
        ctx.insert("error_message", &state.i18n["user_create_error_email_exists"].as_str().unwrap_or(""));
        ctx.insert("active_page", "create");
        ctx.insert("csrf_token", &csrf_token);
        ctx.insert("form_email", &email);
        ctx.insert("form_display_name", &display_name.as_deref().unwrap_or(""));
        ctx.insert("available_roles", &state.config.roles);
        ctx.insert("form_roles", &roles);
        let rendered = state.tera.render("admin/user_create.html", &ctx)?;
        return Ok((StatusCode::CONFLICT, Html(rendered)).into_response());
    }

    let id = crate::crypto::id::new_id();
    let hash = password::hash_password(&pw)?;
    let roles_str = roles.join(",");

    state
        .users
        .create(&id, &email, &hash, display_name.as_deref(), &roles_str)
        .await?;
    tracing::info!(event = "user_created", user_id = %id, email = %email, roles = %roles_str, "Admin created user");

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/admin/users".to_string())],
    )
        .into_response())
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
    let is_locked = state.account_lockout.is_locked(&user.email);

    let mut ctx = state.context();
    ctx.insert("error", &false);
    ctx.insert("active_page", "users");
    ctx.insert("csrf_token", &csrf.form_token);
    ctx.insert("user", &user);
    ctx.insert("form_display_name", &user.display_name.as_deref().unwrap_or(""));
    ctx.insert("available_roles", &state.config.roles);
    ctx.insert("form_roles", &user_roles);
    ctx.insert("is_locked", &is_locked);
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

    if !pw.is_empty() {
        if let Err(msg) = validate_password(&pw, &state.i18n) {
            let mut ctx = state.context();
            ctx.insert("error", &true);
            ctx.insert("error_message", &msg);
            ctx.insert("active_page", "users");
            ctx.insert("csrf_token", &csrf_token);
            ctx.insert("user", &user);
            ctx.insert("form_display_name", &display_name.as_deref().unwrap_or(""));
            ctx.insert("available_roles", &state.config.roles);
            ctx.insert("form_roles", &roles);
            let rendered = state.tera.render("admin/user_edit.html", &ctx)?;
            return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
        }
        let hash = password::hash_password(&pw)?;
        state.users.update_password(&id, &hash).await?;
    }

    let unlock = get_field_opt(&fields, "unlock").is_some();
    if unlock {
        state.account_lockout.clear(&user.email);
    }

    let roles_str = roles.join(",");
    state.users.update(&id, display_name.as_deref(), &roles_str).await?;
    tracing::info!(event = "user_updated", user_id = %id, roles = %roles_str, "Admin updated user");

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/admin/users".to_string())],
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
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

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/admin/users".to_string())],
    )
        .into_response())
}

pub async fn email_templates_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let templates = state.email_templates.list().await?;
    let mut ctx = state.context();
    ctx.insert("templates", &templates);
    ctx.insert("active_page", "email_templates");
    ctx.insert("csrf_token", &csrf.form_token);
    let rendered = state.tera.render("admin/email_templates.html", &ctx)?;

    Ok(Html(rendered).into_response())
}

pub async fn email_template_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(template_type): Path<String>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    use crate::models::email_template::EmailTemplateType;

    let tt = EmailTemplateType::from_str(&template_type)
        .ok_or_else(|| AppError::NotFound("Template type not found".into()))?;

    let template = state.email_templates.find_by_type(&template_type).await?
        .ok_or_else(|| AppError::NotFound("Template not found".into()))?;

    let (quill_js_hash, quill_css_hash, editor_js_hash) =
        crate::routes::static_files::email_editor_hashes();

    let mut ctx = state.context();
    ctx.insert("active_page", "email_templates");
    ctx.insert("csrf_token", &csrf.form_token);
    ctx.insert("template_type", &template_type);
    ctx.insert("subject", &template.subject);
    ctx.insert("body_html", &template.body_html);
    ctx.insert("variables", &tt.available_variables());
    ctx.insert("quill_js_hash", &quill_js_hash);
    ctx.insert("quill_css_hash", &quill_css_hash);
    ctx.insert("editor_js_hash", &editor_js_hash);
    let rendered = state.tera.render("admin/email_template_edit.html", &ctx)?;

    Ok(Html(rendered).into_response())
}

pub async fn email_template_edit_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    _admin: AdminUser,
    Path(template_type): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    use crate::models::email_template::EmailTemplateType;

    EmailTemplateType::from_str(&template_type)
        .ok_or_else(|| AppError::NotFound("Template type not found".into()))?;

    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let subject = get_field(&fields, "subject");
    let body_html = get_field(&fields, "body_html");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    if subject.is_empty() {
        return Err(AppError::BadRequest("Subject is required".into()));
    }

    state.email_templates.update(&template_type, &subject, &body_html).await?;

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/admin/email-templates".to_string())],
    )
        .into_response())
}

pub(crate) fn validate_password(password: &str, i18n: &serde_json::Value) -> Result<(), String> {
    crate::crypto::password::validate_strength(password, 10).map_err(|e| {
        i18n[e.i18n_key()].as_str().unwrap_or("").to_string()
    })
}

fn validate_client_secret(secret: &str, i18n: &serde_json::Value) -> Result<(), String> {
    crate::crypto::password::validate_strength(secret, 16).map_err(|e| {
        i18n[e.client_secret_i18n_key()].as_str().unwrap_or("").to_string()
    })
}

pub async fn clients_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let clients = state.clients.list().await?;
    let mut ctx = state.context();
    ctx.insert("clients", &clients);
    ctx.insert("active_page", "clients");
    ctx.insert("csrf_token", &csrf.form_token);
    let rendered = state.tera.render("admin/clients.html", &ctx)?;

    Ok(Html(rendered).into_response())
}

pub async fn client_create_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let mut ctx = state.context();
    ctx.insert("error", &false);
    ctx.insert("active_page", "create_client");
    ctx.insert("csrf_token", &csrf.form_token);
    ctx.insert("form_client_id", &"");
    ctx.insert("form_redirect_uri", &"http://localhost/signin-oidc");
    ctx.insert("form_post_logout_uri", &"http://localhost/signout-callback-oidc");
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

    if client_id.is_empty() {
        return render_client_create_error(&state, "Client-ID is required", &csrf_token, &client_id, &redirect_uri, &post_logout_uri);
    }

    if let Err(msg) = validate_client_secret(&client_secret, &state.i18n) {
        return render_client_create_error(&state, &msg, &csrf_token, &client_id, &redirect_uri, &post_logout_uri);
    }

    if let Err(msg) = validate_redirect_uri(&redirect_uri) {
        return render_client_create_error(&state, &msg, &csrf_token, &client_id, &redirect_uri, &post_logout_uri);
    }
    if let Some(ref plu) = post_logout_uri {
        if let Err(msg) = validate_redirect_uri(plu) {
            return render_client_create_error(&state, &msg, &csrf_token, &client_id, &redirect_uri, &post_logout_uri);
        }
    }

    if state.clients.find_by_id(&client_id).await?.is_some() {
        let msg = state.i18n["client_create_error_id_exists"].as_str().unwrap_or("");
        return render_client_create_error(&state, msg, &csrf_token, &client_id, &redirect_uri, &post_logout_uri);
    }

    let hash = password::hash_password(&client_secret)?;
    state.clients.create(&client_id, &hash, &redirect_uri, post_logout_uri.as_deref()).await?;
    tracing::info!(event = "client_created", client_id = %client_id, redirect_uri = %redirect_uri, "Admin created client");

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/admin/clients".to_string())],
    )
        .into_response())
}

fn render_client_create_error(
    state: &AppState,
    message: &str,
    csrf_token: &str,
    client_id: &str,
    redirect_uri: &str,
    post_logout_uri: &Option<String>,
) -> Result<Response, AppError> {
    let mut ctx = state.context();
    ctx.insert("error", &true);
    ctx.insert("error_message", message);
    ctx.insert("active_page", "create_client");
    ctx.insert("csrf_token", csrf_token);
    ctx.insert("form_client_id", client_id);
    ctx.insert("form_redirect_uri", redirect_uri);
    ctx.insert("form_post_logout_uri", &post_logout_uri.as_deref().unwrap_or(""));
    let rendered = state.tera.render("admin/client_create.html", &ctx)?;
    Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response())
}

pub async fn client_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(id): Path<String>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let client = state.clients.find_by_id(&id).await?
        .ok_or_else(|| AppError::NotFound("Client not found".into()))?;

    let mut ctx = state.context();
    ctx.insert("error", &false);
    ctx.insert("active_page", "clients");
    ctx.insert("csrf_token", &csrf.form_token);
    ctx.insert("client", &client);
    ctx.insert("form_redirect_uri", &client.client_redirect_uri);
    ctx.insert("form_post_logout_uri", &client.client_post_logout_redirect_uri.as_deref().unwrap_or(""));
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

    if !client_secret.is_empty() {
        if let Err(msg) = validate_client_secret(&client_secret, &state.i18n) {
            let mut ctx = state.context();
            ctx.insert("error", &true);
            ctx.insert("error_message", &msg);
            ctx.insert("active_page", "clients");
            ctx.insert("csrf_token", &csrf_token);
            ctx.insert("client", &client);
            ctx.insert("form_redirect_uri", &redirect_uri);
            ctx.insert("form_post_logout_uri", &post_logout_uri.as_deref().unwrap_or(""));
            let rendered = state.tera.render("admin/client_edit.html", &ctx)?;
            return Ok((StatusCode::BAD_REQUEST, Html(rendered)).into_response());
        }
        let hash = password::hash_password(&client_secret)?;
        state.clients.update_secret(&id, &hash).await?;
    }

    state.clients.update(&id, &redirect_uri, post_logout_uri.as_deref()).await?;
    tracing::info!(event = "client_updated", client_id = %id, redirect_uri = %redirect_uri, "Admin updated client");

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/admin/clients".to_string())],
    )
        .into_response())
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

    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/admin/clients".to_string())],
    )
        .into_response())
}
