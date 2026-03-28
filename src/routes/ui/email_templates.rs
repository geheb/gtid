use axum::{
    body::Bytes,
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;
use tera::Context;
use tower_cookies::Cookies;

use crate::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::session::AdminUser;
use crate::models::email_template::EmailTemplateType;
use crate::routes::ctx::{EmailTemplateEditCtx, EmailTemplatesListCtx};
use crate::AppState;

use super::{get_field, parse_form_fields, redirect};

pub async fn email_templates_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let templates = state.email_templates.list().await?;
    let ctx = Context::from_serialize(EmailTemplatesListCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "email_templates",
        csrf_token: &csrf.form_token,
        templates: &templates,
    })?;
    let rendered = state.tera.render("admin/email_templates.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn email_template_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(template_type): Path<String>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let tt = EmailTemplateType::from_str(&template_type)
        .ok_or_else(|| AppError::NotFound("Template type not found".into()))?;

    let template = state.email_templates.find_by_type(&template_type).await?
        .ok_or_else(|| AppError::NotFound("Template not found".into()))?;

    let (quill_js_hash, quill_css_hash, editor_js_hash) =
        crate::routes::ui::static_files::email_editor_hashes();

    let ctx = Context::from_serialize(EmailTemplateEditCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "email_templates",
        csrf_token: &csrf.form_token,
        template_type: &template_type,
        subject: &template.subject,
        body_html: &template.body_html,
        variables: tt.available_variables(),
        quill_js_hash,
        quill_css_hash,
        editor_js_hash,
    })?;
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

    Ok(redirect("/admin/email-templates"))
}
