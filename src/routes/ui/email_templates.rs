use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use tera::Context;
use tower_cookies::Cookies;

use crate::AppState;
use crate::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use crate::middleware::language::{Lang, SUPPORTED_LANGS};
use crate::middleware::session::AdminUser;
use crate::entities::email_template_type::EmailTemplateType;
use crate::routes::ctx::{BaseCtx, EmailTemplateEditCtx, EmailTemplatesListCtx};

use super::{get_field, parse_form_fields, redirect};

#[derive(Deserialize)]
pub struct EditLangQuery {
    #[serde(default = "default_lang")]
    pub lang: String,
}

fn default_lang() -> String {
    "de".to_string()
}

pub async fn email_templates_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let templates = state.email_templates.list_by_lang("de").await?;
    let ctx = Context::from_serialize(EmailTemplatesListCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        active_page: "email_templates",
        csrf_token: &csrf.form_token,
        templates: &templates,
        supported_langs: SUPPORTED_LANGS,
    })?;
    let rendered = state.tera.render("admin/email_templates.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn email_template_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(template_type): Path<String>,
    Query(query): Query<EditLangQuery>,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let edit_lang = &query.lang;

    let tt =
        EmailTemplateType::parse(&template_type).ok_or_else(|| AppError::NotFound("Template type not found".into()))?;

    if !SUPPORTED_LANGS.contains(&edit_lang.as_str()) {
        return Err(AppError::NotFound("Unsupported language".into()));
    }

    let template = state
        .email_templates
        .find_by_type_and_lang(&template_type, edit_lang)
        .await?
        .ok_or_else(|| AppError::NotFound("Template not found".into()))?;

    let (quill_js_hash, quill_css_hash, editor_js_hash) = crate::routes::ui::static_files::email_editor_hashes();

    let ctx = Context::from_serialize(EmailTemplateEditCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        active_page: "email_templates",
        csrf_token: &csrf.form_token,
        template_type: &template_type,
        edit_lang,
        supported_langs: SUPPORTED_LANGS,
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
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    EmailTemplateType::parse(&template_type).ok_or_else(|| AppError::NotFound("Template type not found".into()))?;

    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let edit_lang = get_field(&fields, "edit_lang");
    let subject = get_field(&fields, "subject");
    let body_html = get_field(&fields, "body_html");

    validate_template_fields(&csrf_token, &edit_lang, &subject).map_err(|e| AppError::BadRequest(e.into()))?;

    if !SUPPORTED_LANGS.contains(&edit_lang.as_str()) {
        return Err(AppError::NotFound("Unsupported language".into()));
    }

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    if subject.is_empty() {
        return Err(AppError::BadRequest("Subject is required".into()));
    }

    state
        .email_templates
        .update(&template_type, &edit_lang, &subject, &body_html)
        .await?;

    Ok(redirect("/admin/email-templates"))
}

fn validate_template_fields(csrf_token: &str, edit_lang: &str, subject: &str) -> Result<(), &'static str> {
    if csrf_token.len() > super::MAX_CSRF_TOKEN
        || edit_lang.len() > super::MAX_LANG
        || subject.len() > super::MAX_SUBJECT
    {
        return Err("invalid request");
    }
    Ok(())
}
