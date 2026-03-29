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
use crate::models::legal_page::LegalPageType;
use crate::routes::ctx::{LegalCtx, LegalEditCtx, LegalListCtx};
use crate::AppState;

use super::{get_field, parse_form_fields, redirect};

// ── Public routes ────────────────────────────────────────────────────────────

pub async fn imprint(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    render_public(&state, "imprint", &state.i18n.legal_imprint_title).await
}

pub async fn privacy(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    render_public(&state, "privacy", &state.i18n.legal_privacy_title).await
}

async fn render_public(state: &AppState, page_type: &str, title: &str) -> Result<Response, AppError> {
    let page = state.legal_pages.find_by_type(page_type).await?
        .ok_or_else(|| AppError::NotFound("Page not found".into()))?;

    if page.body_html.trim().is_empty() {
        return Err(AppError::NotFound("Page not found".into()));
    }

    let ctx = Context::from_serialize(LegalCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        page_title: title,
        content: &page.body_html,
    })?;
    let rendered = state.tera.render("legal.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

// ── Admin routes ─────────────────────────────────────────────────────────────

pub async fn legal_pages_list(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let pages = state.legal_pages.list().await?;
    let ctx = Context::from_serialize(LegalListCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "legal_pages",
        csrf_token: &csrf.form_token,
        pages: &pages,
    })?;
    let rendered = state.tera.render("admin/legal_pages.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn legal_page_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(page_type): Path<String>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    LegalPageType::from_str(&page_type)
        .ok_or_else(|| AppError::NotFound("Page type not found".into()))?;

    let page = state.legal_pages.find_by_type(&page_type).await?
        .ok_or_else(|| AppError::NotFound("Page not found".into()))?;

    let (quill_js_hash, quill_css_hash, editor_js_hash) =
        crate::routes::ui::static_files::email_editor_hashes();

    let ctx = Context::from_serialize(LegalEditCtx {
        t: &state.i18n,
        css_hash: &state.css_hash,
        js_hash: &state.js_hash,
        active_page: "legal_pages",
        csrf_token: &csrf.form_token,
        page_type: &page_type,
        body_html: &page.body_html,
        quill_js_hash,
        quill_css_hash,
        editor_js_hash,
    })?;
    let rendered = state.tera.render("admin/legal_page_edit.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn legal_page_edit_submit(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    _admin: AdminUser,
    Path(page_type): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    LegalPageType::from_str(&page_type)
        .ok_or_else(|| AppError::NotFound("Page type not found".into()))?;

    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let body_html = get_field(&fields, "body_html");

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest("CSRF-Token ungültig".into()));
    }

    state.legal_pages.update(&page_type, &body_html).await?;

    Ok(redirect("/admin/legal-pages"))
}
