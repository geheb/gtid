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
use gtid_shared::errors::AppError;
use crate::middleware::csrf::{self, CsrfToken};
use gtid_shared::middleware::language::{Lang, SUPPORTED_LANGS};
use crate::middleware::session::AdminUser;
use gtid_shared::entities::legal_page::LegalPageType;
use crate::ctx::{BaseCtx, LegalCtx, LegalEditCtx, LegalListCtx};

use super::{get_field, parse_form_fields, redirect};

#[derive(Deserialize)]
pub struct EditLangQuery {
    #[serde(default = "default_lang")]
    pub lang: String,
}

fn default_lang() -> String {
    "de".to_string()
}

// ── Public routes ────────────────────────────────────────────────────────────

pub async fn imprint(State(state): State<Arc<AppState>>, lang: Lang) -> Result<Response, AppError> {
    render_public(
        &state,
        "imprint",
        &state.locales.get(&lang.tag).legal_imprint_title,
        &lang.tag,
    )
    .await
}

pub async fn privacy(State(state): State<Arc<AppState>>, lang: Lang) -> Result<Response, AppError> {
    render_public(
        &state,
        "privacy",
        &state.locales.get(&lang.tag).legal_privacy_title,
        &lang.tag,
    )
    .await
}

async fn render_public(state: &AppState, page_type: &str, title: &str, lang: &str) -> Result<Response, AppError> {
    // Try the visitor's language first, then fall back to "de"
    let page = state
        .legal_pages
        .find_by_type_and_lang(page_type, lang)
        .await?
        .filter(|p| !p.body_html.trim().is_empty());

    let page = if let Some(p) = page {
        p
    } else if lang != "de" {
        state
            .legal_pages
            .find_by_type_and_lang(page_type, "de")
            .await?
            .filter(|p| !p.body_html.trim().is_empty())
            .ok_or_else(|| AppError::NotFound("Page not found".into()))?
    } else {
        return Err(AppError::NotFound("Page not found".into()));
    };

    let ctx = Context::from_serialize(LegalCtx {
        base: BaseCtx {
            t: state.locales.get(lang),
            lang,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
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
    lang: Lang,
) -> Result<Response, AppError> {
    let pages = state.legal_pages.list_by_lang("de").await?;
    let ctx = Context::from_serialize(LegalListCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        active_page: "legal_pages",
        csrf_token: &csrf.form_token,
        pages: &pages,
        supported_langs: SUPPORTED_LANGS,
    })?;
    let rendered = state.tera.render("admin/legal_pages.html", &ctx)?;
    Ok(Html(rendered).into_response())
}

pub async fn legal_page_edit_form(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(page_type): Path<String>,
    Query(query): Query<EditLangQuery>,
    csrf: CsrfToken,
    lang: Lang,
) -> Result<Response, AppError> {
    let edit_lang = &query.lang;

    LegalPageType::parse(&page_type).ok_or_else(|| AppError::NotFound("Page type not found".into()))?;

    if !SUPPORTED_LANGS.contains(&edit_lang.as_str()) {
        return Err(AppError::NotFound("Unsupported language".into()));
    }

    let page = state
        .legal_pages
        .find_by_type_and_lang(&page_type, edit_lang)
        .await?
        .ok_or_else(|| AppError::NotFound("Page not found".into()))?;

    let (quill_js_hash, quill_css_hash, editor_js_hash) = crate::handlers::static_files::email_editor_hashes();

    let ctx = Context::from_serialize(LegalEditCtx {
        base: BaseCtx {
            t: state.locales.get(&lang.tag),
            lang: &lang.tag,
            css_hash: &state.css_hash,
            js_hash: &state.js_hash,
        },
        active_page: "legal_pages",
        csrf_token: &csrf.form_token,
        page_type: &page_type,
        edit_lang,
        supported_langs: SUPPORTED_LANGS,
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
    lang: Lang,
    body: Bytes,
) -> Result<Response, AppError> {
    LegalPageType::parse(&page_type).ok_or_else(|| AppError::NotFound("Page type not found".into()))?;

    let fields = parse_form_fields(&body);
    let csrf_token = get_field(&fields, "csrf_token");
    let edit_lang = get_field(&fields, "edit_lang");
    let body_html = get_field(&fields, "body_html");

    validate_legal_fields(&csrf_token, &edit_lang).map_err(|e| AppError::BadRequest(e.into()))?;

    if !SUPPORTED_LANGS.contains(&edit_lang.as_str()) {
        return Err(AppError::NotFound("Unsupported language".into()));
    }

    if !csrf::verify_csrf(&cookies, &csrf_token) {
        return Err(AppError::BadRequest(
            state.locales.get(&lang.tag).csrf_token_invalid.clone(),
        ));
    }

    state.legal_pages.update(&page_type, &edit_lang, &body_html).await?;

    Ok(redirect("/admin/legal-pages"))
}

fn validate_legal_fields(csrf_token: &str, edit_lang: &str) -> Result<(), &'static str> {
    if csrf_token.len() > super::MAX_CSRF_TOKEN || edit_lang.len() > super::MAX_LANG {
        return Err("Field length exceeded");
    }
    Ok(())
}
