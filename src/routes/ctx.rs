use std::collections::HashMap;

use serde::Serialize;

use crate::i18n::I18n;
use crate::models::{client::Client, email_template::EmailTemplate, user::User};

// ── Admin UI ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DashboardCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub user_count: usize,
    pub active_users: i64,
    pub locked_users: usize,
}

#[derive(Serialize)]
pub struct UsersListCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub users: &'a [User],
    pub locked_until: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct UserCreateCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub error: bool,
    pub error_message: &'a str,
    pub form_email: &'a str,
    pub form_display_name: &'a str,
    pub available_roles: &'a [String],
    pub form_roles: &'a [String],
}

#[derive(Serialize)]
pub struct UserEditCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub error: bool,
    pub error_message: &'a str,
    pub user: &'a User,
    pub form_display_name: &'a str,
    pub available_roles: &'a [String],
    pub form_roles: &'a [String],
    pub locked_until: Option<String>,
}

#[derive(Serialize)]
pub struct ClientsListCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub clients: &'a [Client],
}

#[derive(Serialize)]
pub struct ClientCreateCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub error: bool,
    pub error_message: &'a str,
    pub form_client_id: &'a str,
    pub form_redirect_uri: &'a str,
    pub form_post_logout_uri: &'a str,
}

#[derive(Serialize)]
pub struct ClientEditCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub error: bool,
    pub error_message: &'a str,
    pub client: &'a Client,
    pub form_redirect_uri: &'a str,
    pub form_post_logout_uri: &'a str,
}

#[derive(Serialize)]
pub struct EmailTemplatesListCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub templates: &'a [EmailTemplate],
}

#[derive(Serialize)]
pub struct EmailTemplateEditCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub template_type: &'a str,
    pub subject: &'a str,
    pub body_html: &'a str,
    pub variables: Vec<&'static str>,
    pub quill_js_hash: String,
    pub quill_css_hash: String,
    pub editor_js_hash: String,
}

// ── Auth / login ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LoginCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub error: bool,
    pub error_message: &'a str,
    pub rid: &'a str,
    pub csrf_token: &'a str,
    pub form_email: &'a str,
    pub show_imprint: bool,
    pub show_privacy: bool,
}

// ── Legal pages ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LegalCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub page_title: &'a str,
    pub content: &'a str,
}

#[derive(Serialize)]
pub struct LegalEditCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub page_type: &'a str,
    pub body_html: &'a str,
    pub quill_js_hash: String,
    pub quill_css_hash: String,
    pub editor_js_hash: String,
}

#[derive(Serialize)]
pub struct LegalListCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub pages: &'a [crate::models::legal_page::LegalPage],
}

// ── OAuth2 authorize ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AuthorizeCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub csrf_token: &'a str,
    pub response_type: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<&'a str>,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub user_email: &'a str,
}

// ── Profile ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ProfileCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub user: &'a User,
    pub user_roles: Vec<String>,
    pub csrf_token: &'a str,
    pub saved: bool,
    pub pw_saved: bool,
    pub pw_error: bool,
    pub pw_error_message: &'a str,
    pub form_display_name: &'a str,
}

// ── Error page ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ErrorCtx<'a> {
    pub t: &'a I18n,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
    pub error_message: &'a str,
}
