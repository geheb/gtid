use std::collections::HashMap;

use serde::Serialize;

use crate::i18n::I18n;
use crate::models::{client::Client, email_template::EmailTemplate, user::User};

// ── Base contexts ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct BaseCtx<'a> {
    pub t: &'a I18n,
    pub lang: &'a str,
    pub css_hash: &'a str,
    pub js_hash: &'a str,
}

// ── Admin UI ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DashboardCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub user_count: usize,
    pub active_users: i64,
    pub locked_users: usize,
    pub pending_emails: i64,
    pub unconfirmed_users: usize,
}

#[derive(Serialize)]
pub struct UsersListCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub users: &'a [User],
    pub locked_until: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct UserCreateCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
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
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub error: bool,
    pub error_message: &'a str,
    pub user: &'a User,
    pub form_email: &'a str,
    pub form_display_name: &'a str,
    pub available_roles: &'a [String],
    pub form_roles: &'a [String],
    pub locked_until: Option<String>,
    pub has_totp: bool,
}

#[derive(Serialize)]
pub struct ClientsListCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub clients: &'a [Client],
}

#[derive(Serialize)]
pub struct ClientCreateCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
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
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
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
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub templates: &'a [EmailTemplate],
    pub supported_langs: &'a [&'a str],
}

#[derive(Serialize)]
pub struct EmailTemplateEditCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub template_type: &'a str,
    pub edit_lang: &'a str,
    pub supported_langs: &'a [&'a str],
    pub subject: &'a str,
    pub body_html: &'a str,
    pub variables: Vec<&'static str>,
    pub quill_js_hash: String,
    pub quill_css_hash: String,
    pub editor_js_hash: String,
}

// ── Setup ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SetupCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub csrf_token: &'a str,
    pub error: bool,
    pub error_message: &'a str,
    pub form_email: &'a str,
    pub form_display_name: &'a str,
    pub form_token: &'a str,
}

// ── Auth / login ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LoginCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub error: bool,
    pub error_message: &'a str,
    pub rid: &'a str,
    pub csrf_token: &'a str,
    pub form_email: &'a str,
    pub show_imprint: bool,
    pub show_privacy: bool,
}

// ── 2FA / TOTP ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TotpSetupCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub csrf_token: &'a str,
    pub qr_data_uri: &'a str,
    pub secret_display: &'a str,
    pub pending_id: &'a str,
    pub error: bool,
    pub error_message: &'a str,
}

#[derive(Serialize)]
pub struct TotpVerifyCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub csrf_token: &'a str,
    pub pending_id: &'a str,
    pub error: bool,
    pub error_message: &'a str,
}

// ── Legal pages ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LegalCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub page_title: &'a str,
    pub content: &'a str,
}

#[derive(Serialize)]
pub struct LegalEditCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub page_type: &'a str,
    pub edit_lang: &'a str,
    pub supported_langs: &'a [&'a str],
    pub body_html: &'a str,
    pub quill_js_hash: String,
    pub quill_css_hash: String,
    pub editor_js_hash: String,
}

#[derive(Serialize)]
pub struct LegalListCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub active_page: &'a str,
    pub csrf_token: &'a str,
    pub pages: &'a [crate::models::legal_page::LegalPage],
    pub supported_langs: &'a [&'a str],
}

// ── OAuth2 authorize ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AuthorizeCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
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
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub user: &'a User,
    pub user_roles: Vec<String>,
    pub csrf_token: &'a str,
    pub saved: bool,
    pub pw_saved: bool,
    pub pw_error: bool,
    pub pw_error_message: &'a str,
    pub email_saved: bool,
    pub email_error: bool,
    pub email_error_message: &'a str,
    pub form_display_name: &'a str,
    pub has_totp: bool,
    pub is_admin: bool,
    pub totp_saved: bool,
    pub totp_error: bool,
    pub totp_error_message: &'a str,
}

// ── Confirm email change success ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct ConfirmEmailChangeSuccessCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub anonymized_email: &'a str,
}

// ── Confirm email success ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ConfirmEmailSuccessCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub anonymized_email: &'a str,
}

// ── Forgot password ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ForgotPasswordCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub csrf_token: &'a str,
    pub error: bool,
    pub error_message: &'a str,
    pub form_email: &'a str,
}

#[derive(Serialize)]
pub struct ForgotPasswordSentCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
}

// ── Reset password ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ResetPasswordCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub csrf_token: &'a str,
    pub token: &'a str,
    pub error: bool,
    pub error_message: &'a str,
}

#[derive(Serialize)]
pub struct ResetPasswordSuccessCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
}

// ── Error page ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ErrorCtx<'a> {
    #[serde(flatten)]
    pub base: BaseCtx<'a>,
    pub error_message: &'a str,
}
