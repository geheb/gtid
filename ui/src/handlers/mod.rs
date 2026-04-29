pub(crate) mod auth;
pub(crate) mod authorize;
pub(crate) mod clients;
pub(crate) mod confirm_email;
pub(crate) mod confirm_email_change;
pub(crate) mod dashboard;
pub(crate) mod email_templates;
mod helpers;
pub(crate) mod legal;
pub(crate) mod password_reset;
pub(crate) mod profile;
pub(crate) mod setup;
pub mod static_files;
pub(crate) mod totp;
pub(crate) mod users;

pub(crate) use clients::{
    client_create_form, client_create_submit, client_delete, client_edit_form, client_edit_submit, clients_list,
};
pub(crate) use confirm_email::confirm_email;
pub(crate) use confirm_email_change::confirm_email_change;
pub(crate) use dashboard::dashboard;
pub(crate) use email_templates::{email_template_edit_form, email_template_edit_submit, email_templates_list};
pub(crate) use legal::{legal_page_edit_form, legal_page_edit_submit, legal_pages_list};
pub(crate) use password_reset::{forgot_password_form, forgot_password_submit, reset_password_form, reset_password_submit};
pub(crate) use setup::{root_redirect, setup_form, setup_submit};
pub(crate) use totp::{totp_setup_form, totp_setup_submit, totp_verify_form, totp_verify_submit};
pub(crate) use users::{
    user_create_form, user_create_submit, user_delete, user_edit_form, user_edit_submit, user_reset_2fa, users_list,
};

// Accessible within this module and submodules
pub(super) use helpers::{
    DeleteForm, get_all, get_field, get_field_opt, parse_form_fields, validate_client_secret, validate_redirect_uri,
};
// Also used from api modules and middleware
pub(crate) use helpers::{anonymize_email, normalize_email, redirect, render_email_template, validate_password};
// Field length limits (SECURITY.md §2) — used from api and ui modules
pub(crate) use helpers::{
    MAX_CLIENT_ID, MAX_CLIENT_SECRET, MAX_CSRF_TOKEN, MAX_DISPLAY_NAME, MAX_EMAIL,
    MAX_LANG, MAX_PASSWORD, MAX_RESET_TOKEN, MAX_ROLE, MAX_SCOPE, MAX_SETUP_TOKEN, MAX_SUBJECT,
    MAX_URI, MAX_UUID,
};
