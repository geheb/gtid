pub mod clients;
pub mod dashboard;
pub mod email_templates;
pub mod static_files;
pub mod users;
mod helpers;

pub use clients::{client_create_form, client_create_submit, client_delete, client_edit_form, client_edit_submit, clients_list};
pub use dashboard::dashboard;
pub use email_templates::{email_template_edit_form, email_template_edit_submit, email_templates_list};
pub use users::{user_create_form, user_create_submit, user_delete, user_edit_form, user_edit_submit, users_list};

// Accessible within this module and submodules
pub(super) use helpers::{get_all, get_field, get_field_opt, parse_form_fields, redirect, validate_client_secret, validate_redirect_uri, DeleteForm};
// Also used from api::profile
pub(crate) use helpers::validate_password;
