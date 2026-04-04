pub mod clients;
pub mod confirm_email;
pub mod dashboard;
pub mod email_templates;
pub mod legal;
pub mod setup;
pub mod static_files;
pub mod users;
mod helpers;

pub use clients::{client_create_form, client_create_submit, client_delete, client_edit_form, client_edit_submit, clients_list};
pub use confirm_email::confirm_email;
pub use dashboard::dashboard;
pub use email_templates::{email_template_edit_form, email_template_edit_submit, email_templates_list};
pub use legal::{legal_pages_list, legal_page_edit_form, legal_page_edit_submit};
pub use setup::{root_redirect, setup_form, setup_submit};
pub use users::{user_create_form, user_create_submit, user_delete, user_edit_form, user_edit_submit, users_list};

// Accessible within this module and submodules
pub(super) use helpers::{get_all, get_field, get_field_opt, parse_form_fields, validate_client_secret, validate_redirect_uri, DeleteForm};
// Also used from api modules and middleware
pub(crate) use helpers::{redirect, validate_password};
