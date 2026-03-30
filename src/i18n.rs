use std::collections::HashMap;

use fluent_bundle::{FluentBundle, FluentResource};
use serde::Serialize;
use unic_langid::LanguageIdentifier;

use crate::crypto::password::PasswordError;

#[derive(Debug, Clone, Serialize)]
pub struct I18n {
    pub admin_panel: String,

    pub login_title: String,
    pub login_subtitle: String,
    pub login_email_label: String,
    pub login_email_placeholder: String,
    pub login_password_label: String,
    pub login_password_placeholder: String,
    pub login_submit: String,
    pub login_error_invalid: String,
    pub login_error_rate_limited: String,
    pub login_error_account_locked: String,
    pub login_error_session_expired: String,

    pub authorize_title: String,
    pub authorize_description_prefix: String,
    pub authorize_scope_label: String,
    pub authorize_allow: String,
    pub authorize_deny: String,

    pub error_title: String,
    pub error_back_home: String,

    pub sidebar_dashboard: String,
    pub sidebar_users: String,
    pub sidebar_email_templates: String,
    pub sidebar_clients: String,
    pub sidebar_create_client: String,
    pub sidebar_create_user: String,
    pub sidebar_logout: String,

    pub email_templates_title: String,
    pub email_template_edit_title: String,
    pub email_template_type_confirm_registration: String,
    pub email_template_type_change_email: String,
    pub email_template_type_reset_password: String,
    pub email_template_subject: String,
    pub email_template_body: String,
    pub email_template_variables: String,
    pub email_template_updated: String,
    pub email_template_save: String,

    pub dashboard_title: String,
    pub dashboard_total_users: String,
    pub dashboard_active_users: String,
    pub dashboard_locked_users: String,
    pub dashboard_quick_actions: String,
    pub dashboard_manage_users: String,
    pub dashboard_manage_clients: String,
    pub dashboard_manage_email_templates: String,
    pub dashboard_manage_legal_pages: String,

    pub users_title: String,
    pub users_col_name: String,
    pub users_col_email: String,
    pub users_col_access_level: String,
    pub users_col_last_login: String,
    pub users_col_date_added: String,
    pub users_badge_admin: String,
    pub users_badge_user: String,
    pub users_delete_confirm: String,
    pub users_locked_tooltip: String,
    pub users_create_tooltip: String,

    pub user_create_title: String,
    pub user_create_email_label: String,
    pub user_create_email_placeholder: String,
    pub user_create_name_label: String,
    pub user_create_name_placeholder: String,
    pub user_create_password_label: String,
    pub user_create_password_placeholder: String,
    pub user_create_roles_label: String,
    pub user_create_submit: String,
    pub user_create_cancel: String,
    pub user_create_error_email_exists: String,

    pub user_edit_title: String,
    pub user_edit_email_label: String,
    pub user_edit_name_label: String,
    pub user_edit_name_placeholder: String,
    pub user_edit_password_label: String,
    pub user_edit_password_placeholder: String,
    pub user_edit_submit: String,
    pub user_edit_locked_notice: String,
    pub user_edit_unlock_label: String,

    pub profile_title: String,
    pub profile_email_label: String,
    pub profile_roles_label: String,
    pub profile_last_login_label: String,
    pub profile_name_label: String,
    pub profile_name_placeholder: String,
    pub profile_submit: String,
    pub profile_saved: String,
    pub profile_password_title: String,
    pub profile_password_current_label: String,
    pub profile_password_current_placeholder: String,
    pub profile_password_new_label: String,
    pub profile_password_new_placeholder: String,
    pub profile_password_confirm_label: String,
    pub profile_password_confirm_placeholder: String,
    pub profile_password_submit: String,
    pub profile_password_cancel: String,
    pub profile_password_saved: String,
    pub profile_password_error_wrong: String,
    pub profile_password_error_mismatch: String,

    pub clients_title: String,
    pub clients_col_id: String,
    pub clients_col_redirect_uri: String,
    pub clients_col_post_logout_uri: String,
    pub clients_col_date_added: String,
    pub clients_delete_confirm: String,

    pub client_create_title: String,
    pub client_create_id_label: String,
    pub client_create_id_placeholder: String,
    pub client_create_secret_label: String,
    pub client_create_secret_placeholder: String,
    pub client_create_redirect_uri_label: String,
    pub client_create_redirect_uri_placeholder: String,
    pub client_create_post_logout_uri_label: String,
    pub client_create_post_logout_uri_placeholder: String,
    pub client_create_generate_secret: String,
    pub client_create_copy_secret: String,
    pub client_create_copied: String,
    pub client_create_submit: String,
    pub client_create_cancel: String,
    pub client_create_error_id_exists: String,

    pub client_edit_title: String,
    pub client_edit_id_label: String,
    pub client_edit_secret_label: String,
    pub client_edit_secret_placeholder: String,
    pub client_edit_redirect_uri_label: String,
    pub client_edit_post_logout_uri_label: String,
    pub client_edit_submit: String,
    pub client_edit_cancel: String,

    pub password_error_too_short: String,
    pub password_error_no_uppercase: String,
    pub password_error_no_lowercase: String,
    pub password_error_too_few_digits: String,
    pub password_error_too_few_special: String,
    pub password_error_too_weak: String,

    pub secret_error_too_short: String,
    pub secret_error_no_uppercase: String,
    pub secret_error_no_lowercase: String,
    pub secret_error_too_few_digits: String,
    pub secret_error_too_few_special: String,
    pub secret_error_too_weak: String,

    pub legal_imprint_title: String,
    pub legal_privacy_title: String,
    pub legal_back: String,

    pub sidebar_legal_pages: String,
    pub legal_pages_title: String,
    pub legal_page_edit_title: String,
    pub legal_pages_col_type: String,
    pub legal_pages_col_status: String,
    pub legal_pages_status_active: String,
    pub legal_pages_status_empty: String,

    pub csrf_token_invalid: String,
    pub confirm_delete: String,
    pub copied: String,
}

impl I18n {
    pub fn password_msg(&self, e: PasswordError) -> &str {
        match e {
            PasswordError::TooShort => &self.password_error_too_short,
            PasswordError::NoUppercase => &self.password_error_no_uppercase,
            PasswordError::NoLowercase => &self.password_error_no_lowercase,
            PasswordError::TooFewDigits => &self.password_error_too_few_digits,
            PasswordError::TooFewSpecial => &self.password_error_too_few_special,
            PasswordError::TooWeak => &self.password_error_too_weak,
        }
    }

    pub fn secret_msg(&self, e: PasswordError) -> &str {
        match e {
            PasswordError::TooShort => &self.secret_error_too_short,
            PasswordError::NoUppercase => &self.secret_error_no_uppercase,
            PasswordError::NoLowercase => &self.secret_error_no_lowercase,
            PasswordError::TooFewDigits => &self.secret_error_too_few_digits,
            PasswordError::TooFewSpecial => &self.secret_error_too_few_special,
            PasswordError::TooWeak => &self.secret_error_too_weak,
        }
    }
}

#[derive(Clone)]
pub struct Locales {
    map: HashMap<String, I18n>,
}

impl Locales {
    pub fn get(&self, lang: &str) -> &I18n {
        self.map.get(lang).unwrap_or_else(|| self.map.get("de").unwrap())
    }
}

fn resolve_msg(bundle: &FluentBundle<FluentResource>, key: &str) -> Result<String, String> {
    let msg = bundle
        .get_message(key)
        .ok_or_else(|| format!("Missing Fluent message: {key}"))?;
    let pattern = msg
        .value()
        .ok_or_else(|| format!("Fluent message has no value: {key}"))?;
    let mut errors = vec![];
    let result = bundle.format_pattern(pattern, None, &mut errors);
    if !errors.is_empty() {
        return Err(format!("Fluent format errors for {key}: {errors:?}"));
    }
    Ok(result.into_owned())
}

fn build_bundle(lang: &str, ftl_source: &str) -> FluentBundle<FluentResource> {
    let langid: LanguageIdentifier = lang.parse().expect("Invalid language identifier");
    let resource =
        FluentResource::try_new(ftl_source.to_string()).expect("Failed to parse FTL resource");
    let mut bundle = FluentBundle::new(vec![langid]);
    bundle
        .add_resource(resource)
        .expect("Failed to add FTL resource to bundle");
    bundle
}

macro_rules! resolve_all {
    ($bundle:expr, $( $field:ident ),+ $(,)?) => {
        Ok(I18n {
            $( $field: resolve_msg($bundle, &stringify!($field).replace('_', "-"))?, )+
        })
    };
}

fn resolve_i18n(bundle: &FluentBundle<FluentResource>) -> Result<I18n, String> {
    resolve_all!(
        bundle,
        admin_panel,
        login_title,
        login_subtitle,
        login_email_label,
        login_email_placeholder,
        login_password_label,
        login_password_placeholder,
        login_submit,
        login_error_invalid,
        login_error_rate_limited,
        login_error_account_locked,
        login_error_session_expired,
        authorize_title,
        authorize_description_prefix,
        authorize_scope_label,
        authorize_allow,
        authorize_deny,
        error_title,
        error_back_home,
        sidebar_dashboard,
        sidebar_users,
        sidebar_email_templates,
        sidebar_clients,
        sidebar_create_client,
        sidebar_create_user,
        sidebar_logout,
        email_templates_title,
        email_template_edit_title,
        email_template_type_confirm_registration,
        email_template_type_change_email,
        email_template_type_reset_password,
        email_template_subject,
        email_template_body,
        email_template_variables,
        email_template_updated,
        email_template_save,
        dashboard_title,
        dashboard_total_users,
        dashboard_active_users,
        dashboard_locked_users,
        dashboard_quick_actions,
        dashboard_manage_users,
        dashboard_manage_clients,
        dashboard_manage_email_templates,
        dashboard_manage_legal_pages,
        users_title,
        users_col_name,
        users_col_email,
        users_col_access_level,
        users_col_last_login,
        users_col_date_added,
        users_badge_admin,
        users_badge_user,
        users_delete_confirm,
        users_locked_tooltip,
        users_create_tooltip,
        user_create_title,
        user_create_email_label,
        user_create_email_placeholder,
        user_create_name_label,
        user_create_name_placeholder,
        user_create_password_label,
        user_create_password_placeholder,
        user_create_roles_label,
        user_create_submit,
        user_create_cancel,
        user_create_error_email_exists,
        user_edit_title,
        user_edit_email_label,
        user_edit_name_label,
        user_edit_name_placeholder,
        user_edit_password_label,
        user_edit_password_placeholder,
        user_edit_submit,
        user_edit_locked_notice,
        user_edit_unlock_label,
        profile_title,
        profile_email_label,
        profile_roles_label,
        profile_last_login_label,
        profile_name_label,
        profile_name_placeholder,
        profile_submit,
        profile_saved,
        profile_password_title,
        profile_password_current_label,
        profile_password_current_placeholder,
        profile_password_new_label,
        profile_password_new_placeholder,
        profile_password_confirm_label,
        profile_password_confirm_placeholder,
        profile_password_submit,
        profile_password_cancel,
        profile_password_saved,
        profile_password_error_wrong,
        profile_password_error_mismatch,
        clients_title,
        clients_col_id,
        clients_col_redirect_uri,
        clients_col_post_logout_uri,
        clients_col_date_added,
        clients_delete_confirm,
        client_create_title,
        client_create_id_label,
        client_create_id_placeholder,
        client_create_secret_label,
        client_create_secret_placeholder,
        client_create_redirect_uri_label,
        client_create_redirect_uri_placeholder,
        client_create_post_logout_uri_label,
        client_create_post_logout_uri_placeholder,
        client_create_generate_secret,
        client_create_copy_secret,
        client_create_copied,
        client_create_submit,
        client_create_cancel,
        client_create_error_id_exists,
        client_edit_title,
        client_edit_id_label,
        client_edit_secret_label,
        client_edit_secret_placeholder,
        client_edit_redirect_uri_label,
        client_edit_post_logout_uri_label,
        client_edit_submit,
        client_edit_cancel,
        password_error_too_short,
        password_error_no_uppercase,
        password_error_no_lowercase,
        password_error_too_few_digits,
        password_error_too_few_special,
        password_error_too_weak,
        secret_error_too_short,
        secret_error_no_uppercase,
        secret_error_no_lowercase,
        secret_error_too_few_digits,
        secret_error_too_few_special,
        secret_error_too_weak,
        legal_imprint_title,
        legal_privacy_title,
        legal_back,
        sidebar_legal_pages,
        legal_pages_title,
        legal_page_edit_title,
        legal_pages_col_type,
        legal_pages_col_status,
        legal_pages_status_active,
        legal_pages_status_empty,
        csrf_token_invalid,
        confirm_delete,
        copied,
    )
}

pub fn build_locales() -> Locales {
    let de_bundle = build_bundle("de", include_str!("../locales/de/main.ftl"));
    let en_bundle = build_bundle("en", include_str!("../locales/en/main.ftl"));

    let mut map = HashMap::new();
    map.insert("de".to_string(), resolve_i18n(&de_bundle).expect("Failed to resolve German locale"));
    map.insert("en".to_string(), resolve_i18n(&en_bundle).expect("Failed to resolve English locale"));

    Locales { map }
}
