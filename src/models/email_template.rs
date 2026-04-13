use serde::{Deserialize, Serialize};

use crate::i18n::I18n;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmailTemplate {
    pub id: String,
    pub template_type: String,
    pub lang: String,
    pub subject: String,
    pub body_html: String,
    pub updated_at: String,
}

pub enum EmailTemplateType {
    ConfirmRegistration,
    ChangeEmail,
    ResetPassword,
}

impl EmailTemplateType {
    pub fn all() -> Vec<EmailTemplateType> {
        vec![
            EmailTemplateType::ConfirmRegistration,
            EmailTemplateType::ChangeEmail,
            EmailTemplateType::ResetPassword,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            EmailTemplateType::ConfirmRegistration => "confirm_registration",
            EmailTemplateType::ChangeEmail => "change_email",
            EmailTemplateType::ResetPassword => "reset_password",
        }
    }

    pub fn parse(s: &str) -> Option<EmailTemplateType> {
        match s {
            "confirm_registration" => Some(EmailTemplateType::ConfirmRegistration),
            "change_email" => Some(EmailTemplateType::ChangeEmail),
            "reset_password" => Some(EmailTemplateType::ResetPassword),
            _ => None,
        }
    }

    pub fn default_subject<'a>(&self, t: &'a I18n) -> &'a str {
        match self {
            EmailTemplateType::ConfirmRegistration => &t.email_default_confirm_registration_subject,
            EmailTemplateType::ChangeEmail => &t.email_default_change_email_subject,
            EmailTemplateType::ResetPassword => &t.email_default_reset_password_subject,
        }
    }

    pub fn default_body_html<'a>(&self, t: &'a I18n) -> &'a str {
        match self {
            EmailTemplateType::ConfirmRegistration => &t.email_default_confirm_registration_body,
            EmailTemplateType::ChangeEmail => &t.email_default_change_email_body,
            EmailTemplateType::ResetPassword => &t.email_default_reset_password_body,
        }
    }

    pub fn available_variables(&self) -> Vec<&'static str> {
        match self {
            EmailTemplateType::ConfirmRegistration => vec!["{{name}}", "{{link}}"],
            EmailTemplateType::ChangeEmail => vec!["{{name}}", "{{link}}"],
            EmailTemplateType::ResetPassword => vec!["{{name}}", "{{link}}"],
        }
    }
}
