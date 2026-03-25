use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmailTemplate {
    pub id: String,
    pub template_type: String,
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

    pub fn from_str(s: &str) -> Option<EmailTemplateType> {
        match s {
            "confirm_registration" => Some(EmailTemplateType::ConfirmRegistration),
            "change_email" => Some(EmailTemplateType::ChangeEmail),
            "reset_password" => Some(EmailTemplateType::ResetPassword),
            _ => None,
        }
    }

    pub fn default_subject(&self) -> &'static str {
        match self {
            EmailTemplateType::ConfirmRegistration => "Registrierung bestätigen",
            EmailTemplateType::ChangeEmail => "E-Mail-Adresse ändern",
            EmailTemplateType::ResetPassword => "Passwort zurücksetzen",
        }
    }

    pub fn default_body_html(&self) -> &'static str {
        match self {
            EmailTemplateType::ConfirmRegistration => {
                "<p>Hallo {{name}},</p>\
                 <p>vielen Dank für Ihre Registrierung. Bitte bestätigen Sie Ihre E-Mail-Adresse, indem Sie auf den folgenden Link klicken:</p>\
                 <p><a href=\"{{link}}\">Registrierung bestätigen</a></p>\
                 <p>Falls Sie sich nicht registriert haben, können Sie diese E-Mail ignorieren.</p>\
                 <p>Mit freundlichen Grüßen<br>Ihr GT Id Team</p>"
            }
            EmailTemplateType::ChangeEmail => {
                "<p>Hallo {{name}},</p>\
                 <p>Sie haben eine Änderung Ihrer E-Mail-Adresse angefordert. Bitte bestätigen Sie die neue Adresse, indem Sie auf den folgenden Link klicken:</p>\
                 <p><a href=\"{{link}}\">E-Mail-Adresse bestätigen</a></p>\
                 <p>Falls Sie diese Änderung nicht angefordert haben, können Sie diese E-Mail ignorieren.</p>\
                 <p>Mit freundlichen Grüßen<br>Ihr GT Id Team</p>"
            }
            EmailTemplateType::ResetPassword => {
                "<p>Hallo {{name}},</p>\
                 <p>Sie haben das Zurücksetzen Ihres Passworts angefordert. Klicken Sie auf den folgenden Link, um ein neues Passwort zu vergeben:</p>\
                 <p><a href=\"{{link}}\">Passwort zurücksetzen</a></p>\
                 <p>Falls Sie dies nicht angefordert haben, können Sie diese E-Mail ignorieren.</p>\
                 <p>Mit freundlichen Grüßen<br>Ihr GT Id Team</p>"
            }
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
