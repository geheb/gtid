pub mod smtp_sender;
pub mod worker;

pub fn normalize_email(email: &str) -> String {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.rsplit_once('@') else {
        return trimmed.to_lowercase();
    };
    let local = local.to_lowercase();
    let ascii_domain = idna::domain_to_ascii(domain).unwrap_or_else(|_| domain.to_lowercase());
    format!("{local}@{ascii_domain}")
}

pub fn render_email_template(
    template: Option<&crate::entities::email_template::EmailTemplate>,
    name: &str,
    link: &str,
    default_subject: &str,
    default_body: &str,
) -> (String, String) {
    match template {
        Some(tmpl) => {
            let body = tmpl.body_html.replace("{{name}}", name).replace("{{link}}", link);
            let subject = tmpl.subject.replace("{{name}}", name);
            (subject, body)
        }
        None => {
            let subject = default_subject.replace("{{name}}", name);
            let body = default_body.replace("{{name}}", name).replace("{{link}}", link);
            (subject, body)
        }
    }
}

pub async fn enqueue_confirmation_email(
    state: &crate::AppStateCore,
    user_id: &str,
    email: &str,
    display_name: Option<&str>,
    lang: &str,
) {
    let expiry_hours = state.config.email_confirm_token_expiry_hours;
    let expires_at = match chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(expiry_hours as i64))
    {
        Some(t) => crate::datetime::SqliteDateTimeExt::to_sqlite(&t),
        None => return,
    };

    if let Err(e) = state.confirmation_tokens.delete_by_user_id(user_id).await {
        tracing::error!("Failed to delete old confirmation tokens: {e}");
    }
    let token = match state.confirmation_tokens.create(user_id, &expires_at).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(event = "confirmation_token_failed", error = %e, "Failed to create confirmation token");
            return;
        }
    };

    let link = format!("{}/confirm-email?token={}", state.config.public_ui_uri, token);
    let name = display_name.unwrap_or(email);

    let template = state
        .email_templates
        .find_by_type_and_lang("confirm_registration", lang)
        .await
        .ok()
        .flatten();

    let t = state.locales.get(lang);
    let (subject, body_html) = render_email_template(
        template.as_ref(),
        name,
        &link,
        &t.email_default_confirm_registration_subject,
        &t.email_default_confirm_registration_body,
    );

    if let Err(e) = state.email_queue.enqueue(email, &subject, &body_html).await {
        tracing::error!(event = "confirmation_email_failed", error = %e, "Failed to enqueue confirmation email");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_email_lowercases() {
        assert_eq!(normalize_email("User@Example.COM"), "user@example.com");
    }

    #[test]
    fn normalize_email_trims() {
        assert_eq!(normalize_email("  user@example.com  "), "user@example.com");
    }

    #[test]
    fn normalize_email_punycode_domain() {
        assert_eq!(normalize_email("user@müller.de"), "user@xn--mller-kva.de");
    }

    #[test]
    fn normalize_email_punycode_domain_punnycode() {
        assert_eq!(normalize_email("user@xn--mller-kva.de"), "user@xn--mller-kva.de");
    }

    #[test]
    fn normalize_email_punycode_mixed_case() {
        assert_eq!(normalize_email("User@Müller.DE"), "user@xn--mller-kva.de");
    }

    #[test]
    fn normalize_email_ascii_domain_unchanged() {
        assert_eq!(normalize_email("test@example.com"), "test@example.com");
    }

    #[test]
    fn normalize_email_no_at_sign() {
        assert_eq!(normalize_email("invalid"), "invalid");
    }

    #[test]
    fn normalize_email_umlaut_local_part() {
        assert_eq!(normalize_email("müller@example.com"), "müller@example.com");
    }

    #[test]
    fn render_email_template_with_template() {
        let tmpl = crate::entities::email_template::EmailTemplate {
            id: "t1".into(),
            template_type: "confirm_registration".into(),
            lang: "de".into(),
            subject: "Hallo {{name}}".into(),
            body_html: "<p>Klicke <a href=\"{{link}}\">hier</a>, {{name}}</p>".into(),
            updated_at: "2024-01-01".into(),
        };
        let (subject, body) = render_email_template(Some(&tmpl), "Max", "https://example.com/confirm", "Default Subject", "<p>Default Body</p>");
        assert_eq!(subject, "Hallo Max");
        assert_eq!(body, "<p>Klicke <a href=\"https://example.com/confirm\">hier</a>, Max</p>");
    }

    #[test]
    fn render_email_template_without_template() {
        let (subject, body) = render_email_template(None, "Max", "https://example.com/confirm", "Hallo {{name}}", "<p>Klicke <a href=\"{{link}}\">hier</a>, {{name}}</p>");
        assert_eq!(subject, "Hallo Max");
        assert_eq!(body, "<p>Klicke <a href=\"https://example.com/confirm\">hier</a>, Max</p>");
    }

    #[test]
    fn render_email_template_no_link_placeholder() {
        let tmpl = crate::entities::email_template::EmailTemplate {
            id: "t2".into(),
            template_type: "reset_password".into(),
            lang: "en".into(),
            subject: "Reset for {{name}}".into(),
            body_html: "<p>Hello {{name}}, your code is 1234</p>".into(),
            updated_at: "2024-01-01".into(),
        };
        let (subject, body) = render_email_template(Some(&tmpl), "Anna", "https://example.com/reset", "Default", "<p>Default</p>");
        assert_eq!(subject, "Reset for Anna");
        assert_eq!(body, "<p>Hello Anna, your code is 1234</p>");
    }
}
