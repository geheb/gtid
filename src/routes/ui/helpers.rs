use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

// ── Field length limits (SECURITY.md §2) ────────────────────────────────────
pub const MAX_CSRF_TOKEN: usize = 64;      // SHA256 hex
pub const MAX_EMAIL: usize = 254;          // RFC 5321
pub const MAX_PASSWORD: usize = 256;
pub const MAX_DISPLAY_NAME: usize = 200;
pub const MAX_UUID: usize = 36;            // UUID v6 (pending_id, rid)
pub const MAX_CLIENT_ID: usize = 128;
pub const MAX_CLIENT_SECRET: usize = 256;
pub const MAX_URI: usize = 2048;           // redirect_uri, post_logout_uri
pub const MAX_SETUP_TOKEN: usize = 128;
pub const MAX_RESET_TOKEN: usize = 128;    // hex-encoded SHA256 hash input
pub const MAX_ROLE: usize = 64;
pub const MAX_SCOPE: usize = 1024;
pub const MAX_CODE_VERIFIER: usize = 128;
pub const MAX_GRANT_TYPE: usize = 32;
pub const MAX_LANG: usize = 10;
pub const MAX_SUBJECT: usize = 500;
pub const MAX_REFRESH_TOKEN: usize = 2048;

pub fn redirect(path: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, path.to_string())]).into_response()
}

pub fn parse_form_fields(body: &[u8]) -> Vec<(String, String)> {
    form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

pub fn get_field(fields: &[(String, String)], key: &str) -> String {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).unwrap_or_default()
}

pub fn get_field_opt(fields: &[(String, String)], key: &str) -> Option<String> {
    fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).filter(|v| !v.is_empty())
}

pub fn get_all(fields: &[(String, String)], key: &str) -> Vec<String> {
    fields.iter().filter(|(k, _)| k == key).map(|(_, v)| v.clone()).collect()
}

pub fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    if uri.is_empty() {
        return Err("Redirect URI is required".into());
    }
    let lower = uri.to_lowercase();
    if !lower.starts_with("https://") && !lower.starts_with("http://") {
        return Err("Redirect URI must use http:// or https:// scheme".into());
    }
    if lower.contains("..") || lower.contains("\\") {
        return Err("Redirect URI contains invalid characters".into());
    }
    Ok(())
}

pub fn validate_password(password: &str, i18n: &crate::i18n::I18n) -> Result<(), String> {
    crate::crypto::password::validate_password_strength(password)
        .map_err(|e| i18n.password_msg(e).to_string())
}

pub fn validate_client_secret(secret: &str, i18n: &crate::i18n::I18n) -> Result<(), String> {
    crate::crypto::password::validate_secret_strength(secret)
        .map_err(|e| i18n.secret_msg(e).to_string())
}

/// Normalize an email address: trim, lowercase, and convert the domain to Punycode (IDNA).
/// E.g. `User@Müller.de` → `user@xn--mller-kva.de`
pub fn normalize_email(email: &str) -> String {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.rsplit_once('@') else {
        return trimmed.to_lowercase();
    };
    let local = local.to_lowercase();
    let ascii_domain = idna::domain_to_ascii(domain).unwrap_or_else(|_| domain.to_lowercase());
    format!("{local}@{ascii_domain}")
}

/// Anonymize an email address: `thomas@example.com` → `t...s@example.com`
pub fn anonymize_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "***".to_string();
    };
    let masked = match local.len() {
        0 => "***".to_string(),
        1 => format!("{}...", &local[..1]),
        _ => format!("{}...{}", &local[..1], &local[local.len() - 1..]),
    };
    format!("{masked}@{domain}")
}

/// Render an email template by replacing `{{name}}` and `{{link}}` placeholders.
/// Falls back to the provided default subject/body when no custom template exists.
pub fn render_email_template(
    template: Option<&crate::models::email_template::EmailTemplate>,
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

#[derive(Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    pub csrf_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymize() {
        assert_eq!(anonymize_email("thomas@example.com"), "t...s@example.com");
        assert_eq!(anonymize_email("ab@test.de"), "a...b@test.de");
        assert_eq!(anonymize_email("a@test.de"), "a...@test.de");
        assert_eq!(anonymize_email("invalid"), "***");
    }

    #[test]
    fn valid_https() {
        assert!(validate_redirect_uri("https://example.com/cb").is_ok());
    }

    #[test]
    fn valid_http() {
        assert!(validate_redirect_uri("http://localhost:8080/cb").is_ok());
    }

    #[test]
    fn rejects_javascript_scheme() {
        assert!(validate_redirect_uri("javascript://alert(1)").is_err());
    }

    #[test]
    fn rejects_mixed_case_javascript() {
        assert!(validate_redirect_uri("JavaScript://alert(1)").is_err());
    }

    #[test]
    fn rejects_data_scheme() {
        assert!(validate_redirect_uri("data:text/html,<h1>hi</h1>").is_err());
    }

    #[test]
    fn rejects_ftp_scheme() {
        assert!(validate_redirect_uri("ftp://example.com").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_redirect_uri("").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_redirect_uri("https://example.com/../secret").is_err());
    }

    #[test]
    fn rejects_backslash() {
        assert!(validate_redirect_uri("https://example.com\\@evil.com").is_err());
    }

    #[test]
    fn accepts_mixed_case_http() {
        assert!(validate_redirect_uri("HTTP://localhost/cb").is_ok());
        assert!(validate_redirect_uri("HTTPS://example.com/cb").is_ok());
    }

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
}
