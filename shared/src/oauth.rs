//! OIDC/OAuth helpers shared between the API and UI crates.
//!
//! These helpers are used by both the token endpoint (API) and the
//! authorize/consent screens (UI), so they live in `shared` to avoid forcing
//! a dependency from `ui` to `api`.

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

pub const SUPPORTED_SCOPES: &[&str] = &["openid", "profile", "email"];

pub fn validate_scope(scope: &str, lang: &str) -> Result<(), String> {
    for part in scope.split_whitespace() {
        if !SUPPORTED_SCOPES.contains(&part) {
            return Err(rust_i18n::t!("error_unsupported_scope", locale = lang).to_string());
        }
    }
    if !scope.split_whitespace().any(|s| s == "openid") {
        return Err(rust_i18n::t!("error_scope_must_include_openid", locale = lang).to_string());
    }
    Ok(())
}

pub fn urlencoding(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_special_chars() {
        assert_eq!(urlencoding("hello world"), "hello%20world");
        assert_eq!(urlencoding("a+b=c"), "a%2Bb%3Dc");
        assert_eq!(urlencoding("test"), "test");
    }

    #[test]
    fn validate_scope_ok() {
        assert!(validate_scope("openid", "en").is_ok());
        assert!(validate_scope("openid email", "en").is_ok());
        assert!(validate_scope("openid email profile", "en").is_ok());
    }

    #[test]
    fn validate_scope_missing_openid() {
        assert!(validate_scope("email profile", "en").is_err());
    }

    #[test]
    fn validate_scope_unsupported() {
        assert!(validate_scope("openid admin", "en").is_err());
    }
}
