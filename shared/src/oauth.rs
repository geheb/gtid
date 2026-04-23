//! OIDC/OAuth helpers shared between the API and UI crates.
//!
//! These helpers are used by both the token endpoint (API) and the
//! authorize/consent screens (UI), so they live in `shared` to avoid forcing
//! a dependency from `ui` to `api`.

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

pub const SUPPORTED_SCOPES: &[&str] = &["openid", "profile", "email"];

pub fn validate_scope(scope: &str) -> Result<(), String> {
    for part in scope.split_whitespace() {
        if !SUPPORTED_SCOPES.contains(&part) {
            return Err(format!("Unsupported scope: {part}"));
        }
    }
    if !scope.split_whitespace().any(|s| s == "openid") {
        return Err("scope must include 'openid'".into());
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
        assert!(validate_scope("openid").is_ok());
        assert!(validate_scope("openid email").is_ok());
        assert!(validate_scope("openid email profile").is_ok());
    }

    #[test]
    fn validate_scope_missing_openid() {
        assert!(validate_scope("email profile").is_err());
    }

    #[test]
    fn validate_scope_unsupported() {
        assert!(validate_scope("openid admin").is_err());
    }
}
