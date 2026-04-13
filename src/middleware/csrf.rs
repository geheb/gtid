use axum::{extract::FromRequestParts, http::request::Parts};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower_cookies::cookie::SameSite;
use tower_cookies::cookie::time::Duration;
use tower_cookies::{Cookie, Cookies};

use crate::AppState;

const CSRF_COOKIE_NAME: &str = "__csrf";
const CSRF_TOKEN_LIFETIME: i64 = 3600;

/// Double-submit cookie CSRF protection.
/// The cookie holds a random secret; the form token is SHA256("gtid-csrf:" + secret).
pub struct CsrfToken {
    pub form_token: String,
}

impl FromRequestParts<Arc<AppState>> for CsrfToken {
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

        let secret = match cookies.get(CSRF_COOKIE_NAME) {
            Some(c) if !c.value().is_empty() => c.value().to_string(),
            _ => {
                let secret = generate_secret();
                cookies.add(build_csrf_cookie(secret.clone(), state.config.secure_cookies));
                secret
            }
        };

        let form_token = compute_form_token(&secret);
        Ok(CsrfToken { form_token })
    }
}

/// Generate a fresh CSRF cookie and return the form token.
/// For use in POST handlers that re-render forms.
pub fn set_new_csrf_cookie(cookies: &Cookies, secure: bool) -> String {
    let secret = generate_secret();
    let form_token = compute_form_token(&secret);
    cookies.add(build_csrf_cookie(secret, secure));
    form_token
}

/// Verifies a submitted CSRF token against the cookie value.
pub fn verify_csrf(cookies: &Cookies, submitted_token: &str) -> bool {
    let cookie_value = match cookies.get(CSRF_COOKIE_NAME) {
        Some(c) if !c.value().is_empty() => c.value().to_string(),
        _ => return false,
    };

    let expected = compute_form_token(&cookie_value);
    crate::crypto::constant_time::constant_time_eq(expected.as_bytes(), submitted_token.as_bytes())
}

fn build_csrf_cookie(value: String, secure: bool) -> Cookie<'static> {
    let mut builder = Cookie::build((CSRF_COOKIE_NAME, value))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(CSRF_TOKEN_LIFETIME));
    if secure {
        builder = builder.secure(true);
    }
    builder.build()
}

fn generate_secret() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

fn compute_form_token(cookie_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gtid-csrf:");
    hasher.update(cookie_secret.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_form_token_deterministic() {
        let t1 = compute_form_token("secret123");
        let t2 = compute_form_token("secret123");
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn compute_form_token_different_secrets() {
        assert_ne!(compute_form_token("a"), compute_form_token("b"));
    }

    #[test]
    fn generate_secret_unique() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert_ne!(s1, s2);
        assert_eq!(s1.len(), 64); // 32 bytes hex = 64 chars
    }

    #[test]
    fn build_csrf_cookie_properties() {
        let cookie = build_csrf_cookie("val".to_string(), false);
        assert_eq!(cookie.name(), CSRF_COOKIE_NAME);
        assert_eq!(cookie.value(), "val");
        assert!(cookie.http_only().unwrap_or(false));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
        assert!(!cookie.secure().unwrap_or(false));
    }

    #[test]
    fn build_csrf_cookie_secure() {
        let cookie = build_csrf_cookie("val".to_string(), true);
        assert!(cookie.secure().unwrap_or(false));
    }
}
