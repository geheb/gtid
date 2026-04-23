// scope: shared — SUPPORTED_LANGS consumed by repositories (email_template, legal_page) in addition to UI handlers
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};

pub const SUPPORTED_LANGS: &[&str] = &["de", "en"];
const DEFAULT_LANG: &str = "de";

pub struct Lang {
    pub tag: String,
}

impl<S: Send + Sync> FromRequestParts<S> for Lang {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let tag = parts
            .headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map(negotiate)
            .unwrap_or_else(|| DEFAULT_LANG.to_string());
        Ok(Lang { tag })
    }
}

fn negotiate(header: &str) -> String {
    let mut candidates: Vec<(&str, u16)> = header
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            let (lang, q) = if let Some((l, q_part)) = entry.split_once(";q=") {
                let q_val = q_part.trim().parse::<f32>().unwrap_or(0.0);
                (l.trim(), (q_val * 1000.0) as u16)
            } else {
                (entry, 1000)
            };
            let primary = lang.split('-').next().unwrap_or(lang);
            if SUPPORTED_LANGS.contains(&primary) {
                Some((primary, q))
            } else {
                None
            }
        })
        .collect();

    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    candidates
        .first()
        .map(|(lang, _)| (*lang).to_string())
        .unwrap_or_else(|| DEFAULT_LANG.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_en() {
        assert_eq!(negotiate("en"), "en");
    }

    #[test]
    fn test_negotiate_de() {
        assert_eq!(negotiate("de"), "de");
    }

    #[test]
    fn test_negotiate_en_us() {
        assert_eq!(negotiate("en-US,en;q=0.9,de;q=0.8"), "en");
    }

    #[test]
    fn test_negotiate_unsupported_fallback() {
        assert_eq!(negotiate("fr,de;q=0.5"), "de");
    }

    #[test]
    fn test_negotiate_only_unsupported() {
        assert_eq!(negotiate("fr"), "de");
    }

    #[test]
    fn test_negotiate_wildcard() {
        assert_eq!(negotiate("*"), "de");
    }

    #[test]
    fn test_negotiate_de_preferred() {
        assert_eq!(negotiate("de;q=1.0,en;q=0.5"), "de");
    }
}
