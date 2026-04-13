use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LegalPage {
    pub id: String,
    pub page_type: String,
    pub lang: String,
    pub body_html: String,
    pub updated_at: String,
}

pub enum LegalPageType {
    Imprint,
    Privacy,
}

impl LegalPageType {
    pub fn all() -> Vec<LegalPageType> {
        vec![LegalPageType::Imprint, LegalPageType::Privacy]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LegalPageType::Imprint => "imprint",
            LegalPageType::Privacy => "privacy",
        }
    }

    pub fn parse(s: &str) -> Option<LegalPageType> {
        match s {
            "imprint" => Some(LegalPageType::Imprint),
            "privacy" => Some(LegalPageType::Privacy),
            _ => None,
        }
    }
}
