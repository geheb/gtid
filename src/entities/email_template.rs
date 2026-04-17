use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmailTemplate {
    pub id: String,
    pub template_type: String,
    pub lang: String,
    pub subject: String,
    pub body_html: String,
    pub updated_at: String,
}
