use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct QueuedEmail {
    pub id: String,
    pub recipient: String,
    pub subject: String,
    pub body_html: String,
    pub retry_count: i32,
    pub last_error: Option<String>,
    pub sent_on: Option<String>,
    pub next_schedule: String,
    pub created_at: String,
}
