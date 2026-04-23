use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Client {
    pub client_id: String,
    pub client_secret_hash: String,
    pub client_redirect_uri: String,
    pub client_post_logout_redirect_uri: Option<String>,
    pub created_at: String,
}
