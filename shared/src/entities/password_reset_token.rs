use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PasswordResetToken {
    pub token_hash: String,
    pub user_id: String,
    pub expires_at: String,
    pub created_at: String,
}
