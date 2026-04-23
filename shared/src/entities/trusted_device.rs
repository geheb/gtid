#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TrustedDevice {
    pub token_hash: String,
    pub user_id: String,
    pub expires_at: String,
    pub created_at: String,
}
