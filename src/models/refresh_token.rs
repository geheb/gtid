#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub token_family: String,
    pub expires_at: String,
    pub revoked: i32,
    pub created_at: String,
}
