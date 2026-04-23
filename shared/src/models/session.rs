#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub expires_at: String,
    pub created_at: String,
}
