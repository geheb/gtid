#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub expires_at: String,
    pub used: i32,
    pub created_at: String,
}
