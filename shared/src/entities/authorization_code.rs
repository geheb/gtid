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

pub struct NewAuthorizationCode<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub code_challenge: &'a str,
    pub nonce: Option<&'a str>,
    pub expires_at: &'a str,
}
