use sqlx::SqlitePool;

use crate::models::refresh_token::RefreshToken;

/// Result of attempting to use a refresh token.
pub enum RefreshResult {
    Ok(RefreshToken),
    NotFound,
    /// Token was already revoked - possible theft. Contains the token_family for cascade revocation.
    Reused(String),
}

#[derive(Clone)]
pub struct RefreshTokenRepository {
    pool: SqlitePool,
}

impl RefreshTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        token: &str,
        client_id: &str,
        user_id: &str,
        scope: &str,
        token_family: &str,
        expires_at: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "DELETE FROM refresh_tokens WHERE expires_at < datetime('now') AND revoked = 1",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "INSERT INTO refresh_tokens (token, client_id, user_id, scope, token_family, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(token)
        .bind(client_id)
        .bind(user_id)
        .bind(scope)
        .bind(token_family)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find a valid (non-revoked, non-expired) refresh token.
    pub async fn find_valid(&self, token: &str) -> Result<RefreshResult, sqlx::Error> {
        let row = sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE token = ?",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(rt) if rt.revoked == 0 && !self.is_expired(&rt.expires_at) => {
                Ok(RefreshResult::Ok(rt))
            }
            Some(rt) if rt.revoked == 1 => {
                // Already revoked - this is a reuse attempt (possible theft)
                Ok(RefreshResult::Reused(rt.token_family))
            }
            _ => Ok(RefreshResult::NotFound),
        }
    }

    pub async fn revoke(&self, token: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revoke all refresh tokens in a token family (cascade on code replay or token reuse).
    pub async fn revoke_family(&self, token_family: &str) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_family = ? AND revoked = 0",
        )
        .bind(token_family)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    fn is_expired(&self, expires_at: &str) -> bool {
        chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
            .map(|dt| dt < chrono::Utc::now().naive_utc())
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::client::ClientRepository;
    use crate::repositories::test_helpers::{future_time, make_pool};
    use crate::repositories::user::UserRepository;

    async fn setup() -> RefreshTokenRepository {
        let pool = make_pool().await;
        let users = UserRepository::new(pool.clone());
        let clients = ClientRepository::new(pool.clone());
        users.create("u1", "a@b.com", "hash", None, "").await.unwrap();
        clients.create("c1", "hash", "http://cb", None).await.unwrap();
        RefreshTokenRepository::new(pool)
    }

    #[tokio::test]
    async fn create_and_find() {
        let repo = setup().await;
        repo.create("rt1", "c1", "u1", "openid", "family1", &future_time()).await.unwrap();
        match repo.find_valid("rt1").await.unwrap() {
            RefreshResult::Ok(rt) => {
                assert_eq!(rt.token, "rt1");
                assert_eq!(rt.token_family, "family1");
            }
            _ => panic!("Expected Ok"),
        }
    }

    #[tokio::test]
    async fn revoke_single() {
        let repo = setup().await;
        repo.create("rt1", "c1", "u1", "openid", "family1", &future_time()).await.unwrap();
        repo.revoke("rt1").await.unwrap();
        match repo.find_valid("rt1").await.unwrap() {
            RefreshResult::Reused(family) => assert_eq!(family, "family1"),
            _ => panic!("Expected Reused after revoke"),
        }
    }

    #[tokio::test]
    async fn revoke_family() {
        let repo = setup().await;
        repo.create("rt1", "c1", "u1", "openid", "family1", &future_time()).await.unwrap();
        repo.create("rt2", "c1", "u1", "openid", "family1", &future_time()).await.unwrap();
        let count = repo.revoke_family("family1").await.unwrap();
        assert_eq!(count, 2);
        assert!(matches!(repo.find_valid("rt1").await.unwrap(), RefreshResult::Reused(_)));
        assert!(matches!(repo.find_valid("rt2").await.unwrap(), RefreshResult::Reused(_)));
    }

    #[tokio::test]
    async fn not_found_for_missing() {
        let repo = setup().await;
        assert!(matches!(repo.find_valid("missing").await.unwrap(), RefreshResult::NotFound));
    }
}
