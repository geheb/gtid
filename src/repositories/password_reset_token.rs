use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::models::password_reset_token::PasswordResetToken;

#[derive(Clone)]
pub struct PasswordResetTokenRepository {
    pool: SqlitePool,
}

fn hash_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

impl PasswordResetTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        user_id: &str,
        expires_at: &str,
    ) -> Result<String, sqlx::Error> {
        // Opportunistically clean up expired tokens
        self.delete_expired().await?;

        let token = crate::crypto::id::new_secure_token();
        let token_hash = hash_token(&token);
        sqlx::query(
            "INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    pub async fn find_valid(
        &self,
        token: &str,
    ) -> Result<Option<PasswordResetToken>, sqlx::Error> {
        let token_hash = hash_token(token);
        sqlx::query_as::<_, PasswordResetToken>(
            "SELECT * FROM password_resets WHERE token_hash = ? AND expires_at > datetime('now')",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn delete_for_user(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM password_resets WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_expired(&self) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM password_resets WHERE expires_at <= datetime('now')")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_repo() -> (PasswordResetTokenRepository, crate::repositories::user::UserRepository) {
        let pool = crate::repositories::test_helpers::make_users_pool().await;
        (
            PasswordResetTokenRepository::new(pool.clone()),
            crate::repositories::user::UserRepository::new(pool),
        )
    }

    #[tokio::test]
    async fn create_and_find_valid() {
        let (repo, users) = test_repo().await;
        users.create("u1", "a@b.com", "h", None, "", true).await.unwrap();
        let expires = crate::repositories::test_helpers::future_time();
        let token = repo.create("u1", &expires).await.unwrap();
        assert_eq!(token.len(), 64);
        let found = repo.find_valid(&token).await.unwrap().unwrap();
        assert_eq!(found.user_id, "u1");
    }

    #[tokio::test]
    async fn token_stored_as_hash() {
        let (repo, users) = test_repo().await;
        users.create("u1", "a@b.com", "h", None, "", true).await.unwrap();
        let expires = crate::repositories::test_helpers::future_time();
        let token = repo.create("u1", &expires).await.unwrap();
        let found = repo.find_valid(&token).await.unwrap().unwrap();
        assert_ne!(found.token_hash, token);
        assert_eq!(found.token_hash, hash_token(&token));
    }

    #[tokio::test]
    async fn expired_token_not_found() {
        let (repo, users) = test_repo().await;
        users.create("u1", "a@b.com", "h", None, "", true).await.unwrap();
        let expires = crate::repositories::test_helpers::past_time();
        let token = repo.create("u1", &expires).await.unwrap();
        assert!(repo.find_valid(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_token_not_found() {
        let (repo, _) = test_repo().await;
        assert!(repo.find_valid("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_for_user_removes_all_tokens() {
        let (repo, users) = test_repo().await;
        users.create("u1", "a@b.com", "h", None, "", true).await.unwrap();
        let expires = crate::repositories::test_helpers::future_time();
        let t1 = repo.create("u1", &expires).await.unwrap();
        let t2 = repo.create("u1", &expires).await.unwrap();
        repo.delete_for_user("u1").await.unwrap();
        assert!(repo.find_valid(&t1).await.unwrap().is_none());
        assert!(repo.find_valid(&t2).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_expired_cleans_old_tokens() {
        let (repo, users) = test_repo().await;
        users.create("u1", "a@b.com", "h", None, "", true).await.unwrap();
        let past = crate::repositories::test_helpers::past_time();
        let future = crate::repositories::test_helpers::future_time();
        let _expired = repo.create("u1", &past).await.unwrap();
        let valid = repo.create("u1", &future).await.unwrap();
        repo.delete_expired().await.unwrap();
        assert!(repo.find_valid(&valid).await.unwrap().is_some());
    }
}
