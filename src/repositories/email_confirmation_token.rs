use sqlx::SqlitePool;

use crate::models::email_confirmation_token::EmailConfirmationToken;

#[derive(Clone)]
pub struct EmailConfirmationTokenRepository {
    pool: SqlitePool,
}

impl EmailConfirmationTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        user_id: &str,
        expires_at: &str,
    ) -> Result<String, sqlx::Error> {
        let token = crate::crypto::id::new_secure_token();
        sqlx::query(
            "INSERT INTO email_confirmations (token, user_id, expires_at) VALUES (?, ?, ?)",
        )
        .bind(&token)
        .bind(user_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    pub async fn find_valid(
        &self,
        token: &str,
    ) -> Result<Option<EmailConfirmationToken>, sqlx::Error> {
        sqlx::query_as::<_, EmailConfirmationToken>(
            "SELECT * FROM email_confirmations WHERE token = ? AND expires_at > datetime('now')",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn delete_for_user(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM email_confirmations WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_repo() -> (EmailConfirmationTokenRepository, crate::repositories::user::UserRepository) {
        let pool = crate::repositories::test_helpers::make_users_pool().await;
        (
            EmailConfirmationTokenRepository::new(pool.clone()),
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
}
