use sqlx::SqlitePool;

use crate::models::session::Session;

#[derive(Clone)]
pub struct SessionRepository {
    pool: SqlitePool,
}

impl SessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        id: &str,
        user_id: &str,
        expires_at: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE expires_at < datetime('now')")
            .execute(&self.pool)
            .await?;

        sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
            .bind(id)
            .bind(user_id)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn find_valid(&self, id: &str) -> Result<Option<Session>, sqlx::Error> {
        sqlx::query_as::<_, Session>(
            "SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn count_active_users(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(DISTINCT user_id) FROM sessions WHERE expires_at > datetime('now')")
            .fetch_one(&self.pool)
            .await
    }

    pub async fn delete(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_by_user_id(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::test_helpers::{future_time, make_users_pool, past_time};
    use crate::repositories::user::UserRepository;

    async fn setup() -> (SessionRepository, UserRepository) {
        let pool = make_users_pool().await;
        let users = UserRepository::new(pool.clone());
        users.create("u1", "a@b.com", "hash", None, "", true).await.unwrap();
        (SessionRepository::new(pool), users)
    }

    #[tokio::test]
    async fn create_and_find_valid() {
        let (repo, _) = setup().await;
        repo.create("s1", "u1", &future_time()).await.unwrap();
        let session = repo.find_valid("s1").await.unwrap().unwrap();
        assert_eq!(session.user_id, "u1");
    }

    #[tokio::test]
    async fn expired_session_not_found() {
        let (repo, _) = setup().await;
        repo.create("s1", "u1", &past_time()).await.unwrap();
        assert!(repo.find_valid("s1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_session() {
        let (repo, _) = setup().await;
        repo.create("s1", "u1", &future_time()).await.unwrap();
        repo.delete("s1").await.unwrap();
        assert!(repo.find_valid("s1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_by_user_id() {
        let (repo, _) = setup().await;
        repo.create("s1", "u1", &future_time()).await.unwrap();
        repo.create("s2", "u1", &future_time()).await.unwrap();
        repo.delete_by_user_id("u1").await.unwrap();
        assert!(repo.find_valid("s1").await.unwrap().is_none());
        assert!(repo.find_valid("s2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn count_active_users() {
        let (repo, users) = setup().await;
        users.create("u2", "b@b.com", "hash", None, "", true).await.unwrap();
        repo.create("s1", "u1", &future_time()).await.unwrap();
        repo.create("s2", "u2", &future_time()).await.unwrap();
        repo.create("s3", "u1", &future_time()).await.unwrap(); // same user, different session
        assert_eq!(repo.count_active_users().await.unwrap(), 2);
    }
}
