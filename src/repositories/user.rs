use sqlx::SqlitePool;

use crate::models::user::User;

#[derive(Clone)]
pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        id: &str,
        email: &str,
        password_hash: &str,
        display_name: Option<&str>,
        roles: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, display_name, roles) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(email)
        .bind(password_hash)
        .bind(display_name)
        .bind(roles)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn list(&self) -> Result<Vec<User>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY display_name")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn update(
        &self,
        id: &str,
        display_name: Option<&str>,
        roles: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET display_name = ?, roles = ? WHERE id = ?")
            .bind(display_name)
            .bind(roles)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_password(
        &self,
        id: &str,
        password_hash: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_display_name(
        &self,
        id: &str,
        display_name: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET display_name = ? WHERE id = ?")
            .bind(display_name)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_last_login(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET last_login_at = datetime('now') WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM authorization_codes WHERE user_id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_repo() -> UserRepository {
        UserRepository::new(crate::repositories::test_helpers::make_pool().await)
    }

    #[tokio::test]
    async fn create_and_find_by_email() {
        let repo = test_repo().await;
        repo.create("u1", "a@b.com", "hash", Some("Alice"), "member").await.unwrap();
        let user = repo.find_by_email("a@b.com").await.unwrap().unwrap();
        assert_eq!(user.id, "u1");
        assert_eq!(user.email, "a@b.com");
        assert_eq!(user.display_name.as_deref(), Some("Alice"));
    }

    #[tokio::test]
    async fn find_by_id() {
        let repo = test_repo().await;
        repo.create("u1", "a@b.com", "hash", None, "").await.unwrap();
        assert!(repo.find_by_id("u1").await.unwrap().is_some());
        assert!(repo.find_by_id("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_users() {
        let repo = test_repo().await;
        repo.create("u1", "a@b.com", "h", Some("Alice"), "").await.unwrap();
        repo.create("u2", "b@b.com", "h", Some("Bob"), "").await.unwrap();
        let users = repo.list().await.unwrap();
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn update_user() {
        let repo = test_repo().await;
        repo.create("u1", "a@b.com", "h", None, "").await.unwrap();
        repo.update("u1", Some("New Name"), "admin").await.unwrap();
        let user = repo.find_by_id("u1").await.unwrap().unwrap();
        assert_eq!(user.display_name.as_deref(), Some("New Name"));
        assert_eq!(user.roles, "admin");
    }

    #[tokio::test]
    async fn update_password() {
        let repo = test_repo().await;
        repo.create("u1", "a@b.com", "old_hash", None, "").await.unwrap();
        repo.update_password("u1", "new_hash").await.unwrap();
        let user = repo.find_by_id("u1").await.unwrap().unwrap();
        assert_eq!(user.password_hash, "new_hash");
    }

    #[tokio::test]
    async fn delete_user() {
        let repo = test_repo().await;
        repo.create("u1", "a@b.com", "h", None, "").await.unwrap();
        repo.delete("u1").await.unwrap();
        assert!(repo.find_by_id("u1").await.unwrap().is_none());
    }
}
