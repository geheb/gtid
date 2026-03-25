use std::collections::HashSet;

use sqlx::SqlitePool;

#[derive(Clone)]
pub struct ConsentRepository {
    pool: SqlitePool,
}

impl ConsentRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Checks whether a consent grant exists for user+client that covers all requested scopes.
    pub async fn has_grant(
        &self,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<bool, sqlx::Error> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT scope FROM consent_grants WHERE user_id = ? AND client_id = ?",
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some((stored_scope,)) = row else {
            return Ok(false);
        };

        let stored: HashSet<&str> = stored_scope.split_whitespace().collect();
        let requested: HashSet<&str> = scope.split_whitespace().collect();
        Ok(requested.is_subset(&stored))
    }

    /// Saves or updates a consent grant (INSERT OR REPLACE).
    pub async fn save_grant(
        &self,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT OR REPLACE INTO consent_grants (user_id, client_id, scope) VALUES (?, ?, ?)",
        )
        .bind(user_id)
        .bind(client_id)
        .bind(scope)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::client::ClientRepository;
    use crate::repositories::user::UserRepository;

    async fn setup() -> ConsentRepository {
        let pool = crate::repositories::db::init_pool("sqlite::memory:").await;
        let users = UserRepository::new(pool.clone());
        let clients = ClientRepository::new(pool.clone());
        users.create("u1", "a@b.com", "hash", None, "").await.unwrap();
        clients.create("c1", "hash", "http://cb", None).await.unwrap();
        ConsentRepository::new(pool)
    }

    #[tokio::test]
    async fn grant_and_check() {
        let repo = setup().await;
        repo.save_grant("u1", "c1", "openid email").await.unwrap();
        assert!(repo.has_grant("u1", "c1", "openid").await.unwrap());
        assert!(repo.has_grant("u1", "c1", "openid email").await.unwrap());
    }

    #[tokio::test]
    async fn no_grant_returns_false() {
        let repo = setup().await;
        assert!(!repo.has_grant("u1", "c1", "openid").await.unwrap());
    }

    #[tokio::test]
    async fn scope_superset_rejected() {
        let repo = setup().await;
        repo.save_grant("u1", "c1", "openid").await.unwrap();
        assert!(!repo.has_grant("u1", "c1", "openid email").await.unwrap());
    }

    #[tokio::test]
    async fn update_grant_replaces_scope() {
        let repo = setup().await;
        repo.save_grant("u1", "c1", "openid").await.unwrap();
        repo.save_grant("u1", "c1", "openid email profile").await.unwrap();
        assert!(repo.has_grant("u1", "c1", "openid email profile").await.unwrap());
    }
}
