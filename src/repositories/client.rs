use sqlx::SqlitePool;

use crate::entities::client::Client;

#[derive(Clone)]
pub struct ClientRepository {
    pool: SqlitePool,
}

impl ClientRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        client_id: &str,
        client_secret_hash: &str,
        client_redirect_uri: &str,
        client_post_logout_redirect_uri: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO clients (client_id, client_secret_hash, client_redirect_uri, client_post_logout_redirect_uri) VALUES (?, ?, ?, ?)",
        )
        .bind(client_id)
        .bind(client_secret_hash)
        .bind(client_redirect_uri)
        .bind(client_post_logout_redirect_uri)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_by_id(&self, client_id: &str) -> Result<Option<Client>, sqlx::Error> {
        sqlx::query_as::<_, Client>("SELECT * FROM clients WHERE client_id = ?")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn list(&self) -> Result<Vec<Client>, sqlx::Error> {
        sqlx::query_as::<_, Client>("SELECT * FROM clients ORDER BY client_id")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn update(
        &self,
        client_id: &str,
        client_redirect_uri: &str,
        client_post_logout_redirect_uri: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE clients SET client_redirect_uri = ?, client_post_logout_redirect_uri = ? WHERE client_id = ?",
        )
        .bind(client_redirect_uri)
        .bind(client_post_logout_redirect_uri)
        .bind(client_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_secret(&self, client_id: &str, client_secret_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE clients SET client_secret_hash = ? WHERE client_id = ?")
            .bind(client_secret_hash)
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete(&self, client_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM consent_grants WHERE client_id = ?")
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM authorization_codes WHERE client_id = ?")
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM refresh_tokens WHERE client_id = ?")
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM clients WHERE client_id = ?")
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_repo() -> ClientRepository {
        ClientRepository::new(crate::repositories::test_helpers::make_clients_pool().await)
    }

    #[tokio::test]
    async fn create_and_find() {
        let repo = test_repo().await;
        repo.create("c1", "hash", "http://localhost/cb", None).await.unwrap();
        let client = repo.find_by_id("c1").await.unwrap().unwrap();
        assert_eq!(client.client_id, "c1");
        assert_eq!(client.client_redirect_uri, "http://localhost/cb");
        assert!(client.client_post_logout_redirect_uri.is_none());
    }

    #[tokio::test]
    async fn create_with_post_logout_uri() {
        let repo = test_repo().await;
        repo.create("c1", "hash", "http://cb", Some("http://logout"))
            .await
            .unwrap();
        let client = repo.find_by_id("c1").await.unwrap().unwrap();
        assert_eq!(client.client_post_logout_redirect_uri.as_deref(), Some("http://logout"));
    }

    #[tokio::test]
    async fn list_clients() {
        let repo = test_repo().await;
        repo.create("b-client", "h", "http://b", None).await.unwrap();
        repo.create("a-client", "h", "http://a", None).await.unwrap();
        let clients = repo.list().await.unwrap();
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].client_id, "a-client"); // ordered
    }

    #[tokio::test]
    async fn update_redirect_uri() {
        let repo = test_repo().await;
        repo.create("c1", "h", "http://old", None).await.unwrap();
        repo.update("c1", "http://new", Some("http://logout")).await.unwrap();
        let client = repo.find_by_id("c1").await.unwrap().unwrap();
        assert_eq!(client.client_redirect_uri, "http://new");
        assert_eq!(client.client_post_logout_redirect_uri.as_deref(), Some("http://logout"));
    }

    #[tokio::test]
    async fn update_secret() {
        let repo = test_repo().await;
        repo.create("c1", "old_hash", "http://cb", None).await.unwrap();
        repo.update_secret("c1", "new_hash").await.unwrap();
        let client = repo.find_by_id("c1").await.unwrap().unwrap();
        assert_eq!(client.client_secret_hash, "new_hash");
    }

    #[tokio::test]
    async fn delete_client() {
        let repo = test_repo().await;
        repo.create("c1", "h", "http://cb", None).await.unwrap();
        repo.delete("c1").await.unwrap();
        assert!(repo.find_by_id("c1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn duplicate_client_id_fails() {
        let repo = test_repo().await;
        repo.create("c1", "h", "http://cb", None).await.unwrap();
        assert!(repo.create("c1", "h2", "http://cb2", None).await.is_err());
    }
}
