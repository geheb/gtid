use sqlx::SqlitePool;

use crate::entities::authorization_code::{AuthorizationCode, NewAuthorizationCode};

pub enum ConsumeResult {
    Ok(AuthorizationCode),
    NotFound,
    Replayed(AuthorizationCode),
}

#[derive(Clone)]
pub struct AuthCodeRepository {
    pool: SqlitePool,
}

impl AuthCodeRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, ac: &NewAuthorizationCode<'_>) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, nonce, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(ac.code)
        .bind(ac.client_id)
        .bind(ac.user_id)
        .bind(ac.redirect_uri)
        .bind(ac.scope)
        .bind(ac.code_challenge)
        .bind(ac.nonce)
        .bind(ac.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically consume a code: mark as used and return it only if it was unused and not expired.
    /// Returns Replayed if the code was already used (indicates a replay attack).
    pub async fn consume(&self, code: &str) -> Result<ConsumeResult, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE authorization_codes SET used = 1 WHERE code = ? AND used = 0 AND expires_at > datetime('now')",
        )
        .bind(code)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            let auth_code = sqlx::query_as::<_, AuthorizationCode>("SELECT * FROM authorization_codes WHERE code = ?")
                .bind(code)
                .fetch_optional(&self.pool)
                .await?;
            return match auth_code {
                Some(ac) => Ok(ConsumeResult::Ok(ac)),
                None => Ok(ConsumeResult::NotFound),
            };
        }

        // Code was not consumed - check if it exists and was already used (replay)
        let existing = sqlx::query_as::<_, AuthorizationCode>("SELECT * FROM authorization_codes WHERE code = ?")
            .bind(code)
            .fetch_optional(&self.pool)
            .await?;

        match existing {
            Some(ac) if ac.used == 1 => Ok(ConsumeResult::Replayed(ac)),
            _ => Ok(ConsumeResult::NotFound),
        }
    }

    pub async fn delete_expired(&self) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM authorization_codes WHERE expires_at < datetime('now')")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_by_user_id(&self, user_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM authorization_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::client::ClientRepository;
    use crate::repositories::test_helpers::{future_time, make_clients_pool, past_time};

    async fn setup() -> (AuthCodeRepository, ClientRepository) {
        let pool = make_clients_pool().await;
        let clients = ClientRepository::new(pool.clone());
        let auth_codes = AuthCodeRepository::new(pool);
        clients.create("c1", "hash", "http://cb", None).await.unwrap();
        (auth_codes, clients)
    }

    fn new_ac<'a>(code: &'a str, expires_at: &'a str) -> NewAuthorizationCode<'a> {
        NewAuthorizationCode {
            code,
            client_id: "c1",
            user_id: "u1",
            redirect_uri: "http://cb",
            scope: "openid",
            code_challenge: "chall",
            nonce: None,
            expires_at,
        }
    }

    #[tokio::test]
    async fn create_and_consume() {
        let (repo, _) = setup().await;
        repo.create(&new_ac("code1", &future_time())).await.unwrap();
        match repo.consume("code1").await.unwrap() {
            ConsumeResult::Ok(ac) => assert_eq!(ac.code, "code1"),
            other => panic!("Expected Ok, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[tokio::test]
    async fn replay_detected() {
        let (repo, _) = setup().await;
        repo.create(&new_ac("code1", &future_time())).await.unwrap();
        // First consume succeeds
        assert!(matches!(repo.consume("code1").await.unwrap(), ConsumeResult::Ok(_)));
        // Second consume is replay
        assert!(matches!(
            repo.consume("code1").await.unwrap(),
            ConsumeResult::Replayed(_)
        ));
    }

    #[tokio::test]
    async fn unknown_code_not_found() {
        let (repo, _) = setup().await;
        assert!(matches!(
            repo.consume("nonexistent").await.unwrap(),
            ConsumeResult::NotFound
        ));
    }

    #[tokio::test]
    async fn delete_expired_cleans_old() {
        let (repo, _) = setup().await;
        repo.create(&new_ac("code_old", &past_time())).await.unwrap();
        repo.create(&new_ac("code_new", &future_time())).await.unwrap();
        repo.delete_expired().await.unwrap();
        assert!(matches!(repo.consume("code_old").await.unwrap(), ConsumeResult::NotFound));
        assert!(matches!(repo.consume("code_new").await.unwrap(), ConsumeResult::Ok(_)));
    }

    #[tokio::test]
    async fn expired_code_not_found() {
        let (repo, _) = setup().await;
        repo.create(&new_ac("code1", &past_time())).await.unwrap();
        assert!(matches!(repo.consume("code1").await.unwrap(), ConsumeResult::NotFound));
    }
}
