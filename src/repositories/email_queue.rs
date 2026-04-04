use sqlx::SqlitePool;

use crate::models::email_queue::QueuedEmail;

#[derive(Clone)]
pub struct EmailQueueRepository {
    pool: SqlitePool,
}

impl EmailQueueRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn enqueue(
        &self,
        recipient: &str,
        subject: &str,
        body_html: &str,
    ) -> Result<String, sqlx::Error> {
        let id = crate::crypto::id::new_id();
        sqlx::query(
            "INSERT INTO email_queue (id, recipient, subject, body_html) VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(recipient)
        .bind(subject)
        .bind(body_html)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn fetch_pending(&self, limit: i64) -> Result<Vec<QueuedEmail>, sqlx::Error> {
        sqlx::query_as::<_, QueuedEmail>(
            "SELECT * FROM email_queue WHERE sent_on IS NULL AND next_schedule <= datetime('now') ORDER BY next_schedule ASC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn mark_sent(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE email_queue SET sent_on = datetime('now') WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn count_pending(&self) -> Result<i64, sqlx::Error> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM email_queue WHERE sent_on IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    pub async fn mark_failed(
        &self,
        id: &str,
        error: &str,
        current_retry_count: i32,
    ) -> Result<(), sqlx::Error> {
        let backoff_secs = std::cmp::min(60_i64 * 2_i64.pow(current_retry_count as u32), 3600);
        let offset = format!("+{backoff_secs} seconds");
        sqlx::query(
            "UPDATE email_queue SET last_error = ?, retry_count = retry_count + 1, next_schedule = datetime('now', ?) WHERE id = ?",
        )
        .bind(error)
        .bind(&offset)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_repo() -> EmailQueueRepository {
        let pool = crate::repositories::test_helpers::make_emails_pool().await;
        EmailQueueRepository::new(pool)
    }

    #[tokio::test]
    async fn enqueue_and_fetch_pending() {
        let repo = test_repo().await;
        let id = repo.enqueue("test@example.com", "Hello", "<p>World</p>").await.unwrap();
        let pending = repo.fetch_pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].recipient, "test@example.com");
        assert_eq!(pending[0].subject, "Hello");
        assert_eq!(pending[0].body_html, "<p>World</p>");
        assert_eq!(pending[0].retry_count, 0);
        assert!(pending[0].last_error.is_none());
        assert!(pending[0].sent_on.is_none());
    }

    #[tokio::test]
    async fn mark_sent_removes_from_pending() {
        let repo = test_repo().await;
        let id = repo.enqueue("test@example.com", "Hello", "<p>World</p>").await.unwrap();
        repo.mark_sent(&id).await.unwrap();
        let pending = repo.fetch_pending(10).await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn mark_failed_applies_backoff() {
        let repo = test_repo().await;
        let id = repo.enqueue("test@example.com", "Hello", "<p>World</p>").await.unwrap();
        repo.mark_failed(&id, "connection refused", 0).await.unwrap();
        // Should not be pending anymore (next_schedule is in the future)
        let pending = repo.fetch_pending(10).await.unwrap();
        assert!(pending.is_empty());
        // Verify the record was updated
        let all = sqlx::query_as::<_, QueuedEmail>("SELECT * FROM email_queue WHERE id = ?")
            .bind(&id)
            .fetch_one(&repo.pool)
            .await
            .unwrap();
        assert_eq!(all.retry_count, 1);
        assert_eq!(all.last_error.as_deref(), Some("connection refused"));
    }

    #[tokio::test]
    async fn fetch_pending_respects_limit() {
        let repo = test_repo().await;
        for i in 0..5 {
            repo.enqueue(&format!("user{i}@example.com"), "Sub", "<p>Body</p>").await.unwrap();
        }
        let pending = repo.fetch_pending(2).await.unwrap();
        assert_eq!(pending.len(), 2);
    }
}
