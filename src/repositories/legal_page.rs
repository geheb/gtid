use sqlx::SqlitePool;

use crate::models::legal_page::{LegalPage, LegalPageType};

#[derive(Clone)]
pub struct LegalPageRepository {
    pool: SqlitePool,
}

impl LegalPageRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<LegalPage>, sqlx::Error> {
        sqlx::query_as::<_, LegalPage>(
            "SELECT * FROM legal_pages ORDER BY page_type",
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn find_by_type(&self, page_type: &str) -> Result<Option<LegalPage>, sqlx::Error> {
        sqlx::query_as::<_, LegalPage>(
            "SELECT * FROM legal_pages WHERE page_type = ?",
        )
        .bind(page_type)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn update(&self, page_type: &str, body_html: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE legal_pages SET body_html = ?, updated_at = datetime('now') WHERE page_type = ?",
        )
        .bind(body_html)
        .bind(page_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn seed(&self) -> Result<(), sqlx::Error> {
        for lt in LegalPageType::all() {
            let id = crate::crypto::id::new_id();
            sqlx::query(
                "INSERT OR IGNORE INTO legal_pages (id, page_type, body_html) VALUES (?, ?, '')",
            )
            .bind(&id)
            .bind(lt.as_str())
            .execute(&self.pool)
            .await?;
        }
        tracing::info!("Legal pages seeded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_repo() -> LegalPageRepository {
        let pool = crate::repositories::db::init_pool("sqlite::memory:").await;
        LegalPageRepository::new(pool)
    }

    #[tokio::test]
    async fn seed_creates_all_pages() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        let pages = repo.list().await.unwrap();
        assert_eq!(pages.len(), 2);
        let types: Vec<&str> = pages.iter().map(|p| p.page_type.as_str()).collect();
        assert!(types.contains(&"imprint"));
        assert!(types.contains(&"privacy"));
    }

    #[tokio::test]
    async fn seed_is_idempotent() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        repo.seed().await.unwrap();
        assert_eq!(repo.list().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn find_by_type() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        let page = repo.find_by_type("imprint").await.unwrap().unwrap();
        assert_eq!(page.page_type, "imprint");
        assert!(page.body_html.is_empty());
        assert!(repo.find_by_type("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_page() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        repo.update("imprint", "<p>Test content</p>").await.unwrap();
        let page = repo.find_by_type("imprint").await.unwrap().unwrap();
        assert_eq!(page.body_html, "<p>Test content</p>");
    }
}
