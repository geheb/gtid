use sqlx::SqlitePool;

use crate::middleware::language::SUPPORTED_LANGS;
use crate::entities::legal_page::{LegalPage, LegalPageType};

#[derive(Clone)]
pub struct LegalPageRepository {
    pool: SqlitePool,
}

impl LegalPageRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn list_by_lang(&self, lang: &str) -> Result<Vec<LegalPage>, sqlx::Error> {
        sqlx::query_as::<_, LegalPage>("SELECT * FROM legal_pages WHERE lang = ? ORDER BY page_type")
            .bind(lang)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn find_by_type_and_lang(&self, page_type: &str, lang: &str) -> Result<Option<LegalPage>, sqlx::Error> {
        sqlx::query_as::<_, LegalPage>("SELECT * FROM legal_pages WHERE page_type = ? AND lang = ?")
            .bind(page_type)
            .bind(lang)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn has_any_content(&self, page_type: &str) -> Result<bool, sqlx::Error> {
        let row: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM legal_pages WHERE page_type = ? AND trim(body_html) != '' LIMIT 1")
                .bind(page_type)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }

    pub async fn update(&self, page_type: &str, lang: &str, body_html: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE legal_pages SET body_html = ?, updated_at = datetime('now') WHERE page_type = ? AND lang = ?",
        )
        .bind(body_html)
        .bind(page_type)
        .bind(lang)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn seed(&self) -> Result<(), sqlx::Error> {
        for lang in SUPPORTED_LANGS {
            for lt in LegalPageType::all() {
                let id = crate::crypto::id::new_id();
                sqlx::query("INSERT OR IGNORE INTO legal_pages (id, page_type, lang, body_html) VALUES (?, ?, ?, '')")
                    .bind(&id)
                    .bind(lt.as_str())
                    .bind(lang)
                    .execute(&self.pool)
                    .await?;
            }
        }
        tracing::info!("Legal pages seeded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_repo() -> LegalPageRepository {
        let pool = crate::repositories::test_helpers::make_config_pool().await;
        LegalPageRepository::new(pool)
    }

    #[tokio::test]
    async fn seed_creates_all_pages() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        let de = repo.list_by_lang("de").await.unwrap();
        let en = repo.list_by_lang("en").await.unwrap();
        assert_eq!(de.len(), 2);
        assert_eq!(en.len(), 2);
        let types: Vec<&str> = de.iter().map(|p| p.page_type.as_str()).collect();
        assert!(types.contains(&"imprint"));
        assert!(types.contains(&"privacy"));
    }

    #[tokio::test]
    async fn seed_is_idempotent() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        repo.seed().await.unwrap();
        assert_eq!(repo.list_by_lang("de").await.unwrap().len(), 2);
        assert_eq!(repo.list_by_lang("en").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn find_by_type_and_lang() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        let page = repo.find_by_type_and_lang("imprint", "de").await.unwrap().unwrap();
        assert_eq!(page.page_type, "imprint");
        assert_eq!(page.lang, "de");
        assert!(repo.find_by_type_and_lang("nonexistent", "de").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_page() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        repo.update("imprint", "de", "<p>Deutsches Impressum</p>")
            .await
            .unwrap();
        let de = repo.find_by_type_and_lang("imprint", "de").await.unwrap().unwrap();
        assert_eq!(de.body_html, "<p>Deutsches Impressum</p>");

        // EN should still be empty
        let en = repo.find_by_type_and_lang("imprint", "en").await.unwrap().unwrap();
        assert!(en.body_html.is_empty());
    }

    #[tokio::test]
    async fn has_any_content_works() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        assert!(!repo.has_any_content("imprint").await.unwrap());

        repo.update("imprint", "en", "<p>English imprint</p>").await.unwrap();
        assert!(repo.has_any_content("imprint").await.unwrap());
    }
}
