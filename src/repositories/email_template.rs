use sqlx::SqlitePool;

use crate::i18n::Locales;
use crate::middleware::language::SUPPORTED_LANGS;
use crate::models::email_template::{EmailTemplate, EmailTemplateType};

#[derive(Clone)]
pub struct EmailTemplateRepository {
    pool: SqlitePool,
}

impl EmailTemplateRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn list_by_lang(&self, lang: &str) -> Result<Vec<EmailTemplate>, sqlx::Error> {
        sqlx::query_as::<_, EmailTemplate>(
            "SELECT * FROM email_templates WHERE lang = ? ORDER BY template_type",
        )
        .bind(lang)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn find_by_type_and_lang(
        &self,
        template_type: &str,
        lang: &str,
    ) -> Result<Option<EmailTemplate>, sqlx::Error> {
        sqlx::query_as::<_, EmailTemplate>(
            "SELECT * FROM email_templates WHERE template_type = ? AND lang = ?",
        )
        .bind(template_type)
        .bind(lang)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn update(
        &self,
        template_type: &str,
        lang: &str,
        subject: &str,
        body_html: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE email_templates SET subject = ?, body_html = ?, updated_at = datetime('now') WHERE template_type = ? AND lang = ?",
        )
        .bind(subject)
        .bind(body_html)
        .bind(template_type)
        .bind(lang)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn seed(&self, locales: &Locales) -> Result<(), sqlx::Error> {
        for lang in SUPPORTED_LANGS {
            let t = locales.get(lang);
            for tt in EmailTemplateType::all() {
                let id = crate::crypto::id::new_id();
                sqlx::query(
                    "INSERT OR IGNORE INTO email_templates (id, template_type, lang, subject, body_html) VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&id)
                .bind(tt.as_str())
                .bind(lang)
                .bind(tt.default_subject(t))
                .bind(tt.default_body_html(t))
                .execute(&self.pool)
                .await?;
            }
        }
        tracing::info!("Email templates seeded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::build_locales;

    async fn test_repo() -> (EmailTemplateRepository, Locales) {
        let pool = crate::repositories::db::init_pool("sqlite::memory:").await;
        (EmailTemplateRepository::new(pool), build_locales())
    }

    #[tokio::test]
    async fn seed_creates_all_templates() {
        let (repo, locales) = test_repo().await;
        repo.seed(&locales).await.unwrap();
        let de = repo.list_by_lang("de").await.unwrap();
        let en = repo.list_by_lang("en").await.unwrap();
        assert_eq!(de.len(), 3);
        assert_eq!(en.len(), 3);
        let types: Vec<&str> = de.iter().map(|t| t.template_type.as_str()).collect();
        assert!(types.contains(&"confirm_registration"));
        assert!(types.contains(&"change_email"));
        assert!(types.contains(&"reset_password"));
    }

    #[tokio::test]
    async fn seed_is_idempotent() {
        let (repo, locales) = test_repo().await;
        repo.seed(&locales).await.unwrap();
        repo.seed(&locales).await.unwrap();
        assert_eq!(repo.list_by_lang("de").await.unwrap().len(), 3);
        assert_eq!(repo.list_by_lang("en").await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn find_by_type_and_lang() {
        let (repo, locales) = test_repo().await;
        repo.seed(&locales).await.unwrap();
        let de = repo.find_by_type_and_lang("confirm_registration", "de").await.unwrap().unwrap();
        assert_eq!(de.template_type, "confirm_registration");
        assert_eq!(de.lang, "de");

        let en = repo.find_by_type_and_lang("confirm_registration", "en").await.unwrap().unwrap();
        assert_eq!(en.lang, "en");

        assert!(repo.find_by_type_and_lang("nonexistent", "de").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_template() {
        let (repo, locales) = test_repo().await;
        repo.seed(&locales).await.unwrap();
        repo.update("confirm_registration", "de", "Neuer Betreff", "<p>Neuer Body</p>").await.unwrap();
        let tmpl = repo.find_by_type_and_lang("confirm_registration", "de").await.unwrap().unwrap();
        assert_eq!(tmpl.subject, "Neuer Betreff");
        assert_eq!(tmpl.body_html, "<p>Neuer Body</p>");

        // EN should be unchanged
        let en = repo.find_by_type_and_lang("confirm_registration", "en").await.unwrap().unwrap();
        assert!(en.subject.contains("Confirm"));
    }
}
