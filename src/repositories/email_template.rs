use sqlx::SqlitePool;

use crate::models::email_template::{EmailTemplate, EmailTemplateType};

#[derive(Clone)]
pub struct EmailTemplateRepository {
    pool: SqlitePool,
}

impl EmailTemplateRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<EmailTemplate>, sqlx::Error> {
        sqlx::query_as::<_, EmailTemplate>(
            "SELECT * FROM email_templates ORDER BY template_type",
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn find_by_type(&self, template_type: &str) -> Result<Option<EmailTemplate>, sqlx::Error> {
        sqlx::query_as::<_, EmailTemplate>(
            "SELECT * FROM email_templates WHERE template_type = ?",
        )
        .bind(template_type)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn update(
        &self,
        template_type: &str,
        subject: &str,
        body_html: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE email_templates SET subject = ?, body_html = ?, updated_at = datetime('now') WHERE template_type = ?",
        )
        .bind(subject)
        .bind(body_html)
        .bind(template_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn seed(&self) -> Result<(), sqlx::Error> {
        for tt in EmailTemplateType::all() {
            let id = crate::crypto::id::new_id();
            sqlx::query(
                "INSERT OR IGNORE INTO email_templates (id, template_type, subject, body_html) VALUES (?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(tt.as_str())
            .bind(tt.default_subject())
            .bind(tt.default_body_html())
            .execute(&self.pool)
            .await?;
        }
        tracing::info!("Email templates seeded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_repo() -> EmailTemplateRepository {
        let pool = crate::repositories::db::init_pool("sqlite::memory:").await;
        EmailTemplateRepository::new(pool)
    }

    #[tokio::test]
    async fn seed_creates_all_templates() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        let templates = repo.list().await.unwrap();
        assert_eq!(templates.len(), 3);
        let types: Vec<&str> = templates.iter().map(|t| t.template_type.as_str()).collect();
        assert!(types.contains(&"confirm_registration"));
        assert!(types.contains(&"change_email"));
        assert!(types.contains(&"reset_password"));
    }

    #[tokio::test]
    async fn seed_is_idempotent() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        repo.seed().await.unwrap(); // second call should not fail
        assert_eq!(repo.list().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn find_by_type() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        let tmpl = repo.find_by_type("confirm_registration").await.unwrap().unwrap();
        assert_eq!(tmpl.template_type, "confirm_registration");
        assert!(!tmpl.subject.is_empty());
        assert!(repo.find_by_type("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_template() {
        let repo = test_repo().await;
        repo.seed().await.unwrap();
        repo.update("confirm_registration", "New Subject", "<p>New Body</p>").await.unwrap();
        let tmpl = repo.find_by_type("confirm_registration").await.unwrap().unwrap();
        assert_eq!(tmpl.subject, "New Subject");
        assert_eq!(tmpl.body_html, "<p>New Body</p>");
    }
}
