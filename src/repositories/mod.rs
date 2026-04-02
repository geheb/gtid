pub mod client;
pub mod db;
pub mod user;
pub mod session;
pub mod auth_code;
pub mod consent;
pub mod email_template;
pub mod legal_page;
pub mod refresh_token;

#[cfg(test)]
pub(super) mod test_helpers {
    pub async fn make_users_pool() -> sqlx::SqlitePool {
        let pool = crate::repositories::db::init_pool("sqlite::memory:").await;
        crate::repositories::db::run_users_migrations(&pool).await;
        pool
    }

    pub async fn make_clients_pool() -> sqlx::SqlitePool {
        let pool = crate::repositories::db::init_pool("sqlite::memory:").await;
        crate::repositories::db::run_clients_migrations(&pool).await;
        pool
    }

    pub async fn make_emails_pool() -> sqlx::SqlitePool {
        let pool = crate::repositories::db::init_pool("sqlite::memory:").await;
        crate::repositories::db::run_emails_migrations(&pool).await;
        pool
    }

    pub async fn make_config_pool() -> sqlx::SqlitePool {
        let pool = crate::repositories::db::init_pool("sqlite::memory:").await;
        crate::repositories::db::run_config_migrations(&pool).await;
        pool
    }

    pub fn future_time() -> String {
        (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }

    pub fn past_time() -> String {
        (chrono::Utc::now() - chrono::Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    }
}
