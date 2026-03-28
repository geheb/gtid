pub mod client;
pub mod db;
pub mod user;
pub mod session;
pub mod auth_code;
pub mod consent;
pub mod email_template;
pub mod refresh_token;

#[cfg(test)]
pub(super) mod test_helpers {
    pub async fn make_pool() -> sqlx::SqlitePool {
        crate::repositories::db::init_pool("sqlite::memory:").await
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
