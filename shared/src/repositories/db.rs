use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

pub async fn init_pool(database_uri: &str) -> SqlitePool {
    let path = database_uri.strip_prefix("sqlite:");
    if let Some(path) = path
        && let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).expect("Failed to create database directory");
    }
    #[cfg(unix)]
    if let Some(path) = path
        && std::path::Path::new(path).exists() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

    let options = SqliteConnectOptions::from_str(database_uri)
        .expect("Invalid DATABASE_URI")
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(5))
        .pragma("cache_size", "-65536")
        .pragma("mmap_size", "1073741824")
        .pragma("secure_delete", "1")
        .pragma("temp_store", "2");

    SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .expect("Failed to connect to SQLite")
}

pub async fn run_users_migrations(pool: &SqlitePool) {
    let statements = [
        "CREATE TABLE IF NOT EXISTS users (
            id              TEXT PRIMARY KEY,
            email           TEXT NOT NULL UNIQUE,
            password_hash   TEXT NOT NULL,
            display_name    TEXT,
            roles           TEXT NOT NULL DEFAULT '',
            is_confirmed    INTEGER NOT NULL DEFAULT 0,
            totp_secret     TEXT,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            last_login_at   TEXT
        )",
        "CREATE TABLE IF NOT EXISTS sessions (
            id              TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id),
            expires_at      TEXT NOT NULL,
            last_seen_at    TEXT NOT NULL DEFAULT (datetime('now')),
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS email_confirmations (
            token_hash      TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id),
            expires_at      TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS password_resets (
            token_hash      TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id),
            expires_at      TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS trusted_devices (
            token_hash      TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id),
            expires_at      TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS email_changes (
            token_hash      TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id),
            new_email       TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    ];

    for sql in &statements {
        sqlx::query(sql)
            .execute(pool)
            .await
            .expect("Failed to run users migration");
    }

    tracing::info!("Users database schema initialized");
}

pub async fn run_clients_migrations(pool: &SqlitePool) {
    let statements = [
        "CREATE TABLE IF NOT EXISTS clients (
            client_id                       TEXT PRIMARY KEY,
            client_secret_hash              TEXT NOT NULL,
            client_redirect_uri             TEXT NOT NULL,
            client_post_logout_redirect_uri TEXT,
            created_at                      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS authorization_codes (
            code            TEXT PRIMARY KEY,
            client_id       TEXT NOT NULL REFERENCES clients(client_id),
            user_id         TEXT NOT NULL,
            redirect_uri    TEXT NOT NULL,
            scope           TEXT NOT NULL DEFAULT 'openid',
            code_challenge  TEXT NOT NULL,
            nonce           TEXT,
            expires_at      TEXT NOT NULL,
            used            INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS refresh_tokens (
            token           TEXT PRIMARY KEY,
            client_id       TEXT NOT NULL REFERENCES clients(client_id),
            token_family    TEXT NOT NULL,
            user_id         TEXT NOT NULL,
            scope           TEXT NOT NULL DEFAULT 'openid',
            expires_at      TEXT NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0,
            rotated_at      TEXT,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS consent_grants (
            user_id    TEXT NOT NULL,
            client_id  TEXT NOT NULL REFERENCES clients(client_id),
            scope      TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (user_id, client_id)
        )",
    ];

    for sql in &statements {
        sqlx::query(sql)
            .execute(pool)
            .await
            .expect("Failed to run clients migration");
    }

    tracing::info!("Clients database schema initialized");
}

pub async fn run_emails_migrations(pool: &SqlitePool) {
    let statements = [
        "CREATE TABLE IF NOT EXISTS email_templates (
            id              TEXT PRIMARY KEY,
            template_type   TEXT NOT NULL,
            lang            TEXT NOT NULL DEFAULT 'de',
            subject         TEXT NOT NULL,
            body_html       TEXT NOT NULL,
            updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(template_type, lang)
        )",
        "CREATE TABLE IF NOT EXISTS email_queue (
            id              TEXT PRIMARY KEY,
            recipient       TEXT NOT NULL,
            subject         TEXT NOT NULL,
            body_html       TEXT NOT NULL,
            retry_count     INTEGER NOT NULL DEFAULT 0,
            last_error      TEXT,
            sent_on         TEXT,
            next_schedule   TEXT NOT NULL DEFAULT (datetime('now')),
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    ];

    for sql in &statements {
        sqlx::query(sql)
            .execute(pool)
            .await
            .expect("Failed to run emails migration");
    }

    tracing::info!("Emails database schema initialized");
}

pub async fn run_config_migrations(pool: &SqlitePool) {
    let statements = ["CREATE TABLE IF NOT EXISTS legal_pages (
            id              TEXT PRIMARY KEY,
            page_type       TEXT NOT NULL,
            lang            TEXT NOT NULL DEFAULT 'de',
            body_html       TEXT NOT NULL DEFAULT '',
            updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(page_type, lang)
        )"];

    for sql in &statements {
        sqlx::query(sql)
            .execute(pool)
            .await
            .expect("Failed to run config migration");
    }

    tracing::info!("Config database schema initialized");
}
