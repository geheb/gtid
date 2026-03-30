use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub async fn init_pool(database_uri: &str) -> SqlitePool {
    // Ensure parent directory exists (e.g. ".db/")
    if let Some(path) = database_uri.strip_prefix("sqlite:") {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).expect("Failed to create database directory");
            }
        }
    }

    let options = SqliteConnectOptions::from_str(database_uri)
        .expect("Invalid DATABASE_URI")
        .create_if_missing(true);

    let default_parallelism = std::thread::available_parallelism()
        .map(|p| p.get() as u32)
        .unwrap_or(1);

    tracing::info!("Using max. {} sqlite connections", default_parallelism);

    let pool = SqlitePoolOptions::new()
        .max_connections(default_parallelism)
        .connect_with(options)
        .await
        .expect("Failed to connect to SQLite");

     let pragma_statements = [
        "PRAGMA foreign_keys = ON",
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA cache_size = -65536", // ~64MiB per connection
        &format!("PRAGMA threads = {}", default_parallelism),
        "PRAGMA mmap_size = 1073741824" // 1GiB, more than the current db
    ];

    for sql in &pragma_statements {
        sqlx::query(sql)
            .execute(&pool)
            .await
            .expect("Failed to run pragma statements");
    }  

    // Run schema migrations
    run_migrations(&pool).await;

    pool
}

async fn run_migrations(pool: &SqlitePool) {
    let statements = [
        "CREATE TABLE IF NOT EXISTS users (
            id              TEXT PRIMARY KEY,
            email           TEXT NOT NULL UNIQUE,
            password_hash   TEXT NOT NULL,
            display_name    TEXT,
            roles           TEXT NOT NULL DEFAULT '',
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            last_login_at   TEXT
        )",
        "CREATE TABLE IF NOT EXISTS clients (
            client_id                       TEXT PRIMARY KEY,
            client_secret_hash              TEXT NOT NULL,
            client_redirect_uri             TEXT NOT NULL,
            client_post_logout_redirect_uri TEXT,
            created_at                      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS sessions (
            id              TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id),
            expires_at      TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS authorization_codes (
            code            TEXT PRIMARY KEY,
            client_id       TEXT NOT NULL REFERENCES clients(client_id),
            user_id         TEXT NOT NULL REFERENCES users(id),
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
            user_id         TEXT NOT NULL REFERENCES users(id),
            scope           TEXT NOT NULL DEFAULT 'openid',
            expires_at      TEXT NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        "CREATE TABLE IF NOT EXISTS consent_grants (
            user_id    TEXT NOT NULL REFERENCES users(id),
            client_id  TEXT NOT NULL REFERENCES clients(client_id),
            scope      TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (user_id, client_id)
        )",
        "CREATE TABLE IF NOT EXISTS email_templates (
            id              TEXT PRIMARY KEY,
            template_type   TEXT NOT NULL,
            lang            TEXT NOT NULL DEFAULT 'de',
            subject         TEXT NOT NULL,
            body_html       TEXT NOT NULL,
            updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(template_type, lang)
        )",
        "CREATE TABLE IF NOT EXISTS legal_pages (
            id              TEXT PRIMARY KEY,
            page_type       TEXT NOT NULL,
            lang            TEXT NOT NULL DEFAULT 'de',
            body_html       TEXT NOT NULL DEFAULT '',
            updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(page_type, lang)
        )",
    ];

    for sql in &statements {
        sqlx::query(sql)
            .execute(pool)
            .await
            .expect("Failed to run migration");
    }

    tracing::info!("Database schema initialized");
}
