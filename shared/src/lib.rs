rust_i18n::i18n!("locales");

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub mod config;
pub mod crypto;
pub mod datetime;
pub mod email;
pub mod errors;
pub mod i18n;
pub mod limits;
pub mod middleware;
pub mod entities;
pub mod oauth;
pub mod repositories;
pub mod routes;

use config::AppConfig;
use middleware::bot_trap::BotTrap;
use middleware::rate_limit::LoginRateLimiter;
use repositories::auth_code::AuthCodeRepository;
use repositories::client::ClientRepository;
use repositories::consent::ConsentRepository;
use repositories::email_change::EmailChangeRepository;
use repositories::email_confirmation_token::EmailConfirmationTokenRepository;
use repositories::email_template::EmailTemplateRepository;
use repositories::legal_page::LegalPageRepository;
use repositories::password_reset_token::PasswordResetTokenRepository;
use repositories::refresh_token::RefreshTokenRepository;
use repositories::session::SessionRepository;
use repositories::trusted_device::TrustedDeviceRepository;
use repositories::user::UserRepository;

/// Shared state — used by both API and UI. No HTML/template concerns.
///
/// UI-only stores (pending redirects, pending 2fa, account lockout, trusted
/// devices) live on `gtid_ui::AppState` instead of here, because the API is
/// stateless and does not need them.
#[derive(Clone)]
pub struct AppStateCore {
    pub users: UserRepository,
    pub clients: ClientRepository,
    pub sessions: SessionRepository,
    pub auth_codes: AuthCodeRepository,
    pub consents: ConsentRepository,
    pub refresh_tokens: RefreshTokenRepository,
    pub confirmation_tokens: EmailConfirmationTokenRepository,
    pub password_reset_tokens: PasswordResetTokenRepository,
    pub email_changes: EmailChangeRepository,
    pub email_templates: EmailTemplateRepository,
    pub email_queue: repositories::email_queue::EmailQueueRepository,
    pub legal_pages: LegalPageRepository,
    pub login_rate_limiter: LoginRateLimiter,
    pub bot_trap: BotTrap,
    pub key_store: Arc<crypto::keys::KeyStore>,
    pub config: AppConfig,
    pub setup_needed: Arc<AtomicBool>,
    pub setup_token: Option<String>,
}

pub fn init_user_repos(
    pool: &sqlx::SqlitePool,
) -> (
    UserRepository,
    EmailConfirmationTokenRepository,
    PasswordResetTokenRepository,
    EmailChangeRepository,
    TrustedDeviceRepository,
    SessionRepository,
) {
    (
        UserRepository::new(pool.clone()),
        EmailConfirmationTokenRepository::new(pool.clone()),
        PasswordResetTokenRepository::new(pool.clone()),
        EmailChangeRepository::new(pool.clone()),
        TrustedDeviceRepository::new(pool.clone()),
        SessionRepository::new(pool.clone()),
    )
}

pub fn init_client_repos(
    pool: &sqlx::SqlitePool,
) -> (
    ClientRepository,
    AuthCodeRepository,
    ConsentRepository,
    RefreshTokenRepository,
) {
    (
        ClientRepository::new(pool.clone()),
        AuthCodeRepository::new(pool.clone()),
        ConsentRepository::new(pool.clone()),
        RefreshTokenRepository::new(pool.clone()),
    )
}
