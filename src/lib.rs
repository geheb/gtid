rust_i18n::i18n!("locales");

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use tower::Service;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

pub mod config;
pub mod crypto;
pub mod datetime;
pub mod email;
pub mod errors;
pub mod i18n;
pub mod middleware;
pub mod entities;
pub mod repositories;
pub mod routes;

use config::AppConfig;
use middleware::bot_trap::BotTrap;
use middleware::lockout::AccountLockout;
use middleware::pending_2fa::Pending2faStore;
use middleware::pending_redirect::PendingRedirectStore;
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
    pub trusted_devices: TrustedDeviceRepository,
    pub login_rate_limiter: LoginRateLimiter,
    pub account_lockout: AccountLockout,
    pub pending_redirects: PendingRedirectStore,
    pub pending_2fa: Pending2faStore,
    pub bot_trap: BotTrap,
    pub key_store: Arc<crypto::keys::KeyStore>,
    pub config: AppConfig,
    pub setup_needed: Arc<AtomicBool>,
    pub setup_token: Option<String>,
}

/// UI state — wraps [`AppStateCore`] and adds HTML-rendering concerns.
#[derive(Clone)]
pub struct AppState {
    pub core: Arc<AppStateCore>,
    pub tera: tera::Tera,
    pub locales: i18n::Locales,
    pub css_hash: String,
    pub js_hash: String,
    pub csp: Arc<std::sync::RwLock<String>>,
}

// Forwards `state.users` etc. to the core for ergonomic access in UI handlers.
impl std::ops::Deref for AppState {
    type Target = AppStateCore;
    fn deref(&self) -> &AppStateCore {
        &self.core
    }
}

/// Starts the GT Id server with the given config.
/// Returns the actual (api_port, ui_port) the listeners bound to.
/// The server runs in background tokio tasks and will keep running
/// as long as the tokio runtime is alive.
pub async fn start_server(mut config: AppConfig) -> (u16, u16, Option<String>) {
    // Bind listeners first so we know actual ports (important when port=0)
    let api_addr = format!("127.0.0.1:{}", config.api_listen_port);
    let ui_addr = format!("127.0.0.1:{}", config.ui_listen_port);

    let api_listener = tokio::net::TcpListener::bind(&api_addr)
        .await
        .expect("Failed to bind API address");
    let ui_listener = tokio::net::TcpListener::bind(&ui_addr)
        .await
        .expect("Failed to bind UI address");

    let actual_api_port = api_listener.local_addr().unwrap().port();
    let actual_ui_port = ui_listener.local_addr().unwrap().port();

    // Fix up URIs if they reference the original port (e.g. port 0 -> actual port)
    if config.issuer_uri.is_empty() || config.api_listen_port == 0 {
        config.issuer_uri = format!("http://127.0.0.1:{actual_api_port}");
    }
    if config.public_ui_uri.is_empty() || config.ui_listen_port == 0 {
        config.public_ui_uri = format!("http://127.0.0.1:{actual_ui_port}");
    }

    // Validate issuer URI
    validate_issuer_uri(&config.issuer_uri);

    tracing::info!("API listening on 127.0.0.1:{actual_api_port}");
    tracing::info!("UI listening on 127.0.0.1:{actual_ui_port}");

    let users_db = repositories::db::init_pool(&config.database_uri_users).await;
    repositories::db::run_users_migrations(&users_db).await;

    let clients_db = repositories::db::init_pool(&config.database_uri_clients).await;
    repositories::db::run_clients_migrations(&clients_db).await;

    let emails_db = repositories::db::init_pool(&config.database_uri_emails).await;
    repositories::db::run_emails_migrations(&emails_db).await;

    let config_db = repositories::db::init_pool(&config.database_uri_config).await;
    repositories::db::run_config_migrations(&config_db).await;

    crypto::password::init_dummy_hash();
    let key_store = Arc::new(crypto::keys::generate_keys().expect("Failed to generate initial keys"));
    let tera = load_templates();
    let locales = i18n::build_locales();

    let (users, confirmation_tokens, password_reset_tokens, email_changes, trusted_devices, sessions) =
        init_user_repos(&users_db);
    let (clients, auth_codes, consents, refresh_tokens) = init_client_repos(&clients_db);
    let email_templates = EmailTemplateRepository::new(emails_db.clone());
    let email_queue = repositories::email_queue::EmailQueueRepository::new(emails_db);
    let legal_pages = LegalPageRepository::new(config_db);

    let has_admin = users.has_admin().await.expect("Failed to check for admin users");
    let setup_needed = Arc::new(AtomicBool::new(!has_admin));
    let setup_token = if !has_admin {
        let token = crypto::id::new_id();
        tracing::info!(event = "setup_token", "No admin user found. Setup token generated.");
        eprintln!("\n  Setup token: {token}\n");
        Some(token)
    } else {
        None
    };

    email_templates
        .seed(&locales)
        .await
        .expect("Failed to seed email templates");
    legal_pages.seed().await.expect("Failed to seed legal pages");

    let initial_clients = clients.list().await.unwrap_or_default();
    let csp = Arc::new(std::sync::RwLock::new(middleware::security_headers::build_csp(
        &initial_clients,
    )));

    let (css_hash, js_hash) = routes::ui::static_files::asset_hashes();

    let core = Arc::new(AppStateCore {
        users,
        clients,
        sessions,
        auth_codes,
        consents,
        refresh_tokens,
        confirmation_tokens,
        password_reset_tokens,
        email_changes,
        email_templates,
        email_queue: email_queue.clone(),
        legal_pages,
        trusted_devices,
        login_rate_limiter: LoginRateLimiter::new(),
        account_lockout: AccountLockout::new(config.lockout_max_attempts, config.lockout_duration_secs),
        pending_redirects: PendingRedirectStore::new(),
        pending_2fa: Pending2faStore::new(),
        bot_trap: BotTrap::new(),
        key_store: key_store.clone(),
        config: config.clone(),
        setup_needed,
        setup_token: setup_token.clone(),
    });

    let state = Arc::new(AppState {
        core: core.clone(),
        tera,
        locales,
        css_hash,
        js_hash,
        csp,
    });

    let cors_layer = build_cors_layer(&config.cors_allowed_origins);

    let api_app = Router::new()
        .merge(routes::build_api_router())
        .fallback({
            let st = core.clone();
            move |conn: ConnectInfo<SocketAddr>, req: axum::http::Request<axum::body::Body>| {
                middleware::bot_trap::bot_trap_fallback(st.clone(), conn, req)
            }
        })
        .layer(axum::middleware::from_fn(
            middleware::content_type::validate_content_type,
        ))
        .layer(cors_layer)
        .layer(RequestBodyLimitLayer::new(config.max_request_body_bytes))
        .layer(axum::middleware::from_fn(
            middleware::security_headers::api_security_headers,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(core.clone(), middleware::bot_trap::bot_trap_guard))
        .with_state(core.clone());

    let ui_app = Router::new()
        .merge(routes::build_ui_router())
        .fallback({
            let st = core.clone();
            move |conn: ConnectInfo<SocketAddr>, req: axum::http::Request<axum::body::Body>| {
                middleware::bot_trap::bot_trap_fallback(st.clone(), conn, req)
            }
        })
        .layer(axum::middleware::from_fn(
            middleware::content_type::validate_content_type,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_request_body_bytes))
        .layer(CookieManagerLayer::new())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::security_headers::ui_security_headers,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(core.clone(), middleware::bot_trap::bot_trap_guard))
        .with_state(state.clone());

    let cleanup_state = core;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_hours(1));
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_state.sessions.delete_expired().await {
                tracing::error!("Session cleanup failed: {e}");
            }
            if let Err(e) = cleanup_state.auth_codes.delete_expired().await {
                tracing::error!("Auth code cleanup failed: {e}");
            }
            if let Err(e) = cleanup_state.refresh_tokens.delete_expired().await {
                tracing::error!("Refresh token cleanup failed: {e}");
            }
            if let Err(e) = cleanup_state.trusted_devices.delete_expired().await {
                tracing::error!("Trusted device cleanup failed: {e}");
            }
            if let Err(e) = cleanup_state.email_changes.delete_expired().await {
                tracing::error!("Email change cleanup failed: {e}");
            }
            if let Err(e) = cleanup_state.confirmation_tokens.delete_expired().await {
                tracing::error!("Confirmation token cleanup failed: {e}");
            }
            if let Err(e) = cleanup_state.password_reset_tokens.delete_expired().await {
                tracing::error!("Password reset token cleanup failed: {e}");
            }
        }
    });

    let rotation_interval = config.key_rotation_interval_secs;
    let rotation_key_store = key_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(rotation_interval));
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(e) = rotation_key_store.rotate() {
                tracing::error!("Key rotation failed: {e}");
            }
        }
    });

    let smtp_sender = email::smtp_sender::SmtpSender::new(&config);
    tokio::spawn(async move {
        email::worker::run_email_worker(email_queue, smtp_sender).await;
    });

    tokio::spawn(async move {
        serve_h2c(api_listener, api_app).await;
    });

    tokio::spawn(async move {
        serve_h2c(ui_listener, ui_app).await;
    });

    (actual_api_port, actual_ui_port, setup_token)
}

fn load_templates() -> tera::Tera {
    let mut tera = tera::Tera::default();
    tera.add_raw_templates(vec![
        ("base.html", include_str!("../static/base.html")),
        ("login.html", include_str!("../static/login.html")),
        ("authorize.html", include_str!("../static/authorize.html")),
        ("error.html", include_str!("../static/error.html")),
        ("admin/_sidebar.html", include_str!("../static/admin/_sidebar.html")),
        ("admin/dashboard.html", include_str!("../static/admin/dashboard.html")),
        ("admin/users.html", include_str!("../static/admin/users.html")),
        (
            "admin/user_create.html",
            include_str!("../static/admin/user_create.html"),
        ),
        ("admin/user_edit.html", include_str!("../static/admin/user_edit.html")),
        (
            "admin/email_templates.html",
            include_str!("../static/admin/email_templates.html"),
        ),
        (
            "admin/email_template_edit.html",
            include_str!("../static/admin/email_template_edit.html"),
        ),
        ("profile.html", include_str!("../static/profile.html")),
        ("admin/clients.html", include_str!("../static/admin/clients.html")),
        (
            "admin/client_create.html",
            include_str!("../static/admin/client_create.html"),
        ),
        (
            "admin/client_edit.html",
            include_str!("../static/admin/client_edit.html"),
        ),
        ("legal.html", include_str!("../static/legal.html")),
        (
            "admin/legal_pages.html",
            include_str!("../static/admin/legal_pages.html"),
        ),
        (
            "admin/legal_page_edit.html",
            include_str!("../static/admin/legal_page_edit.html"),
        ),
        ("setup.html", include_str!("../static/setup.html")),
        (
            "confirm_email_success.html",
            include_str!("../static/confirm_email_success.html"),
        ),
        (
            "confirm_email_change_success.html",
            include_str!("../static/confirm_email_change_success.html"),
        ),
        ("forgot_password.html", include_str!("../static/forgot_password.html")),
        (
            "forgot_password_sent.html",
            include_str!("../static/forgot_password_sent.html"),
        ),
        ("reset_password.html", include_str!("../static/reset_password.html")),
        (
            "reset_password_success.html",
            include_str!("../static/reset_password_success.html"),
        ),
        ("totp_setup.html", include_str!("../static/totp_setup.html")),
        ("totp_verify.html", include_str!("../static/totp_verify.html")),
    ])
    .expect("Failed to load embedded templates");
    tera
}

fn init_user_repos(
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

fn init_client_repos(
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

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    use axum::http::{Method, header};

    let origins = if allowed_origins.is_empty() {
        AllowOrigin::list(std::iter::empty::<axum::http::HeaderValue>())
    } else {
        AllowOrigin::list(
            allowed_origins
                .iter()
                .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok()),
        )
    };

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(3600))
}

async fn serve_h2c(listener: tokio::net::TcpListener, app: Router) {
    let mut make_service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("Failed to accept connection: {e}");
                continue;
            }
        };

        let tower_service = unwrap_infallible(make_service.call(remote_addr).await);
        let hyper_service = TowerToHyperService::new(tower_service);

        tokio::spawn(async move {
            let io = TokioIo::new(tcp_stream);
            if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
            {
                tracing::debug!("Connection error: {e}");
            }
        });
    }
}

fn unwrap_infallible<T>(result: Result<T, std::convert::Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(e) => match e {},
    }
}

fn validate_issuer_uri(uri: &str) {
    if uri.is_empty() {
        panic!("ISSUER_URI must not be empty");
    }
    let lower = uri.to_lowercase();
    if !lower.starts_with("https://") && !lower.starts_with("http://") {
        panic!("ISSUER_URI must use http:// or https:// scheme, got: {uri}");
    }
    if uri.ends_with('/') {
        panic!("ISSUER_URI must not end with a trailing slash, got: {uri}");
    }
}
