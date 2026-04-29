//! Server orchestration: binds listeners, bootstraps state, and serves the
//! API and UI routers on separate ports.

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
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use gtid_shared::config::AppConfig;
use gtid_shared::middleware;
use gtid_shared::middleware::bot_trap::BotTrap;
use gtid_shared::middleware::lockout::AccountLockout;
use gtid_shared::middleware::pending_2fa::Pending2faStore;
use gtid_shared::middleware::pending_redirect::PendingRedirectStore;
use gtid_shared::middleware::rate_limit::LoginRateLimiter;
use gtid_shared::repositories;
use gtid_shared::repositories::email_template::EmailTemplateRepository;
use gtid_shared::repositories::legal_page::LegalPageRepository;
use gtid_shared::repositories::trusted_device::TrustedDeviceRepository;
use gtid_shared::{AppStateCore, crypto, email, i18n};
use gtid_ui::AppState;

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
    let tera = gtid_ui::load_templates();
    let locales = i18n::build_locales();

    let (users, confirmation_tokens, password_reset_tokens, email_changes, trusted_devices, sessions) =
        gtid_shared::init_user_repos(&users_db);
    let (clients, auth_codes, consents, refresh_tokens) = gtid_shared::init_client_repos(&clients_db);
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

    let (css_hash, js_hash) = gtid_ui::handlers::static_files::asset_hashes();

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
        login_rate_limiter: LoginRateLimiter::new(),
        bot_trap: BotTrap::new(),
        key_store: key_store.clone(),
        config: config.clone(),
        setup_needed,
        setup_token: setup_token.clone(),
        locales: locales.clone(),
    });

    let state = Arc::new(AppState {
        core: core.clone(),
        tera,
        locales,
        css_hash,
        js_hash,
        csp,
        trusted_devices: trusted_devices.clone(),
        account_lockout: AccountLockout::new(config.lockout_max_attempts, config.lockout_duration_secs),
        pending_redirects: PendingRedirectStore::new(),
        pending_2fa: Pending2faStore::new(),
    });

    // API router comes fully layered from the `gtid-api` crate.
    let api_app = gtid_api::build_api_router(core.clone());

    let ui_app = Router::new()
        .merge(gtid_ui::build_ui_router())
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
            gtid_ui::middleware::security_headers::ui_security_headers,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(
            core.clone(),
            middleware::bot_trap::bot_trap_guard,
        ))
        .layer(axum::middleware::from_fn(
            middleware::language::set_request_lang,
        ))
        .with_state(state.clone());

    let cleanup_state = core;
    let cleanup_trusted_devices: TrustedDeviceRepository = trusted_devices;
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
            if let Err(e) = cleanup_trusted_devices.delete_expired().await {
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
