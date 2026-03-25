use std::sync::Arc;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use tower::Service;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;

mod config;
mod crypto;
mod errors;
mod middleware;
mod models;
mod repositories;
mod routes;

use config::AppConfig;
use middleware::lockout::AccountLockout;
use middleware::pending_redirect::PendingRedirectStore;
use middleware::rate_limit::LoginRateLimiter;
use repositories::auth_code::AuthCodeRepository;
use repositories::client::ClientRepository;
use repositories::consent::ConsentRepository;
use repositories::email_template::EmailTemplateRepository;
use repositories::refresh_token::RefreshTokenRepository;
use repositories::session::SessionRepository;
use repositories::user::UserRepository;

#[derive(Clone)]
pub struct AppState {
    pub users: UserRepository,
    pub clients: ClientRepository,
    pub sessions: SessionRepository,
    pub auth_codes: AuthCodeRepository,
    pub consents: ConsentRepository,
    pub refresh_tokens: RefreshTokenRepository,
    pub email_templates: EmailTemplateRepository,
    pub login_rate_limiter: LoginRateLimiter,
    pub account_lockout: AccountLockout,
    pub pending_redirects: PendingRedirectStore,
    pub tera: tera::Tera,
    pub i18n: serde_json::Value,
    pub key_store: Arc<crypto::keys::KeyStore>,
    pub config: AppConfig,
    pub css_hash: String,
    pub js_hash: String,
}

impl AppState {
    /// Creates a Tera context with i18n translations and asset hashes pre-loaded.
    pub fn context(&self) -> tera::Context {
        let mut ctx = tera::Context::new();
        ctx.insert("t", &self.i18n);
        ctx.insert("css_hash", &self.css_hash);
        ctx.insert("js_hash", &self.js_hash);
        ctx
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = AppConfig::from_env();

    tracing::info!("Starting GT Id — UI on localhost:{}, API on localhost:{}", config.ui_listen_port, config.api_listen_port);

    let db = repositories::db::init_pool(&config.database_uri).await;
    let key_store = Arc::new(crypto::keys::generate_keys());
    let mut tera = tera::Tera::default();
    tera.add_raw_templates(vec![
        ("base.html", include_str!("../static/base.html")),
        ("login.html", include_str!("../static/login.html")),
        ("authorize.html", include_str!("../static/authorize.html")),
        ("error.html", include_str!("../static/error.html")),
        ("admin/_sidebar.html", include_str!("../static/admin/_sidebar.html")),
        ("admin/dashboard.html", include_str!("../static/admin/dashboard.html")),
        ("admin/users.html", include_str!("../static/admin/users.html")),
        ("admin/user_create.html", include_str!("../static/admin/user_create.html")),
        ("admin/user_edit.html", include_str!("../static/admin/user_edit.html")),
        ("admin/email_templates.html", include_str!("../static/admin/email_templates.html")),
        ("admin/email_template_edit.html", include_str!("../static/admin/email_template_edit.html")),
        ("profile.html", include_str!("../static/profile.html")),
        ("admin/clients.html", include_str!("../static/admin/clients.html")),
        ("admin/client_create.html", include_str!("../static/admin/client_create.html")),
        ("admin/client_edit.html", include_str!("../static/admin/client_edit.html")),
    ]).expect("Failed to load embedded templates");

    // i18n translations embedded at compile time
    let i18n: serde_json::Value =
        serde_json::from_str(include_str!("../static/i18n.json")).expect("Failed to parse embedded i18n.json");

    let users = UserRepository::new(db.clone());
    let clients = ClientRepository::new(db.clone());
    let sessions = SessionRepository::new(db.clone());
    let auth_codes = AuthCodeRepository::new(db.clone());
    let consents = ConsentRepository::new(db.clone());
    let email_templates = EmailTemplateRepository::new(db.clone());
    let refresh_tokens = RefreshTokenRepository::new(db);

    seed_admin(&users, &config).await;
    email_templates.seed().await.expect("Failed to seed email templates");

    let (css_hash, js_hash) = routes::static_files::asset_hashes();

    let state = Arc::new(AppState {
        users,
        clients,
        sessions,
        auth_codes,
        consents,
        refresh_tokens,
        email_templates,
        login_rate_limiter: LoginRateLimiter::new(),
        account_lockout: AccountLockout::new(config.lockout_max_attempts, config.lockout_duration_secs),
        pending_redirects: PendingRedirectStore::new(),
        tera,
        i18n,
        key_store: key_store.clone(),
        config: config.clone(),
        css_hash,
        js_hash,
    });

    let api_app = Router::new()
        .merge(routes::build_api_router())
        .layer(axum::middleware::from_fn(middleware::security_headers::api_security_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let ui_app = Router::new()
        .merge(routes::build_ui_router())
        .layer(CookieManagerLayer::new())
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_headers::ui_security_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let api_addr = format!("127.0.0.1:{}", config.api_listen_port);
    let ui_addr = format!("127.0.0.1:{}", config.ui_listen_port);

    let api_listener = tokio::net::TcpListener::bind(&api_addr)
        .await
        .expect("Failed to bind API address");
    let ui_listener = tokio::net::TcpListener::bind(&ui_addr)
        .await
        .expect("Failed to bind UI address");

    tracing::info!("API listening on {api_addr}");
    tracing::info!("UI listening on {ui_addr}");

    // Key rotation background task
    let rotation_interval = config.key_rotation_interval_secs;
    let rotation_key_store = key_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(rotation_interval));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            rotation_key_store.rotate();
        }
    });

    tokio::spawn(async move {
        serve_h2c(api_listener, api_app).await;
    });

    serve_h2c(ui_listener, ui_app).await;
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

async fn seed_admin(users: &UserRepository, config: &AppConfig) {
    if let Ok(Some(_)) = users.find_by_email(&config.admin_email).await {
        tracing::info!("Admin user already exists");
        return;
    }

    if let Err(e) = crypto::password::validate_strength(&config.admin_password, 10) {
        panic!("ADMIN_PASSWORD is invalid: {e}");
    }

    let id = crypto::id::new_id();
    let hash = crypto::password::hash_password(&config.admin_password)
        .expect("Failed to hash admin password");

    users
        .create(&id, &config.admin_email, &hash, Some("Admin"), "admin")
        .await
        .expect("Failed to seed admin user");

    tracing::info!("Admin user seeded: {}", config.admin_email);
}
