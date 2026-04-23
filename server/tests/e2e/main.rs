use gtid_shared::config::AppConfig;
use gtid_shared::crypto::totp as totp_crypto;
use reqwest::redirect::Policy;
use scraper::{Html, Selector};

pub mod flow;
pub mod security;

pub const ADMIN_EMAIL: &str = "admin@example.com";
pub const ADMIN_PASSWORD: &str = "093hG.Insdf!!";
pub const CLIENT_ID: &str = "my-test-app";
pub const CLIENT_SECRET: &str = "Test!!Secret99xx";
pub const REDIRECT_URI: &str = "http://localhost:8080/callback";

pub struct TestServer {
    pub api_port: u16,
    pub ui_port: u16,
    pub client: reqwest::Client,
    pub admin_totp_secret: String,
    pub last_totp_code: std::sync::Mutex<Option<String>>,
    _db_users: tempfile::NamedTempFile,
    _db_clients: tempfile::NamedTempFile,
    _db_emails: tempfile::NamedTempFile,
    _db_config: tempfile::NamedTempFile,
}

impl TestServer {
    pub async fn start() -> Self {
        let db_users = tempfile::NamedTempFile::new().expect("Failed to create temp DB file");
        let db_clients = tempfile::NamedTempFile::new().expect("Failed to create temp DB file");
        let db_emails = tempfile::NamedTempFile::new().expect("Failed to create temp DB file");
        let db_config = tempfile::NamedTempFile::new().expect("Failed to create temp DB file");

        let config = AppConfig {
            issuer_uri: String::new(), // will be set after port is known
            public_ui_uri: String::new(),
            ui_listen_port: 0, // random port
            api_listen_port: 0,
            database_uri_users: format!("sqlite:{}?mode=rwc", db_users.path().to_str().unwrap()),
            database_uri_clients: format!("sqlite:{}?mode=rwc", db_clients.path().to_str().unwrap()),
            database_uri_emails: format!("sqlite:{}?mode=rwc", db_emails.path().to_str().unwrap()),
            database_uri_config: format!("sqlite:{}?mode=rwc", db_config.path().to_str().unwrap()),
            roles: vec!["admin".to_string()],
            lockout_max_attempts: 100,
            lockout_duration_secs: 3600,
            secure_cookies: false,
            session_lifetime_secs: 86400,
            session_idle_timeout_secs: 3600,
            allowed_grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            key_rotation_interval_secs: 86400,
            cors_allowed_origins: vec![],
            max_request_body_bytes: 64 * 1024,
            trusted_proxies: false,
            access_token_expiry_secs: 900,
            id_token_expiry_secs: 600,
            refresh_token_expiry_days: 30,
            smtp_host: None,
            smtp_port: 587,
            smtp_username: None,
            smtp_password: None,
            smtp_from: "noreply@localhost".to_string(),
            smtp_starttls: true,
            email_confirm_token_expiry_hours: 24,
            password_reset_token_expiry_hours: 1,
            totp_encryption_key: [42u8; 32],
            trust_device_lifetime_secs: 2_592_000,
        };

        let (api_port, ui_port, setup_token) = gtid_server::start_server(config).await;

        // Wait for server to be ready
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .user_agent("E2ETest/1.0")
            .build()
            .unwrap();

        for _ in 0..50 {
            if client
                .get(format!("http://127.0.0.1:{api_port}/health"))
                .send()
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // Create initial admin via setup page
        let setup_page = client
            .get(format!("http://127.0.0.1:{ui_port}/setup"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let csrf = extract_csrf(&setup_page).expect("No CSRF token on setup page");
        let token = setup_token
            .as_deref()
            .expect("Setup token should be present for fresh DB");
        let resp = client
            .post(format!("http://127.0.0.1:{ui_port}/setup"))
            .form(&[
                ("setup_token", token),
                ("email", ADMIN_EMAIL),
                ("password", ADMIN_PASSWORD),
                ("display_name", "Admin"),
                ("csrf_token", csrf.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 303, "Setup should redirect to 2FA setup");
        let totp_setup_location = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
        assert!(
            totp_setup_location.contains("/2fa/setup"),
            "Should redirect to /2fa/setup"
        );

        // Complete 2FA setup
        let totp_setup_url = format!("http://127.0.0.1:{ui_port}{totp_setup_location}");
        let totp_resp = client.get(&totp_setup_url).send().await.unwrap();
        let totp_status = totp_resp.status();
        let totp_page = totp_resp.text().await.unwrap();
        assert!(
            totp_status.is_success() || totp_status.as_u16() == 303,
            "TOTP setup page returned {totp_status}: {totp_page}"
        );
        let totp_csrf = extract_csrf(&totp_page).expect("No CSRF on TOTP setup page");
        let totp_secret = extract_totp_secret(&totp_page).expect("No TOTP secret on setup page");
        let pending_id = extract_input_value(&totp_page, "p").expect("No pending ID on setup page");
        let issuer_uri = format!("http://127.0.0.1:{ui_port}");
        let totp = totp_crypto::build_totp(&totp_secret, ADMIN_EMAIL, &issuer_uri).unwrap();
        let code = totp.generate_current().unwrap();
        let resp = client
            .post(format!("http://127.0.0.1:{ui_port}/2fa/setup"))
            .form(&[
                ("csrf_token", totp_csrf.as_str()),
                ("p", pending_id.as_str()),
                ("code", code.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 303, "2FA setup should redirect to /login");

        Self {
            api_port,
            ui_port,
            client,
            admin_totp_secret: totp_secret,
            last_totp_code: std::sync::Mutex::new(Some(code)),
            _db_users: db_users,
            _db_clients: db_clients,
            _db_emails: db_emails,
            _db_config: db_config,
        }
    }

    pub fn api_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.api_port, path)
    }

    pub fn ui_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.ui_port, path)
    }

    /// Create a new reqwest client with its own cookie jar (separate session).
    pub fn new_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .cookie_store(true)
            .redirect(Policy::none())
            .user_agent("E2ETest-Sec/1.0")
            .build()
            .unwrap()
    }

    /// Create a new reqwest client that follows redirects.
    pub fn new_following_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .cookie_store(true)
            .redirect(Policy::limited(10))
            .user_agent("E2ETest/1.0")
            .build()
            .unwrap()
    }
}

pub fn extract_input_value(html: &str, name: &str) -> Option<String> {
    let doc = Html::parse_document(html);
    let selector = Selector::parse(&format!(r#"input[name="{}"]"#, name)).ok()?;
    doc.select(&selector)
        .next()
        .and_then(|el| el.value().attr("value"))
        .map(|v| v.to_string())
}

pub fn extract_csrf(html: &str) -> Option<String> {
    extract_input_value(html, "csrf_token")
}

pub fn extract_totp_secret(html: &str) -> Option<String> {
    let doc = Html::parse_document(html);
    let selector = Selector::parse("code.totp-secret").ok()?;
    doc.select(&selector)
        .next()
        .map(|el| el.text().collect::<String>().replace(' ', ""))
}

pub async fn admin_login(server: &TestServer, client: &reqwest::Client) -> String {
    let login_page = client
        .get(server.ui_url("/login"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let csrf = extract_csrf(&login_page).expect("No CSRF token on login page");

    let resp = client
        .post(server.ui_url("/login"))
        .form(&[
            ("email", ADMIN_EMAIL),
            ("password", ADMIN_PASSWORD),
            ("csrf_token", &csrf),
            ("redirect", ""),
        ])
        .send()
        .await
        .unwrap();

    // No-redirect client: location header present -> manually complete 2FA
    if let Some(location) = resp.headers().get("location") {
        let location = location.to_str().unwrap().to_string();
        if location.contains("/2fa/verify") {
            complete_2fa_verify(server, client, &location).await;
        }
    } else {
        // Following-redirect client: landed on 2FA verify form page
        let body = resp.text().await.unwrap();
        if let (Some(verify_csrf), Some(pending_id)) = (extract_csrf(&body), extract_input_value(&body, "p")) {
            let code = generate_fresh_totp_code(server).await;

            client
                .post(server.ui_url("/2fa/verify"))
                .form(&[
                    ("csrf_token", verify_csrf.as_str()),
                    ("p", pending_id.as_str()),
                    ("code", code.as_str()),
                ])
                .send()
                .await
                .unwrap();
        }
    }

    csrf
}

async fn generate_fresh_totp_code(server: &TestServer) -> String {
    let issuer_uri = server.ui_url("");
    let totp = totp_crypto::build_totp(&server.admin_totp_secret, ADMIN_EMAIL, &issuer_uri).unwrap();
    let mut code = totp.generate_current().unwrap();
    let prev = server.last_totp_code.lock().unwrap().clone();
    if let Some(prev) = prev {
        while code == prev {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            code = totp.generate_current().unwrap();
        }
    }
    *server.last_totp_code.lock().unwrap() = Some(code.clone());
    code
}

pub async fn complete_2fa_verify(server: &TestServer, client: &reqwest::Client, location: &str) {
    let verify_page = client
        .get(server.ui_url(location))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let verify_csrf = extract_csrf(&verify_page).expect("No CSRF on 2FA verify page");
    let pending_id = extract_input_value(&verify_page, "p").expect("No pending ID");

    let code = generate_fresh_totp_code(server).await;

    client
        .post(server.ui_url("/2fa/verify"))
        .form(&[
            ("csrf_token", verify_csrf.as_str()),
            ("p", pending_id.as_str()),
            ("code", code.as_str()),
        ])
        .send()
        .await
        .unwrap();
}

pub async fn setup_test_client(server: &TestServer, client: &reqwest::Client) {
    admin_login(server, client).await;

    // Delete existing client if present
    let clients_page = client
        .get(server.ui_url("/admin/clients"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    if let Some(csrf) = extract_csrf(&clients_page) {
        let _ = client
            .post(server.ui_url(&format!("/admin/clients/{}/delete", CLIENT_ID)))
            .form(&[("csrf_token", &csrf)])
            .send()
            .await;
    }

    // Get CSRF for create form
    let create_page = client
        .get(server.ui_url("/admin/clients/create"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = extract_csrf(&create_page).expect("No CSRF on client create page");

    let resp = client
        .post(server.ui_url("/admin/clients/create"))
        .form(&[
            ("csrf_token", csrf.as_str()),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("client_redirect_uri", REDIRECT_URI),
        ])
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    assert!(
        status == 303 || status == 200,
        "Failed to create test client (HTTP {status})"
    );
}

pub async fn get_fresh_code(server: &TestServer, client: &reqwest::Client) -> (String, String) {
    let auth_resp = client
        .get(server.api_url("/authorize-url?scope=openid%20email%20profile"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let authorize_url = auth_resp["authorize_url"].as_str().unwrap().to_string();
    let code_verifier = auth_resp["code_verifier"].as_str().unwrap().to_string();

    // Follow authorize URL - should auto-redirect since consent was already given
    let redir_resp = client.get(&authorize_url).send().await.unwrap();

    let location = redir_resp
        .headers()
        .get("location")
        .expect("No redirect from authorize")
        .to_str()
        .unwrap()
        .to_string();

    let code = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .expect("No code in redirect")
        .1
        .to_string();

    (code, code_verifier)
}

pub async fn exchange_code(
    server: &TestServer,
    client: &reqwest::Client,
    code: &str,
    code_verifier: &str,
) -> serde_json::Value {
    client
        .post(server.api_url("/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
