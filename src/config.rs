use std::env;

#[derive(Clone)]
pub struct AppConfig {
    pub issuer_uri: String,
    pub public_ui_uri: String,
    pub ui_listen_port: u16,
    pub api_listen_port: u16,
    pub database_uri_users: String,
    pub database_uri_clients: String,
    pub database_uri_emails: String,
    pub database_uri_config: String,
    pub roles: Vec<String>,
    pub lockout_max_attempts: u32,
    pub lockout_duration_secs: u64,
    pub secure_cookies: bool,
    pub session_lifetime_secs: i64,
    pub allowed_grant_types: Vec<String>,
    pub key_rotation_interval_secs: u64,
    pub cors_allowed_origins: Vec<String>,
    pub max_request_body_bytes: usize,
    pub trusted_proxies: bool,
    pub access_token_expiry_secs: i64,
    pub id_token_expiry_secs: i64,
    pub refresh_token_expiry_days: i64,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from: String,
    pub smtp_starttls: bool,
    pub email_confirm_token_expiry_hours: u64,
    pub password_reset_token_expiry_hours: u64,
    pub totp_encryption_key: [u8; 32],
    pub trust_device_lifetime_secs: i64,
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("issuer_uri", &self.issuer_uri)
            .field("public_ui_uri", &self.public_ui_uri)
            .field("ui_listen_port", &self.ui_listen_port)
            .field("api_listen_port", &self.api_listen_port)
            .field("roles", &self.roles)
            .field("secure_cookies", &self.secure_cookies)
            .field("totp_encryption_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self::from_vars(|key| env::var(key).ok())
    }

    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            issuer_uri: get("ISSUER_URI").unwrap_or_else(|| "http://localhost:3000".into()),
            public_ui_uri: get("PUBLIC_UI_URI").unwrap_or_else(|| "http://localhost:3001".into()),
            ui_listen_port: get("UI_LISTEN_PORT").and_then(|v| v.parse().ok()).unwrap_or(3001),
            api_listen_port: get("API_LISTEN_PORT").and_then(|v| v.parse().ok()).unwrap_or(3000),
            database_uri_users: get("DATABASE_URI_USERS").unwrap_or_else(|| "sqlite:gtid_users.db".into()),
            database_uri_clients: get("DATABASE_URI_CLIENTS").unwrap_or_else(|| "sqlite:gtid_clients.db".into()),
            database_uri_emails: get("DATABASE_URI_EMAILS").unwrap_or_else(|| "sqlite:gtid_emails.db".into()),
            database_uri_config: get("DATABASE_URI_CONFIG").unwrap_or_else(|| "sqlite:gtid_config.db".into()),
            roles: {
                let mut roles = vec!["admin".to_string()];
                if let Some(val) = get("ROLES") {
                    for r in val.split(',') {
                        let r = r.trim().to_lowercase();
                        if !r.is_empty() && r != "admin" {
                            roles.push(r);
                        }
                    }
                }
                roles
            },
            lockout_max_attempts: get("LOCKOUT_MAX_ATTEMPTS").and_then(|v| v.parse().ok()).unwrap_or(3),
            lockout_duration_secs: get("LOCKOUT_DURATION_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            secure_cookies: get("SECURE_COOKIES").map(|v| v == "true" || v == "1").unwrap_or(true),
            session_lifetime_secs: get("SESSION_LIFETIME_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),
            allowed_grant_types: get("ALLOWED_GRANT_TYPES")
                .unwrap_or_else(|| "authorization_code,refresh_token".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            key_rotation_interval_secs: get("KEY_ROTATION_INTERVAL_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),
            cors_allowed_origins: get("CORS_ALLOWED_ORIGINS")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            max_request_body_bytes: get("MAX_REQUEST_BODY_BYTES")
                .and_then(|v| v.parse().ok())
                .unwrap_or(64 * 1024), // 64 KB
            trusted_proxies: get("TRUSTED_PROXIES").map(|v| v == "true" || v == "1").unwrap_or(false),
            access_token_expiry_secs: get("ACCESS_TOKEN_EXPIRY_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(900), // 15 minutes
            id_token_expiry_secs: get("ID_TOKEN_EXPIRY_SECS").and_then(|v| v.parse().ok()).unwrap_or(600), // 10 minutes
            refresh_token_expiry_days: get("REFRESH_TOKEN_EXPIRY_DAYS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            smtp_host: get("SMTP_HOST"),
            smtp_port: get("SMTP_PORT").and_then(|v| v.parse().ok()).unwrap_or(587),
            smtp_username: get("SMTP_USERNAME"),
            smtp_password: get("SMTP_PASSWORD"),
            smtp_from: get("SMTP_FROM").unwrap_or_else(|| "noreply@localhost".into()),
            smtp_starttls: get("SMTP_STARTTLS").map(|v| v != "false" && v != "0").unwrap_or(true),
            email_confirm_token_expiry_hours: get("EMAIL_CONFIRM_TOKEN_EXPIRY_HOURS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(24),
            password_reset_token_expiry_hours: get("PASSWORD_RESET_TOKEN_EXPIRY_HOURS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            trust_device_lifetime_secs: get("TRUST_DEVICE_LIFETIME_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(2_592_000), // 30 days
            totp_encryption_key: {
                let hex_str = get("TOTP_ENCRYPTION_KEY").unwrap_or_else(|| "0".repeat(64));
                let bytes =
                    hex::decode(&hex_str).expect("TOTP_ENCRYPTION_KEY must be valid hex (64 hex chars = 32 bytes)");
                let mut key = [0u8; 32];
                assert!(
                    bytes.len() == 32,
                    "TOTP_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars)"
                );
                key.copy_from_slice(&bytes);
                key
            },
        }
    }

    pub fn grant_type_allowed(&self, grant_type: &str) -> bool {
        self.allowed_grant_types.iter().any(|g| g == grant_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config_from(vars: &[(&str, &str)]) -> AppConfig {
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        AppConfig::from_vars(|key| map.get(key).cloned())
    }

    fn minimal() -> AppConfig {
        config_from(&[])
    }

    #[test]
    fn defaults_with_minimal_env() {
        let c = minimal();
        assert_eq!(c.issuer_uri, "http://localhost:3000");
        assert_eq!(c.public_ui_uri, "http://localhost:3001");
        assert_eq!(c.api_listen_port, 3000);
        assert_eq!(c.ui_listen_port, 3001);
        assert_eq!(c.database_uri_users, "sqlite:gtid_users.db");
        assert_eq!(c.database_uri_clients, "sqlite:gtid_clients.db");
        assert_eq!(c.database_uri_emails, "sqlite:gtid_emails.db");
        assert_eq!(c.database_uri_config, "sqlite:gtid_config.db");
        assert_eq!(c.lockout_max_attempts, 3);
        assert_eq!(c.lockout_duration_secs, 3600);
        assert!(c.secure_cookies);
        assert_eq!(c.session_lifetime_secs, 86400);
        assert_eq!(c.key_rotation_interval_secs, 86400);
        assert_eq!(c.allowed_grant_types, vec!["authorization_code", "refresh_token"]);
        assert_eq!(c.roles, vec!["admin"]);
        assert!(c.cors_allowed_origins.is_empty());
        assert_eq!(c.max_request_body_bytes, 64 * 1024);
        assert!(!c.trusted_proxies);
        assert_eq!(c.access_token_expiry_secs, 900);
        assert_eq!(c.id_token_expiry_secs, 600);
        assert_eq!(c.refresh_token_expiry_days, 30);
        assert!(c.smtp_host.is_none());
        assert_eq!(c.smtp_port, 587);
        assert!(c.smtp_username.is_none());
        assert!(c.smtp_password.is_none());
        assert_eq!(c.smtp_from, "noreply@localhost");
        assert!(c.smtp_starttls);
        assert_eq!(c.email_confirm_token_expiry_hours, 24);
        assert_eq!(c.password_reset_token_expiry_hours, 1);
        assert_eq!(c.trust_device_lifetime_secs, 2_592_000);
    }

    #[test]
    fn custom_ports() {
        let c = config_from(&[("API_LISTEN_PORT", "8080"), ("UI_LISTEN_PORT", "9090")]);
        assert_eq!(c.api_listen_port, 8080);
        assert_eq!(c.ui_listen_port, 9090);
    }

    #[test]
    fn invalid_port_falls_back_to_default() {
        let c = config_from(&[("API_LISTEN_PORT", "not_a_number")]);
        assert_eq!(c.api_listen_port, 3000);
    }

    #[test]
    fn roles_always_includes_admin() {
        let c = config_from(&[("ROLES", "editor,viewer")]);
        assert_eq!(c.roles, vec!["admin", "editor", "viewer"]);
    }

    #[test]
    fn roles_deduplicates_admin() {
        let c = config_from(&[("ROLES", "Admin,editor")]);
        assert_eq!(c.roles, vec!["admin", "editor"]);
    }

    #[test]
    fn roles_trims_whitespace_and_lowercases() {
        let c = config_from(&[("ROLES", " Editor , VIEWER ")]);
        assert_eq!(c.roles, vec!["admin", "editor", "viewer"]);
    }

    #[test]
    fn roles_ignores_empty_segments() {
        let c = config_from(&[("ROLES", "editor,,, ,viewer")]);
        assert_eq!(c.roles, vec!["admin", "editor", "viewer"]);
    }

    #[test]
    fn secure_cookies_variants() {
        let check = |val: &str, expected: bool| {
            let c = config_from(&[("SECURE_COOKIES", val)]);
            assert_eq!(c.secure_cookies, expected, "SECURE_COOKIES={val}");
        };
        check("true", true);
        check("1", true);
        check("false", false);
        check("0", false);
        check("yes", false);
    }

    #[test]
    fn grant_type_allowed_checks_list() {
        let c = config_from(&[("ALLOWED_GRANT_TYPES", "authorization_code")]);
        assert!(c.grant_type_allowed("authorization_code"));
        assert!(!c.grant_type_allowed("refresh_token"));
    }

    #[test]
    fn custom_lockout_settings() {
        let c = config_from(&[("LOCKOUT_MAX_ATTEMPTS", "5"), ("LOCKOUT_DURATION_SECS", "7200")]);
        assert_eq!(c.lockout_max_attempts, 5);
        assert_eq!(c.lockout_duration_secs, 7200);
    }

    #[test]
    fn custom_session_lifetime() {
        let c = config_from(&[("SESSION_LIFETIME_SECS", "3600")]);
        assert_eq!(c.session_lifetime_secs, 3600);
    }

    #[test]
    fn custom_key_rotation_interval() {
        let c = config_from(&[("KEY_ROTATION_INTERVAL_SECS", "43200")]);
        assert_eq!(c.key_rotation_interval_secs, 43200);
    }

    #[test]
    fn cors_allowed_origins_parsed() {
        let c = config_from(&[(
            "CORS_ALLOWED_ORIGINS",
            "https://app.example.com, https://other.example.com",
        )]);
        assert_eq!(
            c.cors_allowed_origins,
            vec!["https://app.example.com", "https://other.example.com"]
        );
    }

    #[test]
    fn cors_allowed_origins_empty_by_default() {
        let c = minimal();
        assert!(c.cors_allowed_origins.is_empty());
    }

    #[test]
    fn trusted_proxies_enabled() {
        let c = config_from(&[("TRUSTED_PROXIES", "true")]);
        assert!(c.trusted_proxies);
    }

    #[test]
    fn custom_token_expiry() {
        let c = config_from(&[
            ("ACCESS_TOKEN_EXPIRY_SECS", "300"),
            ("ID_TOKEN_EXPIRY_SECS", "120"),
            ("REFRESH_TOKEN_EXPIRY_DAYS", "7"),
        ]);
        assert_eq!(c.access_token_expiry_secs, 300);
        assert_eq!(c.id_token_expiry_secs, 120);
        assert_eq!(c.refresh_token_expiry_days, 7);
    }

    #[test]
    fn smtp_config_custom() {
        let c = config_from(&[
            ("SMTP_HOST", "smtp.example.com"),
            ("SMTP_PORT", "465"),
            ("SMTP_USERNAME", "user@example.com"),
            ("SMTP_PASSWORD", "secret"),
            ("SMTP_FROM", "noreply@example.com"),
            ("SMTP_STARTTLS", "false"),
        ]);
        assert_eq!(c.smtp_host.as_deref(), Some("smtp.example.com"));
        assert_eq!(c.smtp_port, 465);
        assert_eq!(c.smtp_username.as_deref(), Some("user@example.com"));
        assert_eq!(c.smtp_password.as_deref(), Some("secret"));
        assert_eq!(c.smtp_from, "noreply@example.com");
        assert!(!c.smtp_starttls);
    }

    #[test]
    fn custom_email_confirm_token_expiry() {
        let c = config_from(&[("EMAIL_CONFIRM_TOKEN_EXPIRY_HOURS", "48")]);
        assert_eq!(c.email_confirm_token_expiry_hours, 48);
    }

    #[test]
    fn custom_trust_device_lifetime() {
        let c = config_from(&[("TRUST_DEVICE_LIFETIME_SECS", "604800")]);
        assert_eq!(c.trust_device_lifetime_secs, 604800); // 7 days
    }

    #[test]
    fn custom_max_request_body_bytes() {
        let c = config_from(&[("MAX_REQUEST_BODY_BYTES", "131072")]);
        assert_eq!(c.max_request_body_bytes, 131072);
    }
}
