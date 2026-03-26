use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub issuer_uri: String,
    pub public_ui_uri: String,
    pub ui_listen_port: u16,
    pub api_listen_port: u16,
    pub database_uri: String,
    pub admin_email: String,
    pub admin_password: String,
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
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self::from_vars(|key| env::var(key).ok())
    }

    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            issuer_uri: get("ISSUER_URI").unwrap_or_else(|| "http://localhost:3000".into()),
            public_ui_uri: get("PUBLIC_UI_URI").unwrap_or_else(|| "http://localhost:3001".into()),
            ui_listen_port: get("UI_LISTEN_PORT")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3001),
            api_listen_port: get("API_LISTEN_PORT")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),
            database_uri: get("DATABASE_URI")
                .unwrap_or_else(|| "sqlite:gtid.db".into()),
            admin_email: get("ADMIN_EMAIL").expect("ADMIN_EMAIL must be set"),
            admin_password: get("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set"),
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
            lockout_max_attempts: get("LOCKOUT_MAX_ATTEMPTS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
            lockout_duration_secs: get("LOCKOUT_DURATION_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            secure_cookies: get("SECURE_COOKIES")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
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
                .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default(),
            max_request_body_bytes: get("MAX_REQUEST_BODY_BYTES")
                .and_then(|v| v.parse().ok())
                .unwrap_or(64 * 1024), // 64 KB
            trusted_proxies: get("TRUSTED_PROXIES")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            access_token_expiry_secs: get("ACCESS_TOKEN_EXPIRY_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(900), // 15 minutes
            id_token_expiry_secs: get("ID_TOKEN_EXPIRY_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(600), // 10 minutes
            refresh_token_expiry_days: get("REFRESH_TOKEN_EXPIRY_DAYS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
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
        config_from(&[("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "secret")])
    }

    #[test]
    fn defaults_with_minimal_env() {
        let c = minimal();
        assert_eq!(c.issuer_uri, "http://localhost:3000");
        assert_eq!(c.public_ui_uri, "http://localhost:3001");
        assert_eq!(c.api_listen_port, 3000);
        assert_eq!(c.ui_listen_port, 3001);
        assert_eq!(c.database_uri, "sqlite:gtid.db");
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
    }

    #[test]
    #[should_panic(expected = "ADMIN_EMAIL must be set")]
    fn missing_admin_email_panics() {
        config_from(&[("ADMIN_PASSWORD", "secret")]);
    }

    #[test]
    #[should_panic(expected = "ADMIN_PASSWORD must be set")]
    fn missing_admin_password_panics() {
        config_from(&[("ADMIN_EMAIL", "a@b.c")]);
    }

    #[test]
    fn custom_ports() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("API_LISTEN_PORT", "8080"), ("UI_LISTEN_PORT", "9090"),
        ]);
        assert_eq!(c.api_listen_port, 8080);
        assert_eq!(c.ui_listen_port, 9090);
    }

    #[test]
    fn invalid_port_falls_back_to_default() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("API_LISTEN_PORT", "not_a_number"),
        ]);
        assert_eq!(c.api_listen_port, 3000);
    }

    #[test]
    fn roles_always_includes_admin() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("ROLES", "editor,viewer"),
        ]);
        assert_eq!(c.roles, vec!["admin", "editor", "viewer"]);
    }

    #[test]
    fn roles_deduplicates_admin() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("ROLES", "Admin,editor"),
        ]);
        assert_eq!(c.roles, vec!["admin", "editor"]);
    }

    #[test]
    fn roles_trims_whitespace_and_lowercases() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("ROLES", " Editor , VIEWER "),
        ]);
        assert_eq!(c.roles, vec!["admin", "editor", "viewer"]);
    }

    #[test]
    fn roles_ignores_empty_segments() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("ROLES", "editor,,, ,viewer"),
        ]);
        assert_eq!(c.roles, vec!["admin", "editor", "viewer"]);
    }

    #[test]
    fn secure_cookies_variants() {
        let check = |val: &str, expected: bool| {
            let c = config_from(&[
                ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
                ("SECURE_COOKIES", val),
            ]);
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
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("ALLOWED_GRANT_TYPES", "authorization_code"),
        ]);
        assert!(c.grant_type_allowed("authorization_code"));
        assert!(!c.grant_type_allowed("refresh_token"));
    }

    #[test]
    fn custom_lockout_settings() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("LOCKOUT_MAX_ATTEMPTS", "5"), ("LOCKOUT_DURATION_SECS", "7200"),
        ]);
        assert_eq!(c.lockout_max_attempts, 5);
        assert_eq!(c.lockout_duration_secs, 7200);
    }

    #[test]
    fn custom_session_lifetime() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("SESSION_LIFETIME_SECS", "3600"),
        ]);
        assert_eq!(c.session_lifetime_secs, 3600);
    }

    #[test]
    fn custom_key_rotation_interval() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("KEY_ROTATION_INTERVAL_SECS", "43200"),
        ]);
        assert_eq!(c.key_rotation_interval_secs, 43200);
    }

    #[test]
    fn cors_allowed_origins_parsed() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("CORS_ALLOWED_ORIGINS", "https://app.example.com, https://other.example.com"),
        ]);
        assert_eq!(c.cors_allowed_origins, vec!["https://app.example.com", "https://other.example.com"]);
    }

    #[test]
    fn cors_allowed_origins_empty_by_default() {
        let c = minimal();
        assert!(c.cors_allowed_origins.is_empty());
    }

    #[test]
    fn trusted_proxies_enabled() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("TRUSTED_PROXIES", "true"),
        ]);
        assert!(c.trusted_proxies);
    }

    #[test]
    fn custom_token_expiry() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("ACCESS_TOKEN_EXPIRY_SECS", "300"),
            ("ID_TOKEN_EXPIRY_SECS", "120"),
            ("REFRESH_TOKEN_EXPIRY_DAYS", "7"),
        ]);
        assert_eq!(c.access_token_expiry_secs, 300);
        assert_eq!(c.id_token_expiry_secs, 120);
        assert_eq!(c.refresh_token_expiry_days, 7);
    }

    #[test]
    fn custom_max_request_body_bytes() {
        let c = config_from(&[
            ("ADMIN_EMAIL", "a@b.c"), ("ADMIN_PASSWORD", "s"),
            ("MAX_REQUEST_BODY_BYTES", "131072"),
        ]);
        assert_eq!(c.max_request_body_bytes, 131072);
    }
}
