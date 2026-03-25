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
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            issuer_uri: env::var("ISSUER_URI").unwrap_or_else(|_| "http://localhost:3000".into()),
            public_ui_uri: env::var("PUBLIC_UI_URI").unwrap_or_else(|_| "http://localhost:3001".into()),
            ui_listen_port: env::var("UI_LISTEN_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3001),
            api_listen_port: env::var("API_LISTEN_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),
            database_uri: env::var("DATABASE_URI")
                .unwrap_or_else(|_| "sqlite:gtid.db".into()),
            admin_email: env::var("ADMIN_EMAIL").expect("ADMIN_EMAIL must be set"),
            admin_password: env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set"),
            roles: {
                let mut roles = vec!["admin".to_string()];
                if let Ok(val) = env::var("ROLES") {
                    for r in val.split(',') {
                        let r = r.trim().to_lowercase();
                        if !r.is_empty() && r != "admin" {
                            roles.push(r);
                        }
                    }
                }
                roles
            },
            lockout_max_attempts: env::var("LOCKOUT_MAX_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
            lockout_duration_secs: env::var("LOCKOUT_DURATION_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            secure_cookies: env::var("SECURE_COOKIES")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
            session_lifetime_secs: env::var("SESSION_LIFETIME_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),
            allowed_grant_types: env::var("ALLOWED_GRANT_TYPES")
                .unwrap_or_else(|_| "authorization_code,refresh_token".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            key_rotation_interval_secs: env::var("KEY_ROTATION_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),
        }
    }

    pub fn grant_type_allowed(&self, grant_type: &str) -> bool {
        self.allowed_grant_types.iter().any(|g| g == grant_type)
    }
}
