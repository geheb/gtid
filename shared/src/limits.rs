// Field length limits (SECURITY.md §2) — shared between gtid-api and gtid-ui.
pub const MAX_CSRF_TOKEN: usize = 64; // SHA256 hex
pub const MAX_EMAIL: usize = 254; // RFC 5321
pub const MAX_PASSWORD: usize = 256;
pub const MAX_DISPLAY_NAME: usize = 200;
pub const MAX_UUID: usize = 36; // UUID v6 (pending_id, rid)
pub const MAX_CLIENT_ID: usize = 128;
pub const MAX_CLIENT_SECRET: usize = 256;
pub const MAX_URI: usize = 2048; // redirect_uri, post_logout_uri
pub const MAX_SETUP_TOKEN: usize = 128;
pub const MAX_RESET_TOKEN: usize = 128; // hex-encoded SHA256 hash input
pub const MAX_ROLE: usize = 64;
pub const MAX_SCOPE: usize = 1024;
pub const MAX_CODE_VERIFIER: usize = 128;
pub const MAX_GRANT_TYPE: usize = 32;
pub const MAX_LANG: usize = 10;
pub const MAX_SUBJECT: usize = 500;
pub const MAX_REFRESH_TOKEN: usize = 2048;
