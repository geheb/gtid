pub mod bot_trap;
pub mod content_type;
pub mod csrf;
pub mod lockout;
pub mod pending_redirect;
pub mod rate_limit;
pub mod security_headers;
pub mod session;

/// Rapidhash of `prefix|ip|ua` with a runtime seed — returns u64, used as DashMap key.
/// Pass an empty prefix if no namespace is needed.
pub(super) fn build_key(prefix: &str, ip: &str, ua: &str, seed: u64) -> u64 {
    let mut buf = Vec::with_capacity(prefix.len() + 1 + ip.len() + 1 + ua.len());
    buf.extend_from_slice(prefix.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(ip.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(ua.as_bytes());
    rapidhash::rapidhash_seeded(&buf, seed)
}
