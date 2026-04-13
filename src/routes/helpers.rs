use axum::{
    http::{HeaderMap, header},
};
use std::net::SocketAddr;

/// Extracts the User-Agent header, returning an error if missing or empty.
pub fn require_user_agent(headers: &HeaderMap) -> Result<&str, String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "Missing User-Agent header".to_string())
}

/// Extracts the client IP, using X-Forwarded-For when trusted_proxies is enabled.
pub fn client_ip(headers: &HeaderMap, addr: &SocketAddr, trusted_proxies: bool) -> String {
    if trusted_proxies
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first_ip) = xff.split(',').next().map(|s| s.trim())
        && !first_ip.is_empty()
    {
        return first_ip.to_string();
    }
    addr.ip().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn require_user_agent_present() {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("TestAgent/1.0"));
        assert_eq!(require_user_agent(&headers).unwrap(), "TestAgent/1.0");
    }

    #[test]
    fn require_user_agent_missing() {
        let headers = HeaderMap::new();
        assert!(require_user_agent(&headers).is_err());
    }

    #[test]
    fn require_user_agent_empty() {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static(""));
        assert!(require_user_agent(&headers).is_err());
    }

    #[test]
    fn client_ip_without_proxy() {
        let headers = HeaderMap::new();
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, &addr, false), "192.168.1.1");
    }

    #[test]
    fn client_ip_ignores_xff_when_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1, 10.0.0.2"));
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, &addr, false), "192.168.1.1");
    }

    #[test]
    fn client_ip_uses_xff_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.5, 10.0.0.1"));
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, &addr, true), "203.0.113.5");
    }

    #[test]
    fn client_ip_falls_back_without_xff_header() {
        let headers = HeaderMap::new();
        let addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        assert_eq!(client_ip(&headers, &addr, true), "192.168.1.1");
    }
}
