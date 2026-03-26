use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

const MAX_ATTEMPTS: u32 = 5;
const WINDOW_SECS: u64 = 900; // 15 minutes

#[derive(Clone)]
pub struct LoginRateLimiter {
    attempts: Arc<DashMap<String, Vec<Instant>>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
        }
    }

    /// Returns true if the IP is rate-limited.
    pub fn is_limited(&self, ip: &str) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(WINDOW_SECS);

        if let Some(mut times) = self.attempts.get_mut(ip) {
            times.retain(|t| now.checked_duration_since(*t).is_some_and(|d| d < window));
            times.len() >= MAX_ATTEMPTS as usize
        } else {
            false
        }
    }

    /// Records a failed login attempt for the given IP.
    pub fn record_failure(&self, ip: &str) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(WINDOW_SECS);

        let mut entry = self.attempts.entry(ip.to_string()).or_default();
        entry.retain(|t| now.checked_duration_since(*t).is_some_and(|d| d < window));
        entry.push(now);
    }

    /// Clears attempts for the given IP on successful login.
    pub fn clear(&self, ip: &str) {
        self.attempts.remove(ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_limited_initially() {
        let rl = LoginRateLimiter::new();
        assert!(!rl.is_limited("1.2.3.4"));
    }

    #[test]
    fn limited_after_max_attempts() {
        let rl = LoginRateLimiter::new();
        for _ in 0..5 {
            rl.record_failure("1.2.3.4");
        }
        assert!(rl.is_limited("1.2.3.4"));
    }

    #[test]
    fn clear_resets() {
        let rl = LoginRateLimiter::new();
        for _ in 0..5 {
            rl.record_failure("1.2.3.4");
        }
        assert!(rl.is_limited("1.2.3.4"));
        rl.clear("1.2.3.4");
        assert!(!rl.is_limited("1.2.3.4"));
    }

    #[test]
    fn different_ips_isolated() {
        let rl = LoginRateLimiter::new();
        for _ in 0..5 {
            rl.record_failure("1.2.3.4");
        }
        assert!(rl.is_limited("1.2.3.4"));
        assert!(!rl.is_limited("5.6.7.8"));
    }
}
