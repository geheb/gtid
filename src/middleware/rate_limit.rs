use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

const MAX_ATTEMPTS: u32 = 5;
const WINDOW_SECS: u64 = 900; // 15 minutes

#[derive(Clone)]
pub struct LoginRateLimiter {
    attempts: std::sync::Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns true if the IP is rate-limited.
    pub fn is_limited(&self, ip: &str) -> bool {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = std::time::Duration::from_secs(WINDOW_SECS);

        if let Some(times) = map.get_mut(ip) {
            times.retain(|t| now.checked_duration_since(*t).is_some_and(|d| d < window));
            times.len() >= MAX_ATTEMPTS as usize
        } else {
            false
        }
    }

    /// Records a failed login attempt for the given IP.
    pub fn record_failure(&self, ip: &str) {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = std::time::Duration::from_secs(WINDOW_SECS);

        let times = map.entry(ip.to_string()).or_default();
        times.retain(|t| now.checked_duration_since(*t).is_some_and(|d| d < window));
        times.push(now);
    }

    /// Clears attempts for the given IP on successful login.
    pub fn clear(&self, ip: &str) {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(ip);
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
