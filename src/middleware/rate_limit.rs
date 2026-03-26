use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_ATTEMPTS: u32 = 3;
const WINDOW: Duration = Duration::from_secs(30); 
const MAX_TRACKED_KEYS: usize = 50_000;

#[derive(Clone)]
pub struct LoginRateLimiter {
    attempts: Arc<DashMap<String, Vec<Instant>>>,
    window: Duration,
    max_tracked_keys: usize,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
            window: WINDOW,
            max_tracked_keys: MAX_TRACKED_KEYS,
        }
    }

    #[cfg(test)]
    fn with_limits(window: Duration, max_tracked_keys: usize) -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
            window,
            max_tracked_keys,
        }
    }

    /// Returns true if the key (IP + User-Agent) is rate-limited.
    pub fn is_limited(&self, key: &str) -> bool {
        let now = Instant::now();

        if let Some(mut times) = self.attempts.get_mut(key) {
            times.retain(|t| now.checked_duration_since(*t).is_some_and(|d| d < self.window));
            times.len() >= MAX_ATTEMPTS as usize
        } else {
            false
        }
    }

    /// Records a failed attempt for the given key (IP + User-Agent).
    pub fn record_failure(&self, key: &str) {
        let now = Instant::now();

        // Evict keys whose windows have fully expired
        self.attempts.retain(|_, times| {
            times.iter().any(|t| now.checked_duration_since(*t).is_some_and(|d| d < self.window))
        });

        // DoS protection: refuse to track new keys beyond the limit
        if self.attempts.len() >= self.max_tracked_keys && !self.attempts.contains_key(key) {
            return;
        }

        let mut entry = self.attempts.entry(key.to_string()).or_default();
        entry.retain(|t| now.checked_duration_since(*t).is_some_and(|d| d < self.window));
        entry.push(now);
    }

    /// Clears attempts for the given key on successful login.
    pub fn clear(&self, key: &str) {
        self.attempts.remove(key);
    }

    #[cfg(test)]
    fn tracked_key_count(&self) -> usize {
        self.attempts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_limited_initially() {
        let rl = LoginRateLimiter::new();
        assert!(!rl.is_limited("login|1.2.3.4|Mozilla"));
    }

    #[test]
    fn limited_after_max_attempts() {
        let rl = LoginRateLimiter::new();
        for _ in 0..5 {
            rl.record_failure("login|1.2.3.4|Mozilla");
        }
        assert!(rl.is_limited("login|1.2.3.4|Mozilla"));
    }

    #[test]
    fn clear_resets() {
        let rl = LoginRateLimiter::new();
        for _ in 0..5 {
            rl.record_failure("login|1.2.3.4|Mozilla");
        }
        assert!(rl.is_limited("login|1.2.3.4|Mozilla"));
        rl.clear("login|1.2.3.4|Mozilla");
        assert!(!rl.is_limited("login|1.2.3.4|Mozilla"));
    }

    #[test]
    fn different_keys_isolated() {
        let rl = LoginRateLimiter::new();
        for _ in 0..5 {
            rl.record_failure("login|1.2.3.4|Mozilla");
        }
        assert!(rl.is_limited("login|1.2.3.4|Mozilla"));
        assert!(!rl.is_limited("login|5.6.7.8|Mozilla"));
        assert!(!rl.is_limited("login|1.2.3.4|Chrome"));
    }

    #[test]
    fn rejects_new_key_when_full() {
        let rl = LoginRateLimiter::with_limits(WINDOW, 2);
        rl.record_failure("login|1.1.1.1|ua1");
        rl.record_failure("login|2.2.2.2|ua2");
        assert_eq!(rl.tracked_key_count(), 2);

        rl.record_failure("login|3.3.3.3|ua3");
        assert_eq!(rl.tracked_key_count(), 2);
        assert!(!rl.is_limited("login|3.3.3.3|ua3"));
    }

    #[test]
    fn still_tracks_existing_key_when_full() {
        let rl = LoginRateLimiter::with_limits(WINDOW, 2);
        rl.record_failure("login|1.1.1.1|ua1");
        rl.record_failure("login|2.2.2.2|ua2");

        for _ in 0..4 {
            rl.record_failure("login|1.1.1.1|ua1");
        }
        assert!(rl.is_limited("login|1.1.1.1|ua1"));
    }

    #[test]
    fn accepts_new_key_after_clear() {
        let rl = LoginRateLimiter::with_limits(WINDOW, 2);
        rl.record_failure("login|1.1.1.1|ua1");
        rl.record_failure("login|2.2.2.2|ua2");

        rl.clear("login|1.1.1.1|ua1");
        rl.record_failure("login|3.3.3.3|ua3");
        assert_eq!(rl.tracked_key_count(), 2);
    }

    #[test]
    fn evicts_expired_keys() {
        let rl = LoginRateLimiter::with_limits(Duration::from_millis(50), 2);
        rl.record_failure("login|1.1.1.1|ua1");
        rl.record_failure("login|2.2.2.2|ua2");
        assert_eq!(rl.tracked_key_count(), 2);

        std::thread::sleep(Duration::from_millis(80));

        rl.record_failure("login|3.3.3.3|ua3");
        assert_eq!(rl.tracked_key_count(), 1);
    }
}
