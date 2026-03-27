use crate::middleware::build_key;
use dashmap::DashMap;
use rand::Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_ATTEMPTS: u32 = 3;
const WINDOW: Duration = Duration::from_secs(30);
const MAX_TRACKED_KEYS: usize = 50_000;

#[derive(Clone)]
pub struct LoginRateLimiter {
    attempts: Arc<DashMap<u64, Vec<Instant>>>,
    window: Duration,
    max_tracked_keys: usize,
    seed: u64,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
            window: WINDOW,
            max_tracked_keys: MAX_TRACKED_KEYS,
            seed: rand::rng().next_u64(),
        }
    }

    #[cfg(test)]
    fn with_limits(window: Duration, max_tracked_keys: usize) -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
            window,
            max_tracked_keys,
            seed: 0,
        }
    }

    pub fn key(&self, prefix: &str, ip: &str, ua: &str) -> u64 {
        build_key(prefix, ip, ua, self.seed)
    }

    /// Returns true if the key is rate-limited.
    pub fn is_limited(&self, key: u64) -> bool {
        let now = Instant::now();
        if let Some(mut times) = self.attempts.get_mut(&key) {
            times.retain(|t| now.checked_duration_since(*t).is_some_and(|d| d < self.window));
            times.len() >= MAX_ATTEMPTS as usize
        } else {
            false
        }
    }

    /// Records a failed attempt for the given key.
    pub fn record_failure(&self, key: u64) {
        let now = Instant::now();

        // Evict keys whose windows have fully expired
        self.attempts.retain(|_, times| {
            times.iter().any(|t| now.checked_duration_since(*t).is_some_and(|d| d < self.window))
        });

        // DoS protection: refuse to track new keys beyond the limit
        if self.attempts.len() >= self.max_tracked_keys && !self.attempts.contains_key(&key) {
            return;
        }

        let mut entry = self.attempts.entry(key).or_default();
        entry.retain(|t| now.checked_duration_since(*t).is_some_and(|d| d < self.window));
        entry.push(now);
    }

    /// Clears attempts for the given key on successful login.
    pub fn clear(&self, key: u64) {
        self.attempts.remove(&key);
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
        assert!(!rl.is_limited(rl.key("login", "1.2.3.4", "Mozilla")));
    }

    #[test]
    fn limited_after_max_attempts() {
        let rl = LoginRateLimiter::new();
        let key = rl.key("login", "1.2.3.4", "Mozilla");
        for _ in 0..5 {
            rl.record_failure(key);
        }
        assert!(rl.is_limited(key));
    }

    #[test]
    fn clear_resets() {
        let rl = LoginRateLimiter::new();
        let key = rl.key("login", "1.2.3.4", "Mozilla");
        for _ in 0..5 {
            rl.record_failure(key);
        }
        assert!(rl.is_limited(key));
        rl.clear(key);
        assert!(!rl.is_limited(key));
    }

    #[test]
    fn different_keys_isolated() {
        let rl = LoginRateLimiter::new();
        let key = rl.key("login", "1.2.3.4", "Mozilla");
        for _ in 0..5 {
            rl.record_failure(key);
        }
        assert!(rl.is_limited(key));
        assert!(!rl.is_limited(rl.key("login", "5.6.7.8", "Mozilla")));
        assert!(!rl.is_limited(rl.key("login", "1.2.3.4", "Chrome")));
    }

    #[test]
    fn rejects_new_key_when_full() {
        let rl = LoginRateLimiter::with_limits(WINDOW, 2);
        rl.record_failure(rl.key("login", "1.1.1.1", "ua1"));
        rl.record_failure(rl.key("login", "2.2.2.2", "ua2"));
        assert_eq!(rl.tracked_key_count(), 2);

        rl.record_failure(rl.key("login", "3.3.3.3", "ua3"));
        assert_eq!(rl.tracked_key_count(), 2);
        assert!(!rl.is_limited(rl.key("login", "3.3.3.3", "ua3")));
    }

    #[test]
    fn still_tracks_existing_key_when_full() {
        let rl = LoginRateLimiter::with_limits(WINDOW, 2);
        let key1 = rl.key("login", "1.1.1.1", "ua1");
        rl.record_failure(key1);
        rl.record_failure(rl.key("login", "2.2.2.2", "ua2"));

        for _ in 0..4 {
            rl.record_failure(key1);
        }
        assert!(rl.is_limited(key1));
    }

    #[test]
    fn accepts_new_key_after_clear() {
        let rl = LoginRateLimiter::with_limits(WINDOW, 2);
        let key1 = rl.key("login", "1.1.1.1", "ua1");
        rl.record_failure(key1);
        rl.record_failure(rl.key("login", "2.2.2.2", "ua2"));

        rl.clear(key1);
        rl.record_failure(rl.key("login", "3.3.3.3", "ua3"));
        assert_eq!(rl.tracked_key_count(), 2);
    }

    #[test]
    fn evicts_expired_keys() {
        let rl = LoginRateLimiter::with_limits(Duration::from_millis(50), 2);
        rl.record_failure(rl.key("login", "1.1.1.1", "ua1"));
        rl.record_failure(rl.key("login", "2.2.2.2", "ua2"));
        assert_eq!(rl.tracked_key_count(), 2);

        std::thread::sleep(Duration::from_millis(80));

        rl.record_failure(rl.key("login", "3.3.3.3", "ua3"));
        assert_eq!(rl.tracked_key_count(), 1);
    }

    #[test]
    fn keys_are_hashed() {
        let rl = LoginRateLimiter::with_limits(WINDOW, MAX_TRACKED_KEYS);
        let key = rl.key("login", "10.0.0.1", "Agent");
        rl.record_failure(key);
        assert!(rl.attempts.contains_key(&key));
        assert_ne!(
            rl.key("login", "10.0.0.1", "Agent"),
            rl.key("login", "10.0.0.2", "Agent"),
        );
        assert_ne!(
            rl.key("login", "10.0.0.1", "Agent"),
            rl.key("token", "10.0.0.1", "Agent"),
        );
    }
}
