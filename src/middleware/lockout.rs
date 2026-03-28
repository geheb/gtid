use crate::middleware::TrackedStore;
use std::time::{Duration, Instant};

const MAX_TRACKED_KEYS: usize = 50_000;

struct LockoutEntry {
    attempts: u32,
    locked_until: Option<Instant>,
}

#[derive(Clone)]
pub struct AccountLockout {
    store: TrackedStore<LockoutEntry>,
    max_attempts: u32,
    lockout_duration: Duration,
}

impl AccountLockout {
    pub fn new(max_attempts: u32, lockout_duration_secs: u64) -> Self {
        Self {
            store: TrackedStore::new(MAX_TRACKED_KEYS),
            max_attempts,
            lockout_duration: Duration::from_secs(lockout_duration_secs),
        }
    }

    fn key(&self, email: &str) -> u64 {
        self.store.key_str(&email.to_lowercase())
    }

    /// Returns true if the account (by email) is currently locked.
    pub fn is_locked(&self, email: &str) -> bool {
        let key = self.key(email);
        if let Some(entry) = self.store.map.get(&key) {
            if let Some(until) = entry.locked_until {
                if until.checked_duration_since(Instant::now()).is_some() {
                    return true;
                }
            }
        }
        // Lock expired — clean up outside read guard
        self.store.map.remove_if(&key, |_, e| {
            e.locked_until
                .is_some_and(|until| until.checked_duration_since(Instant::now()).is_none())
        });
        false
    }

    /// Records a failed login attempt. Locks the account if max_attempts is reached.
    pub fn record_failure(&self, email: &str) {
        let key = self.key(email);
        self.store.evict(|e| {
            e.locked_until
                .is_some_and(|until| until.checked_duration_since(Instant::now()).is_none())
        });
        if !self.store.can_insert(key) {
            return;
        }
        let mut entry = self.store.map.entry(key).or_insert(LockoutEntry {
            attempts: 0,
            locked_until: None,
        });
        entry.attempts += 1;
        if entry.attempts >= self.max_attempts {
            entry.locked_until = Some(Instant::now() + self.lockout_duration);
        }
    }

    pub fn locked_count(&self) -> usize {
        let now = Instant::now();
        self.store
            .map
            .iter()
            .filter(|e| e.locked_until.is_some_and(|until| until.checked_duration_since(now).is_some()))
            .count()
    }

    /// Clears failed attempts on successful login.
    pub fn clear(&self, email: &str) {
        self.store.map.remove(&self.key(email));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_locked_initially() {
        let lo = AccountLockout::new(3, 60);
        assert!(!lo.is_locked("test@example.com"));
    }

    #[test]
    fn locked_after_max_attempts() {
        let lo = AccountLockout::new(3, 3600);
        for _ in 0..3 {
            lo.record_failure("test@example.com");
        }
        assert!(lo.is_locked("test@example.com"));
    }

    #[test]
    fn case_insensitive_email() {
        let lo = AccountLockout::new(3, 3600);
        lo.record_failure("Test@Example.COM");
        lo.record_failure("test@example.com");
        lo.record_failure("TEST@EXAMPLE.COM");
        assert!(lo.is_locked("test@example.com"));
        assert!(lo.is_locked("Test@Example.COM"));
    }

    #[test]
    fn clear_resets_lockout() {
        let lo = AccountLockout::new(3, 3600);
        for _ in 0..3 {
            lo.record_failure("test@example.com");
        }
        assert!(lo.is_locked("test@example.com"));
        lo.clear("test@example.com");
        assert!(!lo.is_locked("test@example.com"));
    }

    #[test]
    fn locked_count() {
        let lo = AccountLockout::new(2, 3600);
        for _ in 0..2 {
            lo.record_failure("a@b.com");
        }
        for _ in 0..2 {
            lo.record_failure("c@d.com");
        }
        assert_eq!(lo.locked_count(), 2);
        lo.clear("a@b.com");
        assert_eq!(lo.locked_count(), 1);
    }
}
