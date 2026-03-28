use crate::middleware::TrackedStore;
use std::time::{Duration, Instant};

/// Number of unknown-path hits before the IP+UA combo gets blocked.
const STRIKE_THRESHOLD: u32 = 3;

/// How long an IP+UA stays blocked after reaching the threshold.
const BAN_DURATION: Duration = Duration::from_secs(3600);

/// Maximum tracked keys to prevent memory exhaustion.
const MAX_TRACKED_KEYS: usize = 100_000;

struct BanEntry {
    strikes: u32,
    banned_at: Option<Instant>,
}

#[derive(Clone)]
pub struct BotTrap {
    store: TrackedStore<BanEntry>,
}

impl BotTrap {
    pub fn new() -> Self {
        Self { store: TrackedStore::new(MAX_TRACKED_KEYS) }
    }

    #[cfg(test)]
    fn with_max_keys(max_tracked_keys: usize) -> Self {
        Self { store: TrackedStore::with_seed(max_tracked_keys, 0) }
    }

    pub fn key(&self, ip: &str, ua: &str) -> u64 {
        self.store.key("", ip, ua)
    }

    /// Returns true if this key is currently banned.
    pub fn is_banned(&self, key: u64) -> bool {
        if let Some(entry) = self.store.map.get(&key) {
            if let Some(banned_at) = entry.banned_at {
                if banned_at.elapsed() < BAN_DURATION {
                    return true;
                }
            }
        }
        // Expired ban — clean up outside read guard
        self.store.map.remove_if(&key, |_, e| {
            e.banned_at.is_some_and(|at| at.elapsed() >= BAN_DURATION)
        });
        false
    }

    /// Records a strike for this key. Returns true if now banned.
    pub fn record_strike(&self, key: u64) -> bool {
        self.store.evict(|e| e.banned_at.is_some_and(|at| at.elapsed() >= BAN_DURATION));

        if !self.store.can_insert(key) {
            return false;
        }

        let mut entry = self.store.map.entry(key).or_insert(BanEntry {
            strikes: 0,
            banned_at: None,
        });
        entry.strikes += 1;
        if entry.strikes >= STRIKE_THRESHOLD {
            entry.banned_at = Some(Instant::now());
            true
        } else {
            false
        }
    }

    pub fn banned_count(&self) -> usize {
        self.store.map
            .iter()
            .filter(|e| e.banned_at.is_some_and(|at| at.elapsed() < BAN_DURATION))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_banned_initially() {
        let trap = BotTrap::new();
        assert!(!trap.is_banned(trap.key("1.2.3.4", "Mozilla")));
    }

    #[test]
    fn banned_after_threshold() {
        let trap = BotTrap::new();
        let key = trap.key("1.2.3.4", "Mozilla");
        for i in 0..STRIKE_THRESHOLD {
            let banned = trap.record_strike(key);
            assert_eq!(banned, i + 1 >= STRIKE_THRESHOLD);
        }
        assert!(trap.is_banned(key));
    }

    #[test]
    fn different_keys_isolated() {
        let trap = BotTrap::new();
        let key = trap.key("1.1.1.1", "Bot");
        for _ in 0..STRIKE_THRESHOLD {
            trap.record_strike(key);
        }
        assert!(trap.is_banned(key));
        assert!(!trap.is_banned(trap.key("2.2.2.2", "Bot")));
        assert!(!trap.is_banned(trap.key("1.1.1.1", "Chrome")));
    }

    #[test]
    fn banned_count() {
        let trap = BotTrap::new();
        for _ in 0..STRIKE_THRESHOLD {
            trap.record_strike(trap.key("1.1.1.1", "Bot1"));
        }
        for _ in 0..STRIKE_THRESHOLD {
            trap.record_strike(trap.key("2.2.2.2", "Bot2"));
        }
        assert_eq!(trap.banned_count(), 2);
    }

    #[test]
    fn ban_expires() {
        // Instant subtraction can overflow on systems with low uptime; skip gracefully.
        let Some(past) = Instant::now().checked_sub(BAN_DURATION + Duration::from_secs(1)) else {
            return;
        };
        let trap = BotTrap::with_max_keys(MAX_TRACKED_KEYS);
        let key = trap.key("1.2.3.4", "old-bot");
        trap.store.map.insert(key, BanEntry { strikes: STRIKE_THRESHOLD, banned_at: Some(past) });
        assert!(!trap.is_banned(key));
    }

    #[test]
    fn respects_max_tracked_keys() {
        let trap = BotTrap::with_max_keys(3);
        trap.record_strike(trap.key("ip0", "ua0"));
        trap.record_strike(trap.key("ip1", "ua1"));
        trap.record_strike(trap.key("ip2", "ua2"));
        assert_eq!(trap.store.map.len(), 3);
        // 4th unique key should be refused (returns false = not banned, but also not tracked)
        trap.record_strike(trap.key("ip3", "ua3"));
        assert_eq!(trap.store.map.len(), 3);
        assert!(!trap.is_banned(trap.key("ip3", "ua3")));
    }

    #[test]
    fn keys_are_hashed() {
        let trap = BotTrap::with_max_keys(MAX_TRACKED_KEYS);
        let key = trap.key("10.0.0.1", "LongUserAgent/1.0");
        trap.record_strike(key);
        assert!(trap.store.map.contains_key(&key));
        assert_ne!(
            trap.key("10.0.0.1", "LongUserAgent/1.0"),
            trap.key("10.0.0.2", "LongUserAgent/1.0"),
        );
    }
}
