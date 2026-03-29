use dashmap::DashMap;
use rand::Rng;
use std::sync::Arc;

/// Capacity-bounded, hashed-key store backed by DashMap.
/// Shared by `rate_limit` and `bot_trap` to avoid duplicating Arc/seed/eviction boilerplate.
pub struct TrackedStore<V> {
    pub map: Arc<DashMap<u64, V>>,
    max_keys: usize,
    seed: u64,
}

impl<V> TrackedStore<V> {
    pub fn new(max_keys: usize) -> Self {
        Self {
            map: Arc::new(DashMap::new()),
            max_keys,
            seed: rand::rng().next_u64(),
        }
    }

    #[cfg(test)]
    pub fn with_seed(max_keys: usize, seed: u64) -> Self {
        Self { map: Arc::new(DashMap::new()), max_keys, seed }
    }

    /// Rapidhash of a single string with the runtime seed.
    pub fn key_str(&self, s: &str) -> u64 {
        rapidhash::rapidhash_seeded(s.as_bytes(), self.seed)
    }

    /// Rapidhash of `prefix|ip|ua` with a runtime seed - returns u64, used as DashMap key.
    /// Pass an empty prefix if no namespace is needed.
    pub fn key(&self, prefix: &str, ip: &str, ua: &str) -> u64 {
        let mut buf = Vec::with_capacity(prefix.len() + 1 + ip.len() + 1 + ua.len());
        buf.extend_from_slice(prefix.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(ip.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(ua.as_bytes());
        rapidhash::rapidhash_seeded(&buf, self.seed)
    }

    /// Returns true if inserting `key` is allowed (within capacity or key already tracked).
    pub fn can_insert(&self, key: u64) -> bool {
        self.map.len() < self.max_keys || self.map.contains_key(&key)
    }

    /// Remove all entries for which `is_expired` returns true.
    pub fn evict<F: Fn(&V) -> bool>(&self, is_expired: F) {
        self.map.retain(|_, v| !is_expired(v));
    }
}

impl<V> Clone for TrackedStore<V> {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
            max_keys: self.max_keys,
            seed: self.seed,
        }
    }
}
