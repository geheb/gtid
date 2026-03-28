use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Entry {
    url: String,
    created: Instant,
}

const MAX_AGE: Duration = Duration::from_secs(600); // 10 minutes
const MAX_ENTRIES: usize = 10_000;

#[derive(Clone)]
pub struct PendingRedirectStore {
    inner: Arc<DashMap<String, Entry>>,
    max_age: Duration,
    max_entries: usize,
}

impl PendingRedirectStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            max_age: MAX_AGE,
            max_entries: MAX_ENTRIES,
        }
    }

    #[cfg(test)]
    fn with_limits(max_age: Duration, max_entries: usize) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            max_age,
            max_entries,
        }
    }

    /// Stores a redirect URL and returns an opaque ID, or `None` if at capacity.
    pub fn store(&self, url: String) -> Option<String> {
        let id = crate::crypto::id::new_id();

        // Evict expired entries (checked_sub avoids overflow on Windows
        // when the process uptime is shorter than max_age)
        if let Some(cutoff) = Instant::now().checked_sub(self.max_age) {
            self.inner.retain(|_, entry| entry.created > cutoff);
        }

        // DoS protection
        if self.inner.len() >= self.max_entries {
            return None;
        }

        self.inner.insert(id.clone(), Entry {
            url,
            created: Instant::now(),
        });
        Some(id)
    }

    /// Consumes and returns the redirect URL for the given ID (one-time use).
    pub fn take(&self, id: &str) -> Option<String> {
        let (_, entry) = self.inner.remove(id)?;
        if entry.created.elapsed() > self.max_age {
            return None;
        }
        Some(entry.url)
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_take() {
        let store = PendingRedirectStore::new();
        let id = store.store("http://example.com/cb".to_string()).unwrap();
        assert!(!id.is_empty());
        assert_eq!(store.take(&id), Some("http://example.com/cb".to_string()));
    }

    #[test]
    fn take_is_one_time() {
        let store = PendingRedirectStore::new();
        let id = store.store("http://example.com".to_string()).unwrap();
        assert!(store.take(&id).is_some());
        assert!(store.take(&id).is_none()); // second take returns None
    }

    #[test]
    fn unknown_id_returns_none() {
        let store = PendingRedirectStore::new();
        assert!(store.take("nonexistent").is_none());
    }

    #[test]
    fn multiple_entries_isolated() {
        let store = PendingRedirectStore::new();
        let id1 = store.store("http://a.com".to_string()).unwrap();
        let id2 = store.store("http://b.com".to_string()).unwrap();
        assert_eq!(store.take(&id1), Some("http://a.com".to_string()));
        assert_eq!(store.take(&id2), Some("http://b.com".to_string()));
    }

    #[test]
    fn take_returns_none_after_expiry() {
        let store = PendingRedirectStore::with_limits(Duration::from_millis(50), MAX_ENTRIES);
        let id = store.store("http://example.com".to_string()).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(store.take(&id), None);
    }

    #[test]
    fn store_evicts_expired_entries() {
        let store = PendingRedirectStore::with_limits(Duration::from_millis(50), MAX_ENTRIES);
        store.store("http://old.com".to_string()).unwrap();
        assert_eq!(store.entry_count(), 1);
        std::thread::sleep(Duration::from_millis(80));
        store.store("http://new.com".to_string()).unwrap(); // triggers eviction
        assert_eq!(store.entry_count(), 1); // old entry evicted
    }

    #[test]
    fn store_rejects_when_full() {
        let store = PendingRedirectStore::with_limits(MAX_AGE, 3);
        let id1 = store.store("http://a.com".to_string()).unwrap();
        let id2 = store.store("http://b.com".to_string()).unwrap();
        let id3 = store.store("http://c.com".to_string()).unwrap();
        assert_eq!(store.entry_count(), 3);

        // 4th store should return None
        assert!(store.store("http://d.com".to_string()).is_none());
        assert_eq!(store.entry_count(), 3);

        // existing entries still accessible
        assert_eq!(store.take(&id1), Some("http://a.com".to_string()));
        assert_eq!(store.take(&id2), Some("http://b.com".to_string()));
        assert_eq!(store.take(&id3), Some("http://c.com".to_string()));
    }

    #[test]
    fn store_accepts_again_after_take_frees_slot() {
        let store = PendingRedirectStore::with_limits(MAX_AGE, 2);
        let id1 = store.store("http://a.com".to_string()).unwrap();
        store.store("http://b.com".to_string()).unwrap();
        assert_eq!(store.entry_count(), 2);

        // full — new entry rejected
        assert!(store.store("http://c.com".to_string()).is_none());
        assert_eq!(store.entry_count(), 2);

        // free a slot
        store.take(&id1);
        assert_eq!(store.entry_count(), 1);

        // now a new entry is accepted
        let id4 = store.store("http://d.com".to_string()).unwrap();
        assert_eq!(store.entry_count(), 2);
        assert_eq!(store.take(&id4), Some("http://d.com".to_string()));
    }
}
