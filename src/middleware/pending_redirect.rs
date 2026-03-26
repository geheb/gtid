use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

struct Entry {
    url: String,
    created: Instant,
}

const MAX_AGE_SECS: u64 = 600; // 10 minutes
const MAX_ENTRIES: usize = 10_000;

#[derive(Clone)]
pub struct PendingRedirectStore {
    inner: Arc<DashMap<String, Entry>>,
}

impl PendingRedirectStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    /// Stores a redirect URL and returns an opaque ID.
    pub fn store(&self, url: String) -> String {
        let id = crate::crypto::id::new_id();

        // Evict expired entries
        let cutoff = Instant::now() - std::time::Duration::from_secs(MAX_AGE_SECS);
        self.inner.retain(|_, entry| entry.created > cutoff);

        // DoS protection
        if self.inner.len() >= MAX_ENTRIES {
            return id;
        }

        self.inner.insert(id.clone(), Entry {
            url,
            created: Instant::now(),
        });
        id
    }

    /// Consumes and returns the redirect URL for the given ID (one-time use).
    pub fn take(&self, id: &str) -> Option<String> {
        let (_, entry) = self.inner.remove(id)?;
        if entry.created.elapsed().as_secs() > MAX_AGE_SECS {
            return None;
        }
        Some(entry.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_take() {
        let store = PendingRedirectStore::new();
        let id = store.store("http://example.com/cb".to_string());
        assert!(!id.is_empty());
        assert_eq!(store.take(&id), Some("http://example.com/cb".to_string()));
    }

    #[test]
    fn take_is_one_time() {
        let store = PendingRedirectStore::new();
        let id = store.store("http://example.com".to_string());
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
        let id1 = store.store("http://a.com".to_string());
        let id2 = store.store("http://b.com".to_string());
        assert_eq!(store.take(&id1), Some("http://a.com".to_string()));
        assert_eq!(store.take(&id2), Some("http://b.com".to_string()));
    }
}
