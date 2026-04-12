use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Entry {
    pub user_id: String,
    pub rid: Option<String>,
    pub totp_secret: Option<String>,
    used_codes: Vec<String>,
    created: Instant,
}

const MAX_AGE: Duration = Duration::from_secs(600); // 10 minutes
const MAX_ENTRIES: usize = 1_000;

#[derive(Clone)]
pub struct Pending2faStore {
    inner: Arc<DashMap<String, Entry>>,
    max_age: Duration,
    max_entries: usize,
}

impl Pending2faStore {
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

    /// Stores a pending 2FA entry and returns an opaque ID, or `None` if at capacity.
    pub fn store(&self, user_id: String, rid: Option<String>, totp_secret: Option<String>) -> Option<String> {
        let id = crate::crypto::id::new_id();

        if let Some(cutoff) = Instant::now().checked_sub(self.max_age) {
            self.inner.retain(|_, entry| entry.created > cutoff);
        }

        if self.inner.len() >= self.max_entries {
            return None;
        }

        self.inner.insert(id.clone(), Entry {
            user_id,
            rid,
            totp_secret,
            used_codes: Vec::new(),
            created: Instant::now(),
        });
        Some(id)
    }

    /// Reads the entry without consuming it (for repeated form renderings).
    /// Returns None if expired or not found.
    pub fn get(&self, id: &str) -> Option<dashmap::mapref::one::Ref<'_, String, Entry>> {
        let entry = self.inner.get(id)?;
        if entry.created.elapsed() > self.max_age {
            drop(entry);
            self.inner.remove(id);
            return None;
        }
        Some(entry)
    }

    /// Updates the totp_secret for an existing entry.
    pub fn set_totp_secret(&self, id: &str, secret: String) {
        if let Some(mut entry) = self.inner.get_mut(id) {
            entry.totp_secret = Some(secret);
        }
    }

    /// Returns true if the code was already used for this pending entry (replay prevention).
    pub fn is_code_used(&self, id: &str, code: &str) -> bool {
        self.inner.get(id)
            .is_some_and(|e| e.used_codes.iter().any(|c| c == code))
    }

    /// Marks a code as used for this pending entry.
    pub fn mark_code_used(&self, id: &str, code: &str) {
        if let Some(mut entry) = self.inner.get_mut(id) {
            entry.used_codes.push(code.to_string());
        }
    }

    /// Consumes and returns the entry (one-time use on success).
    pub fn take(&self, id: &str) -> Option<Entry> {
        let (_, entry) = self.inner.remove(id)?;
        if entry.created.elapsed() > self.max_age {
            return None;
        }
        Some(entry)
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
        let store = Pending2faStore::new();
        let id = store.store("user-1".into(), None, None).unwrap();
        let entry = store.take(&id).unwrap();
        assert_eq!(entry.user_id, "user-1");
    }

    #[test]
    fn take_is_one_time() {
        let store = Pending2faStore::new();
        let id = store.store("user-1".into(), None, None).unwrap();
        assert!(store.take(&id).is_some());
        assert!(store.take(&id).is_none());
    }

    #[test]
    fn get_does_not_consume() {
        let store = Pending2faStore::new();
        let id = store.store("user-1".into(), Some("rid-1".into()), None).unwrap();
        {
            let entry = store.get(&id).unwrap();
            assert_eq!(entry.user_id, "user-1");
            assert_eq!(entry.rid.as_deref(), Some("rid-1"));
        }
        // Still available after get
        assert!(store.get(&id).is_some());
        assert!(store.take(&id).is_some());
    }

    #[test]
    fn set_totp_secret_updates_entry() {
        let store = Pending2faStore::new();
        let id = store.store("user-1".into(), None, None).unwrap();
        assert!(store.get(&id).unwrap().totp_secret.is_none());
        store.set_totp_secret(&id, "SECRET123".into());
        assert_eq!(store.get(&id).unwrap().totp_secret.as_deref(), Some("SECRET123"));
    }

    #[test]
    fn unknown_id_returns_none() {
        let store = Pending2faStore::new();
        assert!(store.get("nonexistent").is_none());
        assert!(store.take("nonexistent").is_none());
    }

    #[test]
    fn expired_entries_removed() {
        let store = Pending2faStore::with_limits(Duration::from_millis(50), MAX_ENTRIES);
        let id = store.store("user-1".into(), None, None).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        assert!(store.get(&id).is_none());
        assert!(store.take(&id).is_none());
    }

    #[test]
    fn store_evicts_expired() {
        let store = Pending2faStore::with_limits(Duration::from_millis(50), MAX_ENTRIES);
        store.store("old".into(), None, None).unwrap();
        assert_eq!(store.entry_count(), 1);
        std::thread::sleep(Duration::from_millis(80));
        store.store("new".into(), None, None).unwrap();
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn store_rejects_when_full() {
        let store = Pending2faStore::with_limits(MAX_AGE, 2);
        store.store("u1".into(), None, None).unwrap();
        store.store("u2".into(), None, None).unwrap();
        assert!(store.store("u3".into(), None, None).is_none());
    }

    #[test]
    fn rid_preserved() {
        let store = Pending2faStore::new();
        let id = store.store("user-1".into(), Some("/authorize?...".into()), None).unwrap();
        let entry = store.take(&id).unwrap();
        assert_eq!(entry.rid.as_deref(), Some("/authorize?..."));
    }

    #[test]
    fn code_replay_prevention() {
        let store = Pending2faStore::new();
        let id = store.store("user-1".into(), None, None).unwrap();

        assert!(!store.is_code_used(&id, "123456"));
        store.mark_code_used(&id, "123456");
        assert!(store.is_code_used(&id, "123456"));

        // Different code is not affected
        assert!(!store.is_code_used(&id, "654321"));
    }

    #[test]
    fn code_replay_unknown_id() {
        let store = Pending2faStore::new();
        assert!(!store.is_code_used("nonexistent", "123456"));
    }
}
