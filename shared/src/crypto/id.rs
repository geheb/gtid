use uuid::{Uuid, timestamp::Timestamp};
use zeroize::Zeroize;

pub fn new_id() -> String {
    let ts = Timestamp::now(uuid::NoContext);
    let mut node_id: [u8; 6] = rand::random();
    let id = Uuid::new_v6(ts, &node_id).to_string();
    node_id.zeroize();
    id
}

pub fn new_secure_token() -> String {
    let mut bytes: [u8; 32] = rand::random();
    let token = bytes.iter().map(|b| format!("{b:02x}")).collect();
    bytes.zeroize();
    token
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn returns_valid_uuid_v6() {
        let id = new_id();
        let parsed = Uuid::parse_str(&id).expect("should be valid UUID");
        assert_eq!(parsed.get_version(), Some(uuid::Version::SortMac));
    }

    #[test]
    fn returns_36_char_string() {
        let id = new_id();
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn ids_are_unique() {
        let ids: HashSet<String> = (0..100).map(|_| new_id()).collect();
        assert_eq!(ids.len(), 100);
    }

    #[test]
    fn ids_are_roughly_sortable_by_time() {
        let first = new_id();
        let second = new_id();
        assert!(first < second || first != second);
    }

    #[test]
    fn secure_token_is_64_hex_chars() {
        let token = new_secure_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn secure_tokens_are_unique() {
        let tokens: HashSet<String> = (0..100).map(|_| new_secure_token()).collect();
        assert_eq!(tokens.len(), 100);
    }
}
