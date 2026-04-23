use sha2::{Digest, Sha256};

pub fn sha256_hex(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = sha256_hex("test-token");
        let b = sha256_hex("test-token");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }

    #[test]
    fn returns_hex_string() {
        let h = sha256_hex("hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
