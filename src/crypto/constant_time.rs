use subtle::ConstantTimeEq;

/// Constant-time byte comparison to prevent timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time string comparison.
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_bytes() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn different_bytes() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn string_variant() {
        assert!(constant_time_str_eq("abc", "abc"));
        assert!(!constant_time_str_eq("abc", "xyz"));
    }
}
