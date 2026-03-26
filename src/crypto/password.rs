use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(65536, 3, 4, None)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    TooShort,
    NoUppercase,
    NoLowercase,
    TooFewDigits,
    TooFewSpecial,
    TooWeak,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "too short"),
            Self::NoUppercase => write!(f, "missing uppercase letter"),
            Self::NoLowercase => write!(f, "missing lowercase letter"),
            Self::TooFewDigits => write!(f, "requires at least 2 digits"),
            Self::TooFewSpecial => write!(f, "requires at least 2 special characters"),
            Self::TooWeak => write!(f, "too weak or too common"),
        }
    }
}

impl PasswordError {
    pub fn i18n_key(self) -> &'static str {
        match self {
            Self::TooShort => "password_error_too_short",
            Self::NoUppercase => "password_error_no_uppercase",
            Self::NoLowercase => "password_error_no_lowercase",
            Self::TooFewDigits => "password_error_too_few_digits",
            Self::TooFewSpecial => "password_error_too_few_special",
            Self::TooWeak => "password_error_too_weak",
        }
    }

    pub fn client_secret_i18n_key(self) -> &'static str {
        match self {
            Self::TooShort => "secret_error_too_short",
            Self::NoUppercase => "secret_error_no_uppercase",
            Self::NoLowercase => "secret_error_no_lowercase",
            Self::TooFewDigits => "secret_error_too_few_digits",
            Self::TooFewSpecial => "secret_error_too_few_special",
            Self::TooWeak => "secret_error_too_weak",
        }
    }
}

pub fn validate_strength(password: &str, min_len: usize) -> Result<(), PasswordError> {
    if password.len() < min_len {
        return Err(PasswordError::TooShort);
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(PasswordError::NoUppercase);
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(PasswordError::NoLowercase);
    }
    if password.chars().filter(|c| c.is_ascii_digit()).count() < 2 {
        return Err(PasswordError::TooFewDigits);
    }
    if password.chars().filter(|c| !c.is_alphanumeric()).count() < 2 {
        return Err(PasswordError::TooFewSpecial);
    }
    if password_strength::estimate_strength(password) < 0.7 {
        return Err(PasswordError::TooWeak);
    }
    Ok(())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Runs a dummy password verification to burn the same time as a real one.
/// Prevents user enumeration via timing side-channels.
pub fn dummy_verify(password: &str) {
    #[static_init::dynamic]
    static DUMMY_HASH: String = hash_password("dummy-timing-pad").expect("dummy hash failed");
    let _ = verify_password(password, &DUMMY_HASH);
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- validate_strength -------------------------------------------------

    #[test]
    fn valid_password() {
        assert!(validate_strength("Str0ng!!Pass99", 10).is_ok());
    }

    #[test]
    fn too_short() {
        assert_eq!(validate_strength("Ab1!x", 10), Err(PasswordError::TooShort));
    }

    #[test]
    fn no_uppercase() {
        assert_eq!(validate_strength("abcdef12!!", 8), Err(PasswordError::NoUppercase));
    }

    #[test]
    fn no_lowercase() {
        assert_eq!(validate_strength("ABCDEF12!!", 8), Err(PasswordError::NoLowercase));
    }

    #[test]
    fn too_few_digits() {
        assert_eq!(validate_strength("Abcdefgh!!", 8), Err(PasswordError::TooFewDigits));
    }

    #[test]
    fn too_few_special() {
        assert_eq!(validate_strength("Abcdefg123", 8), Err(PasswordError::TooFewSpecial));
    }

    #[test]
    fn exact_min_len() {
        assert!(validate_strength("Xk92!m@Zq7", 10).is_ok());
    }

    // -- hash + verify -----------------------------------------------------

    #[test]
    fn hash_verify_roundtrip() {
        let hash = hash_password("Test!!99xx").unwrap();
        assert!(verify_password("Test!!99xx", &hash));
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("Test!!99xx").unwrap();
        assert!(!verify_password("Wrong!!99xx", &hash));
    }

    #[test]
    fn different_salts() {
        let h1 = hash_password("Test!!99xx").unwrap();
        let h2 = hash_password("Test!!99xx").unwrap();
        assert_ne!(h1, h2); // different salt each time
    }

    #[test]
    fn verify_invalid_hash() {
        assert!(!verify_password("anything", "not-a-valid-hash"));
    }
}
