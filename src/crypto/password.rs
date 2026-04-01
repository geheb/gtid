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


pub fn validate_password_strength(password: &str) -> Result<(), PasswordError> {
    if password.len() < 10 {
        return Err(PasswordError::TooShort);
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(PasswordError::NoUppercase);
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(PasswordError::NoLowercase);
    }
    if password.chars().filter(|c| c.is_ascii_digit()).count() < 1 {
        return Err(PasswordError::TooFewDigits);
    }
    if password.chars().filter(|c| !c.is_alphanumeric()).count() < 1 {
        return Err(PasswordError::TooFewSpecial);
    }
    if password_strength::estimate_strength(password) < 0.7 {
        return Err(PasswordError::TooWeak);
    }
    Ok(())
}

pub fn validate_secret_strength(password: &str) -> Result<(), PasswordError> {
    if password.len() < 16 {
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
    static DUMMY_HASH: String = {
        let random_pad = SaltString::generate(&mut OsRng).to_string();
        hash_password(&random_pad).expect("dummy hash failed")
    };
    let _ = verify_password(password, &DUMMY_HASH);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_password() {
        assert!(validate_password_strength("Str0ng!!Pass99").is_ok());
    }

    #[test]
    fn too_short() {
        assert_eq!(validate_password_strength("Ab1!x"), Err(PasswordError::TooShort));
    }

    #[test]
    fn no_uppercase() {
        assert_eq!(validate_password_strength("abcdef12!!"), Err(PasswordError::NoUppercase));
    }

    #[test]
    fn no_lowercase() {
        assert_eq!(validate_password_strength("ABCDEF12!!"), Err(PasswordError::NoLowercase));
    }

    #[test]
    fn too_few_digits() {
        assert_eq!(validate_password_strength("Abcdefgh!!"), Err(PasswordError::TooFewDigits));
    }

    #[test]
    fn too_few_special() {
        assert_eq!(validate_password_strength("Abcdefg123"), Err(PasswordError::TooFewSpecial));
    }

    #[test]
    fn exact_min_len() {
        assert!(validate_password_strength("Xk92!m@Zq7").is_ok());
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
