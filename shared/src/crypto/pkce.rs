use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub fn generate_pkce() -> (String, String) {
    let mut random_bytes: [u8; 32] = rand::random();
    let verifier = URL_SAFE_NO_PAD.encode(random_bytes);
    random_bytes.zeroize();
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

pub fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    let mut hash = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    hash.zeroize();
    super::constant_time::constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_roundtrip() {
        let (verifier, challenge) = generate_pkce();
        assert!(verify_pkce_s256(&verifier, &challenge));
    }

    #[test]
    fn wrong_verifier_fails() {
        let (_, challenge) = generate_pkce();
        assert!(!verify_pkce_s256("wrong-verifier-aaaaaaaaaaaaaaaaaaaaaa", &challenge));
    }

    #[test]
    fn wrong_challenge_fails() {
        let (verifier, _) = generate_pkce();
        assert!(!verify_pkce_s256(&verifier, "wrong-challenge"));
    }

    #[test]
    fn rfc7636_appendix_b() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce_s256(verifier, expected_challenge));
    }

    #[test]
    fn empty_strings() {
        assert!(!verify_pkce_s256("", ""));
        let (verifier, _) = generate_pkce();
        assert!(!verify_pkce_s256(&verifier, ""));
    }
}
