use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use jsonwebtoken::{DecodingKey, EncodingKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use arc_swap::ArcSwap;

pub struct KeyPair {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub kid: String,
    pub jwk: serde_json::Value,
}

struct KeyStoreInner {
    current: KeyPair,
    previous: Option<KeyPair>,
}

/// Manages current + previous key pairs for graceful rotation.
pub struct KeyStore {
    inner: ArcSwap<KeyStoreInner>,
}

impl KeyStore {
    pub fn new(initial: KeyPair) -> Self {
        Self {
            inner: ArcSwap::from_pointee(KeyStoreInner {
                current: initial,
                previous: None,
            }),
        }
    }

    /// Rotate keys: current becomes previous, a new key pair becomes current.
    pub fn rotate(&self) -> String {
        let new_keys = generate_key_pair();
        let new_kid = new_keys.kid.clone();
        let old = self.inner.load();
        self.inner.store(Arc::new(KeyStoreInner {
            previous: Some(KeyPair {
                encoding_key: old.current.encoding_key.clone(),
                decoding_key: old.current.decoding_key.clone(),
                kid: old.current.kid.clone(),
                jwk: old.current.jwk.clone(),
            }),
            current: new_keys,
        }));
        tracing::info!("Key rotation complete, new kid: {new_kid}");
        new_kid
    }

    /// Get the current encoding key and kid for signing.
    pub fn signing_key(&self) -> (EncodingKey, String) {
        let snap = self.inner.load();
        (snap.current.encoding_key.clone(), snap.current.kid.clone())
    }

    /// Get all decoding keys (current + previous) for verification.
    pub fn decoding_keys(&self) -> Vec<DecodingKey> {
        let snap = self.inner.load();
        let mut keys = vec![snap.current.decoding_key.clone()];
        if let Some(ref prev) = snap.previous {
            keys.push(prev.decoding_key.clone());
        }
        keys
    }

    /// Build JWKS JSON containing all available public keys.
    pub fn jwks_json(&self) -> serde_json::Value {
        let snap = self.inner.load();
        let mut keys = vec![snap.current.jwk.clone()];
        if let Some(ref prev) = snap.previous {
            keys.push(prev.jwk.clone());
        }
        serde_json::json!({ "keys": keys })
    }
}

/// Generates a fresh Ed25519 keypair in memory.
pub fn generate_key_pair() -> KeyPair {
    let seed: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let priv_pem = signing_key
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("Failed to encode private key as PKCS8 PEM");
    let pub_pem = verifying_key
        .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("Failed to encode public key as SPKI PEM");

    let encoding_key =
        EncodingKey::from_ed_pem(priv_pem.as_bytes()).expect("Failed to create encoding key");
    let decoding_key =
        DecodingKey::from_ed_pem(pub_pem.as_bytes()).expect("Failed to create decoding key");

    let (kid, jwk) = build_jwk(pub_pem.as_bytes());

    KeyPair {
        encoding_key,
        decoding_key,
        kid,
        jwk,
    }
}

/// Convenience: generate keys and wrap in a KeyStore.
pub fn generate_keys() -> KeyStore {
    tracing::info!("Generating ephemeral Ed25519 keypair");
    KeyStore::new(generate_key_pair())
}

fn derive_kid(pub_bytes: &[u8]) -> String {
    let hash = Sha256::digest(pub_bytes);
    URL_SAFE_NO_PAD.encode(&hash[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_pair_produces_valid_keys() {
        let kp = generate_key_pair();
        assert!(!kp.kid.is_empty());
        // Sign and verify roundtrip via JWT using proper claims
        let token = crate::crypto::jwt::issue_access_token(
            &kp.encoding_key, &kp.kid, "http://test", "client", "user", "openid",
        ).unwrap();
        let claims = crate::crypto::jwt::decode_access_token(
            &token, &kp.decoding_key, "http://test", "client",
        ).unwrap();
        assert_eq!(claims.sub, "user");
    }

    #[test]
    fn keystore_initial_state() {
        let store = generate_keys();
        assert_eq!(store.decoding_keys().len(), 1);
        let (_, kid) = store.signing_key();
        assert!(!kid.is_empty());
    }

    #[test]
    fn keystore_rotation() {
        let store = generate_keys();
        let (_, kid1) = store.signing_key();
        let new_kid = store.rotate();
        assert_ne!(kid1, new_kid);
        assert_eq!(store.decoding_keys().len(), 2);
        let (_, kid2) = store.signing_key();
        assert_eq!(kid2, new_kid);
    }

    #[test]
    fn jwks_json_structure() {
        let store = generate_keys();
        let jwks = store.jwks_json();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "OKP");
        assert_eq!(keys[0]["crv"], "Ed25519");
        assert_eq!(keys[0]["alg"], "EdDSA");
        assert_eq!(keys[0]["use"], "sig");

        store.rotate();
        let jwks2 = store.jwks_json();
        assert_eq!(jwks2["keys"].as_array().unwrap().len(), 2);
    }
}

fn build_jwk(pub_pem: &[u8]) -> (String, serde_json::Value) {
    let pem_str = std::str::from_utf8(pub_pem).expect("Invalid PEM");
    let der_b64: String = pem_str
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&der_b64)
        .expect("Failed to decode PEM base64");

    let pub_bytes = &der[der.len() - 32..];
    let x = URL_SAFE_NO_PAD.encode(pub_bytes);
    let kid = derive_kid(pub_bytes);

    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "kid": kid,
        "x": x
    });

    (kid, jwk)
}
