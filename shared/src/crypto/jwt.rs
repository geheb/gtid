use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub email: String,
    pub email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

fn encode_token<T: serde::Serialize>(
    encoding_key: &EncodingKey,
    kid: &str,
    claims: T,
) -> Result<String, jsonwebtoken::errors::Error> {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());
    encode(&header, &claims, encoding_key)
}

pub fn issue_access_token(
    encoding_key: &EncodingKey,
    kid: &str,
    issuer: &str,
    client_id: &str,
    user_id: &str,
    scope: &str,
    expiry_secs: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        iss: issuer.to_string(),
        aud: client_id.to_string(),
        exp: now + expiry_secs,
        iat: now,
        scope: scope.to_string(),
    };
    encode_token(encoding_key, kid, claims)
}

/// Compute at_hash per OIDC Core 3.1.3.6:
/// base64url(left-half(SHA-256(ASCII(access_token))))
pub fn compute_at_hash(access_token: &str) -> String {
    let hash = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash[..16])
}

pub struct IdTokenParams<'a> {
    pub encoding_key: &'a EncodingKey,
    pub kid: &'a str,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub email: &'a str,
    pub email_verified: bool,
    pub display_name: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub access_token: &'a str,
    pub roles: Vec<String>,
    pub expiry_secs: i64,
}

pub fn issue_id_token(params: IdTokenParams<'_>) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = IdTokenClaims {
        sub: params.user_id.to_string(),
        iss: params.issuer.to_string(),
        aud: params.client_id.to_string(),
        exp: now + params.expiry_secs,
        iat: now,
        email: params.email.to_string(),
        email_verified: params.email_verified,
        name: params.display_name.map(|s| s.to_string()),
        nonce: params.nonce.map(|s| s.to_string()),
        at_hash: Some(compute_at_hash(params.access_token)),
        roles: params.roles,
    };

    encode_token(params.encoding_key, params.kid, claims)
}

pub fn decode_access_token(
    token: &str,
    decoding_key: &DecodingKey,
    issuer: &str,
    client_id: &str,
) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);

    let data = decode::<AccessTokenClaims>(token, decoding_key, &validation)?;
    Ok(data.claims)
}

/// Decode an access token trying multiple keys (for key rotation).
pub fn decode_access_token_multi(
    token: &str,
    decoding_keys: &[&DecodingKey],
    issuer: &str,
    client_id: &str,
) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
    let mut last_err = None;
    for key in decoding_keys {
        match decode_access_token(token, key, issuer, client_id) {
            Ok(claims) => return Ok(claims),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_key_pair;

    const ISSUER: &str = "http://test.local";
    const CLIENT: &str = "test-client";
    const USER: &str = "user-123";

    fn test_keys() -> (EncodingKey, DecodingKey, String) {
        let kp = generate_key_pair().unwrap();
        (kp.encoding_key, kp.decoding_key, kp.kid)
    }

    #[test]
    fn at_hash_deterministic() {
        let h1 = compute_at_hash("some-token");
        let h2 = compute_at_hash("some-token");
        assert_eq!(h1, h2);
        assert!(!h1.is_empty());
    }

    #[test]
    fn at_hash_different_for_different_tokens() {
        assert_ne!(compute_at_hash("token-a"), compute_at_hash("token-b"));
    }

    #[test]
    fn access_token_roundtrip() {
        let (enc, dec, kid) = test_keys();
        let token = issue_access_token(&enc, &kid, ISSUER, CLIENT, USER, "openid", 900).unwrap();
        let claims = decode_access_token(&token, &dec, ISSUER, CLIENT).unwrap();
        assert_eq!(claims.sub, USER);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.aud, CLIENT);
        assert_eq!(claims.scope, "openid");
    }

    #[test]
    fn id_token_roundtrip() {
        let (enc, dec, kid) = test_keys();
        let at = issue_access_token(&enc, &kid, ISSUER, CLIENT, USER, "openid", 900).unwrap();
        let id_token = issue_id_token(IdTokenParams {
            encoding_key: &enc,
            kid: &kid,
            issuer: ISSUER,
            client_id: CLIENT,
            user_id: USER,
            email: "user@test.com",
            email_verified: true,
            display_name: Some("Test User"),
            nonce: Some("nonce-1"),
            access_token: &at,
            roles: vec!["admin".to_string()],
            expiry_secs: 600,
        })
        .unwrap();

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[CLIENT]);
        let data = decode::<IdTokenClaims>(&id_token, &dec, &validation).unwrap();
        assert_eq!(data.claims.email, "user@test.com");
        assert_eq!(data.claims.nonce.as_deref(), Some("nonce-1"));
        assert_eq!(data.claims.at_hash, Some(compute_at_hash(&at)));
        assert_eq!(data.claims.roles, vec!["admin"]);
    }

    #[test]
    fn wrong_issuer_rejected() {
        let (enc, dec, kid) = test_keys();
        let token = issue_access_token(&enc, &kid, ISSUER, CLIENT, USER, "openid", 900).unwrap();
        assert!(decode_access_token(&token, &dec, "http://wrong.issuer", CLIENT).is_err());
    }

    #[test]
    fn wrong_audience_rejected() {
        let (enc, dec, kid) = test_keys();
        let token = issue_access_token(&enc, &kid, ISSUER, CLIENT, USER, "openid", 900).unwrap();
        assert!(decode_access_token(&token, &dec, ISSUER, "wrong-client").is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let (enc, _, kid) = test_keys();
        let (_, dec2, _) = test_keys(); // different key pair
        let token = issue_access_token(&enc, &kid, ISSUER, CLIENT, USER, "openid", 900).unwrap();
        assert!(decode_access_token(&token, &dec2, ISSUER, CLIENT).is_err());
    }

    #[test]
    fn multi_key_decode() {
        let (enc, dec, kid) = test_keys();
        let (_, dec2, _) = test_keys();
        let token = issue_access_token(&enc, &kid, ISSUER, CLIENT, USER, "openid", 900).unwrap();
        // Correct key is second in list
        let keys = [&dec2, &dec];
        let claims = decode_access_token_multi(&token, &keys, ISSUER, CLIENT).unwrap();
        assert_eq!(claims.sub, USER);
    }

    #[test]
    fn multi_key_empty_slice() {
        let (enc, _, kid) = test_keys();
        let token = issue_access_token(&enc, &kid, ISSUER, CLIENT, USER, "openid", 900).unwrap();
        let keys: &[&DecodingKey] = &[];
        assert!(decode_access_token_multi(&token, keys, ISSUER, CLIENT).is_err());
    }
}
