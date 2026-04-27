use aes_gcm::{
    AeadCore, Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use hmac::Hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
use totp_rs::{Algorithm, Secret, TOTP};

pub fn generate_secret() -> String {
    let secret = Secret::generate_secret();
    secret.to_encoded().to_string()
}

pub fn build_totp(secret_base32: &str, email: &str, issuer_uri: &str) -> Result<TOTP, String> {
    let stripped_issuer_uri = if issuer_uri.to_lowercase().starts_with("https://") {
        &issuer_uri[8..]
    } else if issuer_uri.to_lowercase().starts_with("http://") {
        &issuer_uri[7..]
    } else {
        issuer_uri
    };

    let issuer_label = stripped_issuer_uri
        .split(&[':', '/'][..])
        .next()
        .unwrap_or("localhost")
        .to_string();

    let secret = Secret::Encoded(secret_base32.to_string());
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,  // 1-step skew tolerance
        30, // 30-second step
        secret.to_bytes().map_err(|e| format!("invalid secret: {e}"))?,
        Some(["GT Id - ", &issuer_label].concat()),
        email.to_string(),
    )
    .map_err(|e| format!("TOTP build error: {e}"))
}

pub fn generate_qr_data_uri(totp: &TOTP) -> Result<String, String> {
    totp.get_qr_base64()
        .map(|b64| format!("data:image/png;base64,{b64}"))
        .map_err(|e| format!("QR generation error: {e}"))
}

pub fn verify_code(totp: &TOTP, code: &str) -> bool {
    totp.check_current(code).unwrap_or(false)
}

pub fn derive_user_key(master_key: &[u8; 32], user_id: &str) -> Result<[u8; 32], String> {
    let mut mac =
        <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(master_key).map_err(|e| format!("HMAC key init: {e}"))?;
    hmac::digest::Update::update(&mut mac, b"totp-secret");
    hmac::digest::Update::update(&mut mac, user_id.as_bytes());
    let result = hmac::digest::FixedOutput::finalize_fixed(mac);
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

pub fn encrypt_secret(plaintext: &str, user_key: &[u8; 32]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(user_key).map_err(|e| format!("cipher init: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(hex::encode(combined))
}

pub fn decrypt_secret(hex_data: &str, user_key: &[u8; 32]) -> Result<String, String> {
    let data = hex::decode(hex_data).map_err(|e| format!("hex decode: {e}"))?;
    if data.len() < 12 {
        return Err("Decryption failed".into());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes.try_into().map_err(|_| "invalid nonce length")?;
    let nonce = Nonce::from(nonce_arr);
    let cipher = Aes256Gcm::new_from_slice(user_key).map_err(|e| format!("cipher init: {e}"))?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "Decryption failed (wrong key or corrupted data)".to_string())?;
    String::from_utf8(plaintext).map_err(|e| format!("utf8: {e}"))
}

pub fn format_secret_for_display(secret_base32: &str) -> String {
    secret_base32
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_secret_is_valid_base32() {
        let secret = generate_secret();
        assert!(!secret.is_empty());
        assert!(Secret::Encoded(secret.clone()).to_bytes().is_ok());
    }

    #[test]
    fn build_totp_and_verify() {
        let secret = generate_secret();
        let totp = build_totp(&secret, "test@example.com", "GTId").unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_code(&totp, &code));
        assert!(!verify_code(&totp, "000000"));
    }

    #[test]
    fn qr_data_uri_starts_with_data_prefix() {
        let secret = generate_secret();
        let totp = build_totp(&secret, "test@example.com", "GTId").unwrap();
        let uri = generate_qr_data_uri(&totp).unwrap();
        assert!(uri.starts_with("data:image/png;base64,"));
    }

    #[test]
    fn derive_user_key_deterministic() {
        let master = [42u8; 32];
        let k1 = derive_user_key(&master, "user-1").unwrap();
        let k2 = derive_user_key(&master, "user-1").unwrap();
        let k3 = derive_user_key(&master, "user-2").unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master = [99u8; 32];
        let user_key = derive_user_key(&master, "user-1").unwrap();
        let secret = "JBSWY3DPEHPK3PXP";
        let encrypted = encrypt_secret(secret, &user_key).unwrap();
        let decrypted = decrypt_secret(&encrypted, &user_key).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let master = [99u8; 32];
        let key1 = derive_user_key(&master, "user-1").unwrap();
        let key2 = derive_user_key(&master, "user-2").unwrap();
        let encrypted = encrypt_secret("JBSWY3DPEHPK3PXP", &key1).unwrap();
        assert!(decrypt_secret(&encrypted, &key2).is_err());
    }

    #[test]
    fn format_secret_groups_of_four() {
        assert_eq!(format_secret_for_display("ABCDEFGH"), "ABCD EFGH");
        assert_eq!(format_secret_for_display("ABCDE"), "ABCD E");
    }
}
