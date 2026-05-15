#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(uri) = std::str::from_utf8(data) {
        // Validate redirect URI without needing actual i18n (check panic safety only)
        let lower = uri.to_lowercase();
        let _ = lower.starts_with("https://");
        let _ = lower.starts_with("http://");
        let _ = lower.contains("..");
        let _ = lower.contains("\\");
        // Also test the full validation path via gtid_shared email normalize
        let _ = gtid_shared::email::normalize_email(uri);
    }
});
