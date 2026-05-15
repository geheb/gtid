#![no_main]

use libfuzzer_sys::fuzz_target;
use gtid_shared::crypto::password::validate_password_strength;

fuzz_target!(|data: &[u8]| {
    if let Ok(password) = std::str::from_utf8(data) {
        let _ = validate_password_strength(password);
    }
});
