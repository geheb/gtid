#![no_main]

use libfuzzer_sys::fuzz_target;
use gtid_shared::email::normalize_email;

fuzz_target!(|data: &[u8]| {
    if let Ok(email) = std::str::from_utf8(data) {
        let _ = normalize_email(email);
    }
});
