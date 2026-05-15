#![no_main]

use libfuzzer_sys::fuzz_target;
use gtid_shared::crypto::pkce;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parts: Vec<&str> = s.split('|').collect();
        if parts.len() == 2 {
            // Don't care about result, just checking for panics / UB
            let _ = pkce::verify_pkce_s256(parts[0], parts[1]);
        }
    }
});
