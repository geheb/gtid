#![no_main]

use libfuzzer_sys::fuzz_target;
use gtid_shared::oauth::validate_scope;

fuzz_target!(|data: &[u8]| {
    if let Ok(scope) = std::str::from_utf8(data) {
        // Use "en" locale to avoid i18n complexity in fuzzer
        let _ = validate_scope(scope, "en");
    }
});
