#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must not panic on any input
        let _ = sentinel_engine::PolicyEngine::normalize_path(s);
        // Also test bounded variant
        let _ = sentinel_engine::PolicyEngine::normalize_path_bounded(s, 5);
    }
});
