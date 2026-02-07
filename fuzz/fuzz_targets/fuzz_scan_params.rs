#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try parsing as JSON, then scan for targets.
    // scan_params_for_targets handles arbitrary nested JSON (objects, arrays,
    // strings with file:// URLs, scheme-based URLs, absolute paths, relative
    // paths with ..). It must never panic on any input.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let mut paths = Vec::new();
        let mut domains = Vec::new();
        sentinel_server::scan_params_for_targets(&value, &mut paths, &mut domains);
    }
});
