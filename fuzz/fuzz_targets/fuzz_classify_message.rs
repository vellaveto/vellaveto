#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON and classify
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        // Must not panic on any valid JSON
        let _ = vellaveto_mcp::extractor::classify_message(&value);
    }
});
