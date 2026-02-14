#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        // A2A message classification: must not panic on any valid JSON.
        let msg_type = vellaveto_mcp::a2a::message::classify_a2a_message(&value);
        // Action extraction from classified message: must not panic.
        let _ = vellaveto_mcp::a2a::extractor::extract_a2a_action(&msg_type);
    }
});
