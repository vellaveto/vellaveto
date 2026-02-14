#![no_main]
//! Fuzz target for injection detection with Unicode normalization.
//!
//! Tests that the Aho-Corasick scanner with NFKC normalization handles
//! all Unicode inputs without panicking, including malformed sequences.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test with valid UTF-8 strings
    if let Ok(s) = std::str::from_utf8(data) {
        // Test the InjectionScanner with custom patterns
        if let Some(scanner) = vellaveto_mcp::inspection::InjectionScanner::new(&[s]) {
            let _ = scanner.inspect(s);

            // Test response scanning
            let response = serde_json::json!({
                "result": {
                    "content": [{
                        "type": "text",
                        "text": s
                    }]
                }
            });
            let _ = scanner.scan_response(&response);

            // Test notification scanning
            let notification = serde_json::json!({
                "method": "notifications/message",
                "params": { "message": s }
            });
            let _ = scanner.scan_notification(&notification);
        }

        // Test with default patterns
        let _ = vellaveto_mcp::inspection::scan_response_for_injection(&serde_json::json!({
            "result": { "content": [{ "type": "text", "text": s }] }
        }));
    }

    // Test with arbitrary JSON for response scanning
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = vellaveto_mcp::inspection::scan_response_for_injection(&value);
        let _ = vellaveto_mcp::inspection::scan_notification_for_injection(&value);
    }
});
