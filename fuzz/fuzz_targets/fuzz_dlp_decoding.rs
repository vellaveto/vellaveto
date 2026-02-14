#![no_main]
//! Fuzz target for DLP multi-layer decode pipeline.
//!
//! Tests that the 8-layer decode chain (raw, base64, percent, combos)
//! handles all inputs without panicking, including malformed encodings.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test with raw bytes as string (may be invalid UTF-8)
    if let Ok(s) = std::str::from_utf8(data) {
        // Test the public API
        let params = serde_json::json!({ "data": s });
        let _ = vellaveto_mcp::inspection::scan_parameters_for_secrets(&params);

        // Test nested structures
        let nested = serde_json::json!({
            "outer": {
                "inner": s,
                "array": [s, s]
            }
        });
        let _ = vellaveto_mcp::inspection::scan_parameters_for_secrets(&nested);
    }

    // Also test with arbitrary JSON
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = vellaveto_mcp::inspection::scan_parameters_for_secrets(&value);
        let _ = vellaveto_mcp::inspection::scan_response_for_secrets(&value);
        let _ = vellaveto_mcp::inspection::scan_notification_for_secrets(&value);
    }
});
