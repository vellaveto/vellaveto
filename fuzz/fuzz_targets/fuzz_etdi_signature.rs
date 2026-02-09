#![no_main]
//! Fuzz target for ETDI signature verification.
//!
//! Tests that the Ed25519 signature verification handles arbitrary
//! inputs without panicking.

use libfuzzer_sys::fuzz_target;
use sentinel_config::AllowedSignersConfig;
use sentinel_types::{SignatureAlgorithm, ToolSignature};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parts: Vec<&str> = s.split('\n').collect();

        // Create a signature with fuzzed values
        let signature = ToolSignature {
            signature_id: parts.get(0).unwrap_or(&"sig-fuzz").to_string(),
            signature: parts.get(1).unwrap_or(&"invalid").to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: parts.get(2).unwrap_or(&"invalid").to_string(),
            key_fingerprint: parts.get(3).map(|s| s.to_string()),
            signed_at: parts.get(4).unwrap_or(&"2026-01-01T00:00:00Z").to_string(),
            expires_at: parts.get(5).map(|s| s.to_string()),
            signer_spiffe_id: parts.get(6).map(|s| s.to_string()),
        };

        // Create a schema with fuzzed content
        let schema = if let Some(schema_str) = parts.get(7) {
            serde_json::from_str(schema_str).unwrap_or(serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        let tool_name = parts.get(8).unwrap_or(&"fuzz_tool");

        // Test signature verification with default config (should not panic even with invalid data)
        let verifier = sentinel_mcp::etdi::ToolSignatureVerifier::new(AllowedSignersConfig::default());
        let _ = verifier.verify_tool_signature(tool_name, &schema, &signature);

        // Test with custom allowed signers
        let trusted: Vec<String> = parts.iter().skip(9).map(|s| s.to_string()).collect();
        let allowed = AllowedSignersConfig {
            fingerprints: trusted.clone(),
            spiffe_ids: trusted,
        };
        let verifier = sentinel_mcp::etdi::ToolSignatureVerifier::new(allowed);
        let _ = verifier.verify_tool_signature(tool_name, &schema, &signature);
    }
});
