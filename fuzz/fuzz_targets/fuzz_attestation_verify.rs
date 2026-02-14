#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON into an AccountabilityAttestation and verify it.
    // Must not panic on any input — all malformed data must produce Err.
    if let Ok(attestation) =
        serde_json::from_slice::<vellaveto_types::AccountabilityAttestation>(data)
    {
        let now = chrono::Utc::now();
        let _ = vellaveto_mcp::accountability::verify_attestation(&attestation, None, &now);

        // Also try with a random expected key
        let _ = vellaveto_mcp::accountability::verify_attestation(
            &attestation,
            Some("deadbeef01234567890abcdef01234567890abcdef01234567890abcdef012345"),
            &now,
        );
    }
});
