#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // SSRF prevention: must not panic on any input.
        // Valid URLs pass, everything else returns Err.
        let _ = vellaveto_mcp::a2a::agent_card::validate_agent_card_base_url(s);
    }
});
