#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Agent card JSON parsing: must not panic on any input.
        let _ = sentinel_mcp::a2a::agent_card::parse_agent_card(s);
    }
});
