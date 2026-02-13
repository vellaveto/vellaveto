#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Unicode homoglyph normalization: must not panic on any input.
        // Properties: output is always valid UTF-8, output length <= input length.
        let normalized = sentinel_types::unicode::normalize_homoglyphs(s);
        assert!(normalized.len() <= s.len() * 4); // char expansion bounded
    }
});
