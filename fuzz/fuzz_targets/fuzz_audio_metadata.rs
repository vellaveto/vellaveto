#![no_main]
//! Fuzz target for audio metadata extraction (WAV + MP3).
//!
//! Tests that the WAV LIST/INFO parser and MP3 ID3v2 parser handle
//! all byte inputs without panicking, including truncated, oversized,
//! and malformed data.

use libfuzzer_sys::fuzz_target;
use vellaveto_mcp::inspection::multimodal::{ContentType, MultimodalConfig, MultimodalScanner};

fuzz_target!(|data: &[u8]| {
    let config = MultimodalConfig {
        enabled: true,
        content_types: vec![ContentType::Audio],
        max_image_size: 10 * 1024 * 1024, // 10MB
        ..Default::default()
    };
    let scanner = MultimodalScanner::new(config);

    // Test with auto-detected content type
    let _ = scanner.scan_content(data, None);

    // Test with forced Audio content type
    let _ = scanner.scan_content(data, Some(ContentType::Audio));

    // Test content type detection itself
    let _ = ContentType::from_magic_bytes(data);
});
