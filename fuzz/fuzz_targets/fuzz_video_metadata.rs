#![no_main]
//! Fuzz target for video metadata extraction (MP4 + WebM).
//!
//! Tests that the MP4 ISO BMFF box walker and WebM EBML tag parser
//! handle all byte inputs without panicking, including truncated,
//! deeply nested, oversized, and malformed data.

use libfuzzer_sys::fuzz_target;
use vellaveto_mcp::inspection::multimodal::{ContentType, MultimodalConfig, MultimodalScanner};

fuzz_target!(|data: &[u8]| {
    let config = MultimodalConfig {
        enabled: true,
        content_types: vec![ContentType::Video],
        max_image_size: 10 * 1024 * 1024, // 10MB
        ..Default::default()
    };
    let scanner = MultimodalScanner::new(config);

    // Test with auto-detected content type
    let _ = scanner.scan_content(data, None);

    // Test with forced Video content type
    let _ = scanner.scan_content(data, Some(ContentType::Video));

    // Test content type detection itself
    let _ = ContentType::from_magic_bytes(data);
});
