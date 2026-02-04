#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test read_message with arbitrary bytes
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let cursor = std::io::Cursor::new(data.to_vec());
        let mut reader = tokio::io::BufReader::new(cursor);
        // Must not panic — errors are fine
        let _ = sentinel_mcp::framing::read_message(&mut reader).await;
    });

    // Test find_duplicate_json_key with arbitrary strings
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sentinel_mcp::framing::find_duplicate_json_key(s);
    }
});
