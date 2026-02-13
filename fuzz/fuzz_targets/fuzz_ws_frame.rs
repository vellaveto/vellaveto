#![no_main]
//! Fuzz target for WebSocket frame message parsing path.
//!
//! Simulates receiving arbitrary bytes as a WebSocket text frame,
//! parsing as JSON, classifying via the MCP extractor, and extracting
//! an Action. Ensures no panics on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Step 1: Try to parse as UTF-8 (WebSocket text frames are UTF-8)
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Step 2: Try to parse as JSON
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Step 3: Classify the message (must not panic)
    let classified = sentinel_mcp::extractor::classify_message(&value);

    // Step 4: If it's a tool call, extract the action (must not panic)
    if let sentinel_mcp::extractor::MessageType::ToolCall {
        tool_name,
        arguments,
        ..
    } = classified
    {
        let _ = sentinel_mcp::extractor::extract_action(&tool_name, &arguments);
    }

    // Step 5: If it's a resource read, extract resource action (must not panic)
    if let sentinel_mcp::extractor::MessageType::ResourceRead { uri, .. } =
        sentinel_mcp::extractor::classify_message(&value)
    {
        let _ = sentinel_mcp::extractor::extract_resource_action(&uri);
    }
});
