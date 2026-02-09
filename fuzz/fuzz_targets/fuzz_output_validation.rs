#![no_main]
//! Fuzz target for output schema validation.
//!
//! Tests that the output validation system handles arbitrary schemas
//! and outputs without panicking.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON for schema/output pairs
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        // Test schema registration and validation
        if let Some(obj) = value.as_object() {
            let schema = obj.get("schema").cloned().unwrap_or(serde_json::json!({}));
            let output = obj.get("output").cloned().unwrap_or(serde_json::json!({}));
            let tool = obj
                .get("tool")
                .and_then(|t| t.as_str())
                .unwrap_or("fuzz_tool");

            // Create registry and test
            let registry = sentinel_mcp::output_validation::OutputSchemaRegistry::new();

            // Register schema
            registry.register(tool, schema);

            // Validate output against schema
            let _ = registry.validate(tool, &output);

            // Test has_schema
            let _ = registry.has_schema(tool);
        }

        // Also test register_from_tools_list with arbitrary JSON
        let registry = sentinel_mcp::output_validation::OutputSchemaRegistry::new();
        registry.register_from_tools_list(&value);
    }
});
