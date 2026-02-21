use serde_json::Value;

/// Maximum recursion depth for schema compression strategies.
/// Prevents stack overflow from adversarially nested JSON schemas.
const MAX_SCHEMA_DEPTH: usize = 64;

/// Compresses JSON Schema tool descriptions to fit within a token budget.
///
/// Applies compression strategies in order of increasing aggressiveness:
/// 1. Strip redundant `"type": "object"` at root level
/// 2. Inline single-value enums as constants
/// 3. Truncate descriptions to first sentence
/// 4. Collapse single-property nested objects
/// 5. Remove optional parameter descriptions (keep required ones)
pub struct SchemaCompressor;

impl SchemaCompressor {
    /// Compress a tool schema to fit within the given token budget.
    ///
    /// Applies compression strategies in order until the estimated token count
    /// is at or below the budget. If already under budget, returns the schema
    /// unchanged.
    pub fn compress(schema: &Value, budget: usize) -> Value {
        let mut result = schema.clone();

        let strategies: &[fn(&mut Value, usize)] = &[
            strip_redundant_root_type,
            inline_single_value_enums,
            truncate_descriptions,
            collapse_single_property_objects,
            remove_optional_descriptions,
        ];

        for strategy in strategies {
            if Self::estimate_tokens(&result) <= budget {
                break;
            }
            strategy(&mut result, 0);
        }

        result
    }

    /// Estimate the token count of a JSON value.
    ///
    /// Uses a simple heuristic: 1 token ~ 4 characters of compact JSON.
    /// Returns at least 1 for any non-empty value.
    ///
    /// SECURITY (FIND-R131-001): On serialization failure, returns a high
    /// estimate (fail-closed) so compression strategies are still applied.
    /// Previously used `unwrap_or_default()` which returned 0 (fail-open),
    /// causing the compressor to think any schema fits within budget.
    pub fn estimate_tokens(schema: &Value) -> usize {
        /// Fail-closed estimate when serialization unexpectedly fails.
        /// High enough to trigger all compression strategies.
        const FAILSAFE_TOKEN_ESTIMATE: usize = 100_000;

        match serde_json::to_string(schema) {
            Ok(json) if json.is_empty() => 0,
            Ok(json) => json.len().div_ceil(4),
            Err(_) => FAILSAFE_TOKEN_ESTIMATE,
        }
    }
}

/// Remove `"type": "object"` from the root level if `"properties"` exists,
/// since `"type": "object"` is implied when properties are present.
fn strip_redundant_root_type(schema: &mut Value, _depth: usize) {
    if let Some(obj) = schema.as_object_mut() {
        if obj.contains_key("properties") {
            if let Some(Value::String(t)) = obj.get("type") {
                if t == "object" {
                    obj.remove("type");
                }
            }
        }
    }
}

/// Replace single-value enums with `"const"`.
/// `{"enum": ["only_value"]}` becomes `{"const": "only_value"}`.
/// Recurses into all nested objects and arrays.
fn inline_single_value_enums(schema: &mut Value, depth: usize) {
    // SECURITY (IMP-R110-003): Prevent stack overflow from deeply nested schemas.
    if depth > MAX_SCHEMA_DEPTH {
        return;
    }
    match schema {
        Value::Object(obj) => {
            // Check if this object itself has a single-value enum
            let should_inline = obj
                .get("enum")
                .and_then(|v| v.as_array())
                .filter(|arr| arr.len() == 1)
                .map(|arr| arr[0].clone());

            if let Some(single_val) = should_inline {
                obj.remove("enum");
                obj.insert("const".to_string(), single_val);
            }

            // Recurse into all values
            let keys: Vec<String> = obj.keys().cloned().collect();
            for key in keys {
                if let Some(val) = obj.get_mut(&key) {
                    inline_single_value_enums(val, depth + 1);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                inline_single_value_enums(item, depth + 1);
            }
        }
        _ => {}
    }
}

/// Truncate all `"description"` fields to the first sentence.
/// A sentence ends at the first `.`, `!`, or `?` followed by a space,
/// newline, or end of string.
fn truncate_descriptions(schema: &mut Value, depth: usize) {
    if depth > MAX_SCHEMA_DEPTH {
        return;
    }
    match schema {
        Value::Object(obj) => {
            if let Some(Value::String(desc)) = obj.get("description") {
                let truncated = first_sentence(desc);
                if truncated.len() < desc.len() {
                    obj.insert(
                        "description".to_string(),
                        Value::String(truncated.to_string()),
                    );
                }
            }

            // Recurse into all values
            let keys: Vec<String> = obj.keys().cloned().collect();
            for key in keys {
                if key != "description" {
                    if let Some(val) = obj.get_mut(&key) {
                        truncate_descriptions(val, depth + 1);
                    }
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                truncate_descriptions(item, depth + 1);
            }
        }
        _ => {}
    }
}

/// Delegate to the shared `first_sentence` implementation in mod.rs.
/// (IMP-R116-002: deduplicated from compress.rs and deepseek.rs copies)
fn first_sentence(text: &str) -> &str {
    super::first_sentence(text)
}

/// Collapse single-property nested objects.
///
/// If a property schema is `"type": "object"` with exactly one property inside,
/// replace the outer wrapper with the inner property schema, preserving the key
/// but flattening the nesting.
///
/// Example:
/// ```json
/// { "wrapper": { "type": "object", "properties": { "inner": { "type": "string" } } } }
/// ```
/// becomes:
/// ```json
/// { "wrapper": { "type": "string" } }
/// ```
fn collapse_single_property_objects(schema: &mut Value, depth: usize) {
    if depth > MAX_SCHEMA_DEPTH {
        return;
    }
    match schema {
        Value::Object(obj) => {
            // First recurse into children so we collapse bottom-up
            let keys: Vec<String> = obj.keys().cloned().collect();
            for key in &keys {
                if let Some(val) = obj.get_mut(key) {
                    collapse_single_property_objects(val, depth + 1);
                }
            }

            // Now check if "properties" contains any single-property objects to collapse
            if let Some(Value::Object(properties)) = obj.get_mut("properties") {
                let prop_keys: Vec<String> = properties.keys().cloned().collect();
                for prop_key in prop_keys {
                    let should_collapse = properties
                        .get(&prop_key)
                        .and_then(|v| v.as_object())
                        .and_then(|inner_obj| {
                            // Must be type: object with exactly one property
                            let is_object = inner_obj
                                .get("type")
                                .and_then(|t| t.as_str())
                                .map(|t| t == "object")
                                .unwrap_or(false);
                            if !is_object {
                                return None;
                            }
                            inner_obj
                                .get("properties")
                                .and_then(|p| p.as_object())
                                .filter(|p| p.len() == 1)
                                .and_then(|p| p.values().next().cloned())
                        });

                    if let Some(inner_schema) = should_collapse {
                        properties.insert(prop_key, inner_schema);
                    }
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                collapse_single_property_objects(item, depth + 1);
            }
        }
        _ => {}
    }
}

/// Remove `"description"` from properties that are NOT listed in `"required"`.
/// Required property descriptions are preserved since they are more important.
fn remove_optional_descriptions(schema: &mut Value, depth: usize) {
    if depth > MAX_SCHEMA_DEPTH {
        return;
    }
    match schema {
        Value::Object(obj) => {
            // Collect the set of required field names
            let required_fields: Vec<String> = obj
                .get("required")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            // Remove descriptions from optional properties
            if let Some(Value::Object(properties)) = obj.get_mut("properties") {
                for (prop_name, prop_schema) in properties.iter_mut() {
                    if !required_fields.contains(prop_name) {
                        if let Some(prop_obj) = prop_schema.as_object_mut() {
                            prop_obj.remove("description");
                        }
                    }
                }
            }

            // Recurse into all values (including nested schemas)
            let keys: Vec<String> = obj.keys().cloned().collect();
            for key in keys {
                if let Some(val) = obj.get_mut(&key) {
                    remove_optional_descriptions(val, depth + 1);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                remove_optional_descriptions(item, depth + 1);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── strip_redundant_root_type ────────────────────────────────────────

    #[test]
    fn test_compress_strip_root_type() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            }
        });
        strip_redundant_root_type(&mut schema, 0);
        assert!(schema.get("type").is_none());
        assert!(schema.get("properties").is_some());
    }

    #[test]
    fn test_compress_keeps_root_type_without_properties() {
        let mut schema = json!({"type": "object"});
        strip_redundant_root_type(&mut schema, 0);
        assert_eq!(schema["type"], "object");
    }

    #[test]
    fn test_compress_keeps_non_object_root_type() {
        let mut schema = json!({
            "type": "string",
            "properties": {"x": {"type": "number"}}
        });
        strip_redundant_root_type(&mut schema, 0);
        // "type": "string" is NOT "object", so it should stay
        assert_eq!(schema["type"], "string");
    }

    // ── inline_single_value_enums ────────────────────────────────────────

    #[test]
    fn test_compress_inline_single_enum() {
        let mut schema = json!({
            "properties": {
                "mode": {"enum": ["read_only"]}
            }
        });
        inline_single_value_enums(&mut schema, 0);
        assert_eq!(schema["properties"]["mode"]["const"], "read_only");
        assert!(schema["properties"]["mode"].get("enum").is_none());
    }

    #[test]
    fn test_compress_keeps_multi_value_enum() {
        let mut schema = json!({
            "properties": {
                "mode": {"enum": ["read", "write"]}
            }
        });
        inline_single_value_enums(&mut schema, 0);
        // Should remain an enum, not converted to const
        assert!(schema["properties"]["mode"].get("enum").is_some());
        assert!(schema["properties"]["mode"].get("const").is_none());
    }

    #[test]
    fn test_compress_inline_nested_single_enum() {
        let mut schema = json!({
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "format": {"enum": ["json"]}
                    }
                }
            }
        });
        inline_single_value_enums(&mut schema, 0);
        assert_eq!(
            schema["properties"]["config"]["properties"]["format"]["const"],
            "json"
        );
    }

    #[test]
    fn test_compress_inline_single_enum_numeric() {
        let mut schema = json!({
            "properties": {
                "count": {"enum": [1]}
            }
        });
        inline_single_value_enums(&mut schema, 0);
        assert_eq!(schema["properties"]["count"]["const"], 1);
    }

    // ── truncate_descriptions ────────────────────────────────────────────

    #[test]
    fn test_compress_truncate_description() {
        let mut schema = json!({
            "description": "Read a file from disk. Returns the contents as a string. Useful for debugging.",
            "properties": {
                "path": {"type": "string", "description": "The path to the file. Must be absolute. No symlinks allowed."}
            }
        });
        truncate_descriptions(&mut schema, 0);
        assert_eq!(schema["description"], "Read a file from disk.");
        assert_eq!(
            schema["properties"]["path"]["description"],
            "The path to the file."
        );
    }

    #[test]
    fn test_compress_truncate_preserves_short() {
        let mut schema = json!({
            "description": "Short desc"
        });
        truncate_descriptions(&mut schema, 0);
        assert_eq!(schema["description"], "Short desc");
    }

    #[test]
    fn test_compress_truncate_empty_description() {
        let mut schema = json!({"description": ""});
        truncate_descriptions(&mut schema, 0);
        assert_eq!(schema["description"], "");
    }

    #[test]
    fn test_compress_truncate_with_exclamation() {
        let mut schema = json!({
            "description": "Warning! This tool is dangerous. Use with caution."
        });
        truncate_descriptions(&mut schema, 0);
        assert_eq!(schema["description"], "Warning!");
    }

    #[test]
    fn test_compress_truncate_with_question() {
        let mut schema = json!({
            "description": "Ready? Execute the command. Then verify."
        });
        truncate_descriptions(&mut schema, 0);
        assert_eq!(schema["description"], "Ready?");
    }

    #[test]
    fn test_compress_truncate_period_in_url() {
        // Period followed by non-space should not be treated as sentence end
        let mut schema = json!({
            "description": "Access api.example.com for data"
        });
        truncate_descriptions(&mut schema, 0);
        assert_eq!(schema["description"], "Access api.example.com for data");
    }

    // ── collapse_single_property_objects ──────────────────────────────────

    #[test]
    fn test_compress_collapse_single_property() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "wrapper": {
                    "type": "object",
                    "properties": {
                        "inner": {"type": "string"}
                    }
                }
            }
        });
        collapse_single_property_objects(&mut schema, 0);
        assert_eq!(schema["properties"]["wrapper"]["type"], "string");
    }

    #[test]
    fn test_compress_no_collapse_multi_property() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "wrapper": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string"},
                        "b": {"type": "integer"}
                    }
                }
            }
        });
        collapse_single_property_objects(&mut schema, 0);
        // Should remain unchanged — wrapper has 2 properties
        assert_eq!(schema["properties"]["wrapper"]["type"], "object");
        assert!(schema["properties"]["wrapper"]["properties"]["a"].is_object());
    }

    #[test]
    fn test_compress_no_collapse_non_object_type() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "arr": {
                    "type": "array",
                    "properties": {
                        "item": {"type": "string"}
                    }
                }
            }
        });
        collapse_single_property_objects(&mut schema, 0);
        // Not type:object, should not collapse
        assert_eq!(schema["properties"]["arr"]["type"], "array");
    }

    // ── remove_optional_descriptions ─────────────────────────────────────

    #[test]
    fn test_compress_remove_optional_descriptions() {
        let mut schema = json!({
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "description": "Required path"},
                "verbose": {"type": "boolean", "description": "Optional verbose flag"}
            }
        });
        remove_optional_descriptions(&mut schema, 0);
        // Required field keeps its description
        assert_eq!(schema["properties"]["path"]["description"], "Required path");
        // Optional field loses its description
        assert!(schema["properties"]["verbose"].get("description").is_none());
    }

    #[test]
    fn test_compress_keeps_required_descriptions() {
        let mut schema = json!({
            "required": ["a", "b"],
            "properties": {
                "a": {"type": "string", "description": "Field A"},
                "b": {"type": "integer", "description": "Field B"}
            }
        });
        remove_optional_descriptions(&mut schema, 0);
        assert_eq!(schema["properties"]["a"]["description"], "Field A");
        assert_eq!(schema["properties"]["b"]["description"], "Field B");
    }

    #[test]
    fn test_compress_remove_optional_no_required_array() {
        let mut schema = json!({
            "properties": {
                "x": {"type": "string", "description": "Will be removed"}
            }
        });
        remove_optional_descriptions(&mut schema, 0);
        // No required array means all are optional, so description removed
        assert!(schema["properties"]["x"].get("description").is_none());
    }

    // ── estimate_tokens ──────────────────────────────────────────────────

    #[test]
    fn test_estimate_tokens_basic() {
        let schema = json!({"type": "object"});
        let tokens = SchemaCompressor::estimate_tokens(&schema);
        // {"type":"object"} = 17 chars => ceil(17/4) = 5
        assert_eq!(tokens, 5);
    }

    #[test]
    fn test_estimate_tokens_empty_object() {
        let schema = json!({});
        let tokens = SchemaCompressor::estimate_tokens(&schema);
        // {} = 2 chars => ceil(2/4) = 1
        assert_eq!(tokens, 1);
    }

    #[test]
    fn test_estimate_tokens_null() {
        let schema = Value::Null;
        let tokens = SchemaCompressor::estimate_tokens(&schema);
        // "null" = 4 chars => ceil(4/4) = 1
        assert_eq!(tokens, 1);
    }

    #[test]
    fn test_estimate_tokens_large_schema() {
        let desc = "A ".repeat(500); // 1000 chars
        let schema = json!({"description": desc});
        let tokens = SchemaCompressor::estimate_tokens(&schema);
        assert!(tokens > 200);
    }

    // ── full compress pipeline ───────────────────────────────────────────

    #[test]
    fn test_compress_within_budget_no_changes() {
        let schema = json!({"type": "string"});
        let budget = 1000;
        let result = SchemaCompressor::compress(&schema, budget);
        assert_eq!(result, schema);
    }

    #[test]
    fn test_compress_progressive_strategies() {
        // Build a schema large enough to require multiple compression stages
        let schema = json!({
            "type": "object",
            "description": "A very detailed description of a complex tool. It has many features. And more features. Plus even more features.",
            "required": ["path"],
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to read. Must be an absolute path. Relative paths are rejected."
                },
                "encoding": {
                    "type": "string",
                    "description": "The encoding to use when reading. Defaults to UTF-8. Can be ASCII.",
                    "enum": ["utf8"]
                },
                "verbose": {
                    "type": "boolean",
                    "description": "Whether to print extra output. Useful for debugging. Not recommended in production."
                }
            }
        });

        let original_tokens = SchemaCompressor::estimate_tokens(&schema);

        // Set a tight budget that requires compression
        let budget = original_tokens / 2;
        let result = SchemaCompressor::compress(&schema, budget);
        let result_tokens = SchemaCompressor::estimate_tokens(&result);
        assert!(
            result_tokens <= budget,
            "expected tokens <= {}, got {}",
            budget,
            result_tokens
        );
    }

    #[test]
    fn test_compress_zero_budget_applies_all_strategies() {
        let schema = json!({
            "type": "object",
            "description": "Read a file. Returns contents.",
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "description": "The path."},
                "mode": {"enum": ["read"]},
                "extra": {
                    "type": "object",
                    "properties": {
                        "flag": {"type": "boolean", "description": "A flag. Unused."}
                    }
                }
            }
        });

        // Budget 0 forces all strategies to run
        let result = SchemaCompressor::compress(&schema, 0);

        // root "type": "object" stripped
        assert!(result.get("type").is_none());
        // single enum inlined to const
        assert_eq!(result["properties"]["mode"]["const"], "read");
        // descriptions truncated
        assert_eq!(result["description"], "Read a file.");
    }

    #[test]
    fn test_compress_empty_schema() {
        let schema = json!({});
        let result = SchemaCompressor::compress(&schema, 0);
        assert_eq!(result, json!({}));
    }

    #[test]
    fn test_compress_non_object_schema() {
        // Edge case: schema is not an object
        let schema = json!("just a string");
        let result = SchemaCompressor::compress(&schema, 0);
        assert_eq!(result, json!("just a string"));
    }

    #[test]
    fn test_compress_null_schema() {
        let result = SchemaCompressor::compress(&Value::Null, 0);
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn test_compress_deeply_nested_enums() {
        let mut schema = json!({
            "properties": {
                "a": {
                    "type": "object",
                    "properties": {
                        "b": {
                            "type": "object",
                            "properties": {
                                "c": {"enum": ["deep_value"]}
                            }
                        }
                    }
                }
            }
        });
        inline_single_value_enums(&mut schema, 0);
        assert_eq!(
            schema["properties"]["a"]["properties"]["b"]["properties"]["c"]["const"],
            "deep_value"
        );
    }

    #[test]
    fn test_compress_enum_in_array() {
        let mut schema = json!({
            "items": [
                {"enum": ["only"]},
                {"enum": ["a", "b"]}
            ]
        });
        inline_single_value_enums(&mut schema, 0);
        assert_eq!(schema["items"][0]["const"], "only");
        assert!(schema["items"][1].get("const").is_none());
    }

    #[test]
    fn test_compress_empty_enum_unchanged() {
        let mut schema = json!({
            "properties": {
                "x": {"enum": []}
            }
        });
        inline_single_value_enums(&mut schema, 0);
        // Empty enum should not be converted
        assert!(schema["properties"]["x"].get("enum").is_some());
        assert!(schema["properties"]["x"].get("const").is_none());
    }

    #[test]
    fn test_compress_description_sentence_at_end() {
        let mut schema = json!({"description": "Only sentence."});
        truncate_descriptions(&mut schema, 0);
        // Period is at end of string, so entire string is first sentence
        assert_eq!(schema["description"], "Only sentence.");
    }

    #[test]
    fn test_compress_multiple_properties_collapse_only_singles() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "single": {
                    "type": "object",
                    "properties": {
                        "val": {"type": "integer"}
                    }
                },
                "multi": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string"},
                        "b": {"type": "string"}
                    }
                }
            }
        });
        collapse_single_property_objects(&mut schema, 0);
        // single should be collapsed
        assert_eq!(schema["properties"]["single"]["type"], "integer");
        // multi should remain
        assert_eq!(schema["properties"]["multi"]["type"], "object");
    }

    #[test]
    fn test_first_sentence_no_punctuation() {
        assert_eq!(first_sentence("No period here"), "No period here");
    }

    #[test]
    fn test_first_sentence_period_at_very_end() {
        assert_eq!(first_sentence("Ends with period."), "Ends with period.");
    }

    #[test]
    fn test_first_sentence_empty() {
        assert_eq!(first_sentence(""), "");
    }

    #[test]
    fn test_first_sentence_whitespace_only() {
        assert_eq!(first_sentence("   "), "");
    }

    /// SECURITY (IMP-R110-003): Deeply nested schemas do not overflow the stack.
    #[test]
    fn test_compress_deeply_nested_schema_no_stack_overflow() {
        // Build a schema nested > MAX_SCHEMA_DEPTH levels deep
        let mut schema = json!({"description": "leaf. extra sentence.", "enum": ["only"]});
        for _ in 0..(MAX_SCHEMA_DEPTH + 20) {
            schema = json!({
                "type": "object",
                "properties": {
                    "nested": schema
                }
            });
        }
        // Should not panic/stack overflow — just stops recursing at MAX_SCHEMA_DEPTH
        let result = SchemaCompressor::compress(&schema, 0);
        // The top-level type:"object" should still be stripped
        assert!(result.get("type").is_none());
    }

    // ── FIND-R131-001: estimate_tokens fail-closed ────────────────────────

    #[test]
    fn test_estimate_tokens_nonzero_for_any_valid_value() {
        // All non-"" JSON values should produce a non-zero estimate
        for val in [
            json!(null),
            json!(true),
            json!(42),
            json!("x"),
            json!([]),
            json!({}),
        ] {
            let tokens = SchemaCompressor::estimate_tokens(&val);
            assert!(tokens > 0, "Expected >0 tokens for {:?}", val);
        }
    }
}
