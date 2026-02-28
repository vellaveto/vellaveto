// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

use serde_json::Value;
use vellaveto_types::{CanonicalToolSchema, ModelFamily};

use super::error::ProjectorError;

/// Attempts to repair malformed tool calls against their expected schema.
///
/// Repair strategies applied (in order):
/// 1. Extract JSON from markdown code blocks (DeepSeek-specific)
/// 2. Parse stringified arguments into objects
/// 3. Correct hallucinated tool names via Levenshtein distance
/// 4. Coerce mismatched types (string/integer/boolean)
/// 5. Inject missing required fields that have defaults in the schema
pub struct CallRepairer;

impl CallRepairer {
    /// Attempt to repair a malformed tool call.
    ///
    /// `call` is the raw tool call value from the model.
    /// `schema` is the canonical tool schema the call should conform to.
    /// `model` is the model family (used for model-specific repairs).
    ///
    /// Returns `Ok(repaired_value)` if repair succeeded, `Err` if unfixable.
    pub fn repair(
        call: &Value,
        schema: &CanonicalToolSchema,
        model: &ModelFamily,
    ) -> Result<Value, ProjectorError> {
        let mut result = call.clone();

        // Strategy 1: DeepSeek-specific — extract JSON from markdown code blocks
        if matches!(model, ModelFamily::DeepSeek) {
            if let Some(s) = result.as_str() {
                result = extract_json_from_code_block(s)?;
            }
        }

        // Strategy 2: If arguments field is a JSON string, parse it into an object
        result = parse_string_arguments(result);

        // Strategy 3: Correct hallucinated tool name if close to schema name
        result = correct_tool_name(result, &schema.name)?;

        // Strategy 4: Type coercion on arguments against schema
        result = coerce_argument_types(result, &schema.input_schema);

        // Strategy 5: Inject missing required fields that have defaults
        result = inject_missing_defaults(result, &schema.input_schema);

        Ok(result)
    }
}

/// Extract JSON from a markdown code block.
///
/// Handles patterns like:
/// - ```json\n{...}\n```
/// - ```\n{...}\n```
/// - <think>...</think> prefix followed by JSON or code block
fn extract_json_from_code_block(text: &str) -> Result<Value, ProjectorError> {
    // SECURITY (FIND-R182-002): Bound input size before cloning to prevent
    // memory exhaustion from oversized model responses.
    const MAX_CODE_BLOCK_INPUT_SIZE: usize = 1_048_576; // 1 MiB
    if text.len() > MAX_CODE_BLOCK_INPUT_SIZE {
        return Err(ProjectorError::ParseError(format!(
            "input too large for code block extraction: {} bytes (max {})",
            text.len(),
            MAX_CODE_BLOCK_INPUT_SIZE
        )));
    }
    let mut cleaned = text.to_string();

    // Remove <think>...</think> blocks
    // SECURITY (FIND-R55-MCP-007): Bound iteration count to prevent DoS via
    // crafted input with many nested/repeated <think> tags.
    const MAX_THINK_TAG_ITERATIONS: usize = 100;
    let mut think_iterations = 0usize;
    while let Some(start) = cleaned.find("<think>") {
        think_iterations += 1;
        if think_iterations > MAX_THINK_TAG_ITERATIONS {
            tracing::warn!(
                "extract_json_from_code_block: exceeded {} think-tag removal iterations, breaking",
                MAX_THINK_TAG_ITERATIONS
            );
            break;
        }
        if let Some(end) = cleaned[start..].find("</think>") {
            let end_abs = start + end + "</think>".len();
            cleaned.replace_range(start..end_abs, "");
        } else {
            // Unclosed <think> tag — remove from <think> to end
            cleaned.truncate(start);
            break;
        }
    }

    let cleaned = cleaned.trim();

    // Try direct JSON parse first
    if let Ok(v) = serde_json::from_str::<Value>(cleaned) {
        return Ok(v);
    }

    // Try extracting from markdown code blocks
    if let Some(start) = cleaned.find("```") {
        let after_ticks = &cleaned[start + 3..];
        // Skip optional language tag (e.g., "json")
        let json_start = after_ticks
            .trim_start_matches(|c: char| c.is_alphabetic())
            .trim_start();
        if let Some(end) = json_start.find("```") {
            let json_text = json_start[..end].trim();
            if let Ok(v) = serde_json::from_str::<Value>(json_text) {
                return Ok(v);
            }
        }
    }

    Err(ProjectorError::ParseError(
        "could not extract JSON from code block".to_string(),
    ))
}

/// If the `arguments` field is a JSON string, parse it into an object.
fn parse_string_arguments(mut call: Value) -> Value {
    if let Some(obj) = call.as_object_mut() {
        let needs_parse = obj.get("arguments").map(|v| v.is_string()).unwrap_or(false);

        if needs_parse {
            if let Some(Value::String(s)) = obj.get("arguments") {
                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                    if parsed.is_object() {
                        obj.insert("arguments".to_string(), parsed);
                    }
                }
            }
        }
    }
    call
}

/// Maximum tool name length for Levenshtein distance computation.
///
/// Levenshtein is O(m*n) time and space. User-supplied tool names are unbounded,
/// so we skip the expensive computation for names exceeding this threshold.
/// (FIND-R84-001)
const MAX_TOOL_NAME_LEN_FOR_REPAIR: usize = 256;

/// Correct a hallucinated tool name if it is within Levenshtein distance 3 of the schema name.
fn correct_tool_name(mut call: Value, schema_name: &str) -> Result<Value, ProjectorError> {
    if let Some(obj) = call.as_object_mut() {
        // Check common tool name field locations
        for field in &["tool_name", "name"] {
            if let Some(Value::String(call_name)) = obj.get(*field) {
                if call_name != schema_name {
                    // SECURITY (FIND-R84-001): Skip Levenshtein (O(m*n)) for oversized names
                    if call_name.len() > MAX_TOOL_NAME_LEN_FOR_REPAIR
                        || schema_name.len() > MAX_TOOL_NAME_LEN_FOR_REPAIR
                    {
                        tracing::warn!(
                            call_name_len = call_name.len(),
                            schema_name_len = schema_name.len(),
                            max = MAX_TOOL_NAME_LEN_FOR_REPAIR,
                            "skipping Levenshtein repair: tool name exceeds length bound"
                        );
                        continue;
                    }
                    let dist = levenshtein(call_name, schema_name);
                    if dist <= 3 {
                        obj.insert(field.to_string(), Value::String(schema_name.to_string()));
                    }
                    // If distance > 3, leave it alone (unfixable typo or intentional)
                }
            }
        }

        // Also check nested function.name (OpenAI/DeepSeek format)
        if let Some(Value::Object(func)) = obj.get_mut("function") {
            if let Some(Value::String(call_name)) = func.get("name") {
                if call_name != schema_name {
                    // SECURITY (FIND-R84-001): Skip Levenshtein (O(m*n)) for oversized names
                    if call_name.len() > MAX_TOOL_NAME_LEN_FOR_REPAIR
                        || schema_name.len() > MAX_TOOL_NAME_LEN_FOR_REPAIR
                    {
                        tracing::warn!(
                            call_name_len = call_name.len(),
                            schema_name_len = schema_name.len(),
                            max = MAX_TOOL_NAME_LEN_FOR_REPAIR,
                            "skipping Levenshtein repair: function name exceeds length bound"
                        );
                    } else {
                        let dist = levenshtein(call_name, schema_name);
                        if dist <= 3 {
                            func.insert("name".to_string(), Value::String(schema_name.to_string()));
                        }
                    }
                }
            }
        }
    }
    Ok(call)
}

/// Coerce argument types to match the schema.
///
/// Handles:
/// - String -> Integer: "42" -> 42
/// - String -> Number: "3.14" -> 3.14
/// - Number -> String: 42 -> "42"
/// - String -> Boolean: "true"/"false" -> true/false
/// - Boolean -> String: true -> "true"
fn coerce_argument_types(mut call: Value, input_schema: &Value) -> Value {
    let schema_properties = input_schema
        .as_object()
        .and_then(|o| o.get("properties"))
        .and_then(|p| p.as_object());

    let schema_properties = match schema_properties {
        Some(p) => p,
        None => return call,
    };

    // Get mutable reference to arguments
    let arguments = call
        .as_object_mut()
        .and_then(|o| o.get_mut("arguments"))
        .and_then(|a| a.as_object_mut());

    let arguments = match arguments {
        Some(a) => a,
        None => return call,
    };

    for (field_name, prop_schema) in schema_properties {
        let expected_type = prop_schema
            .as_object()
            .and_then(|o| o.get("type"))
            .and_then(|t| t.as_str());

        let expected_type = match expected_type {
            Some(t) => t,
            None => continue,
        };

        if let Some(current_value) = arguments.get(field_name).cloned() {
            let coerced = coerce_value(&current_value, expected_type);
            if let Some(new_val) = coerced {
                arguments.insert(field_name.clone(), new_val);
            }
        }
    }

    call
}

/// Attempt to coerce a single value to the expected JSON Schema type.
/// Returns `Some(coerced)` if coercion was performed, `None` if not needed or impossible.
fn coerce_value(value: &Value, expected_type: &str) -> Option<Value> {
    match (value, expected_type) {
        // String -> Integer
        (Value::String(s), "integer") => s.trim().parse::<i64>().ok().map(Value::from),
        // String -> Number
        (Value::String(s), "number") => s.trim().parse::<f64>().ok().map(|f| {
            serde_json::Number::from_f64(f)
                .map(Value::Number)
                .unwrap_or(Value::String(s.clone()))
        }),
        // Number -> String
        (Value::Number(n), "string") => Some(Value::String(n.to_string())),
        // Boolean -> String
        (Value::Bool(b), "string") => Some(Value::String(b.to_string())),
        // String -> Boolean
        (Value::String(s), "boolean") => match s.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" => Some(Value::Bool(true)),
            "false" | "0" | "no" => Some(Value::Bool(false)),
            _ => None,
        },
        _ => None,
    }
}

/// Inject missing required fields that have a `"default"` value in the schema.
fn inject_missing_defaults(mut call: Value, input_schema: &Value) -> Value {
    let schema_obj = match input_schema.as_object() {
        Some(o) => o,
        None => return call,
    };

    let required_fields: Vec<String> = schema_obj
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let schema_properties = match schema_obj.get("properties").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return call,
    };

    let arguments = match call
        .as_object_mut()
        .and_then(|o| o.get_mut("arguments"))
        .and_then(|a| a.as_object_mut())
    {
        Some(a) => a,
        None => return call,
    };

    for field_name in &required_fields {
        if arguments.contains_key(field_name) {
            continue;
        }

        // Check if the schema has a default for this required field
        if let Some(prop_schema) = schema_properties.get(field_name) {
            if let Some(default_val) = prop_schema.as_object().and_then(|o| o.get("default")) {
                arguments.insert(field_name.clone(), default_val.clone());
            }
        }
    }

    call
}

/// Compute the Levenshtein edit distance between two strings.
///
/// Uses the classic dynamic programming approach with O(min(m,n)) space.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    // Optimize: ensure b is the shorter string for better space usage
    if a_len < b_len {
        return levenshtein(b, a);
    }

    // Previous row of distances
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr: Vec<usize> = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr[0] = i;
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1) // deletion
                .min(curr[j - 1] + 1) // insertion
                .min(prev[j - 1] + cost); // substitution
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_schema(name: &str, input_schema: Value) -> CanonicalToolSchema {
        CanonicalToolSchema {
            name: name.to_string(),
            description: "Test tool".to_string(),
            input_schema,
            output_schema: None,
        }
    }

    // ── levenshtein ──────────────────────────────────────────────────────

    #[test]
    fn test_levenshtein_identical() {
        assert_eq!(levenshtein("hello", "hello"), 0);
    }

    #[test]
    fn test_levenshtein_empty_strings() {
        assert_eq!(levenshtein("", ""), 0);
    }

    #[test]
    fn test_levenshtein_one_empty() {
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", "xyz"), 3);
    }

    #[test]
    fn test_levenshtein_single_char_diff() {
        assert_eq!(levenshtein("cat", "bat"), 1);
    }

    #[test]
    fn test_levenshtein_insertion() {
        assert_eq!(levenshtein("read_file", "read_flie"), 2);
    }

    #[test]
    fn test_levenshtein_completely_different() {
        assert_eq!(levenshtein("abc", "xyz"), 3);
    }

    #[test]
    fn test_levenshtein_symmetric() {
        let d1 = levenshtein("kitten", "sitting");
        let d2 = levenshtein("sitting", "kitten");
        assert_eq!(d1, d2);
        assert_eq!(d1, 3);
    }

    #[test]
    fn test_levenshtein_prefix() {
        assert_eq!(levenshtein("read", "read_file"), 5);
    }

    // ── type coercion ────────────────────────────────────────────────────

    #[test]
    fn test_repair_string_to_integer() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "count": {"type": "integer"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"count": "42"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["count"], 42);
    }

    #[test]
    fn test_repair_string_to_number() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "rate": {"type": "number"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"rate": "3.14"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        let rate = result["arguments"]["rate"].as_f64().unwrap();
        let expected = "3.14".parse::<f64>().unwrap();
        assert!((rate - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_repair_number_to_string() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "id": {"type": "string"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"id": 42}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["id"], "42");
    }

    #[test]
    fn test_repair_boolean_to_string() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "flag": {"type": "string"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"flag": true}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["flag"], "true");
    }

    #[test]
    fn test_repair_string_to_boolean_true() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "verbose": {"type": "boolean"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"verbose": "true"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["verbose"], true);
    }

    #[test]
    fn test_repair_string_to_boolean_false() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "verbose": {"type": "boolean"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"verbose": "false"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["verbose"], false);
    }

    #[test]
    fn test_repair_string_to_boolean_yes() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "confirm": {"type": "boolean"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"confirm": "yes"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["confirm"], true);
    }

    // ── missing required with default ────────────────────────────────────

    #[test]
    fn test_repair_missing_required_with_default() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "required": ["path", "encoding"],
                "properties": {
                    "path": {"type": "string"},
                    "encoding": {"type": "string", "default": "utf-8"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"path": "/tmp/file.txt"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["encoding"], "utf-8");
        assert_eq!(result["arguments"]["path"], "/tmp/file.txt");
    }

    #[test]
    fn test_repair_missing_required_no_default() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {"type": "string"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {}
        });
        // No default for "path", so it stays missing — repair doesn't fail, just can't inject
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert!(result["arguments"].get("path").is_none());
    }

    #[test]
    fn test_repair_existing_required_not_overwritten() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": {"type": "string", "default": "read"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"mode": "write"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        // Existing value should NOT be overwritten by default
        assert_eq!(result["arguments"]["mode"], "write");
    }

    // ── hallucinated tool name ───────────────────────────────────────────

    #[test]
    fn test_repair_hallucinated_name_close_match() {
        let schema = make_schema("read_file", json!({"type": "object"}));
        let call = json!({
            "name": "read_flie",
            "arguments": {}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["name"], "read_file");
    }

    #[test]
    fn test_repair_hallucinated_name_exact_match() {
        let schema = make_schema("read_file", json!({"type": "object"}));
        let call = json!({
            "name": "read_file",
            "arguments": {}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["name"], "read_file");
    }

    #[test]
    fn test_repair_hallucinated_name_too_far() {
        let schema = make_schema("read_file", json!({"type": "object"}));
        let call = json!({
            "name": "completely_different",
            "arguments": {}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        // Distance > 3, should NOT be corrected
        assert_eq!(result["name"], "completely_different");
    }

    #[test]
    fn test_repair_hallucinated_name_distance_3() {
        let schema = make_schema("search", json!({"type": "object"}));
        let call = json!({
            "name": "sreach",
            "arguments": {}
        });
        let dist = levenshtein("sreach", "search");
        assert_eq!(dist, 2); // transposition counts as 2 in Levenshtein
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["name"], "search");
    }

    #[test]
    fn test_repair_hallucinated_function_name() {
        let schema = make_schema("read_file", json!({"type": "object"}));
        let call = json!({
            "function": {
                "name": "read_flie",
                "arguments": {}
            }
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["function"]["name"], "read_file");
    }

    #[test]
    fn test_repair_hallucinated_name_skips_levenshtein_for_long_names() {
        let schema = make_schema("read_file", json!({"type": "object"}));
        // Name exceeds MAX_TOOL_NAME_LEN_FOR_REPAIR (256)
        let long_name = "a".repeat(300);
        let call = json!({
            "name": long_name,
            "arguments": {}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        // Should NOT attempt repair — name left as-is
        assert_eq!(result["name"], long_name);
    }

    #[test]
    fn test_repair_hallucinated_function_name_skips_levenshtein_for_long_names() {
        let schema = make_schema("read_file", json!({"type": "object"}));
        let long_name = "b".repeat(300);
        let call = json!({
            "function": {
                "name": long_name,
                "arguments": {}
            }
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        // Should NOT attempt repair — function name left as-is
        assert_eq!(result["function"]["name"], long_name);
    }

    #[test]
    fn test_repair_hallucinated_name_at_boundary_length() {
        let schema = make_schema("read_file", json!({"type": "object"}));
        // Exactly at the limit (256 chars) — should still compute Levenshtein
        let at_limit_name = "x".repeat(256);
        let call = json!({
            "name": at_limit_name,
            "arguments": {}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        // Distance > 3, so not corrected, but Levenshtein was computed
        assert_eq!(result["name"], at_limit_name);
    }

    // ── arguments as string ──────────────────────────────────────────────

    #[test]
    fn test_repair_arguments_as_string() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": "{\"path\": \"/tmp\"}"
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["path"], "/tmp");
    }

    #[test]
    fn test_repair_arguments_as_invalid_string() {
        let schema = make_schema("tool", json!({"type": "object"}));
        let call = json!({
            "name": "tool",
            "arguments": "not valid json"
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        // Unparseable string remains as-is
        assert_eq!(result["arguments"], "not valid json");
    }

    // ── DeepSeek-specific ────────────────────────────────────────────────

    #[test]
    fn test_repair_deepseek_code_block() {
        let schema = make_schema(
            "search",
            json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                }
            }),
        );
        let call =
            json!("```json\n{\"name\": \"search\", \"arguments\": {\"query\": \"test\"}}\n```");
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::DeepSeek).unwrap();
        assert_eq!(result["name"], "search");
        assert_eq!(result["arguments"]["query"], "test");
    }

    #[test]
    fn test_repair_deepseek_with_think_tags() {
        let schema = make_schema(
            "search",
            json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                }
            }),
        );
        let call = json!("<think>I need to search</think>{\"name\": \"search\", \"arguments\": {\"query\": \"hello\"}}");
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::DeepSeek).unwrap();
        assert_eq!(result["name"], "search");
        assert_eq!(result["arguments"]["query"], "hello");
    }

    #[test]
    fn test_repair_deepseek_not_applied_to_other_models() {
        let schema = make_schema("tool", json!({"type": "object"}));
        // For non-DeepSeek models, string values are NOT parsed as code blocks
        let call = json!("```json\n{\"name\": \"tool\"}\n```");
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::OpenAi).unwrap();
        // Should remain a string since OpenAI doesn't get code block extraction
        assert!(result.is_string());
    }

    // ── no changes needed ────────────────────────────────────────────────

    #[test]
    fn test_repair_no_changes_needed() {
        let schema = make_schema(
            "read_file",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                }
            }),
        );
        let call = json!({
            "name": "read_file",
            "arguments": {"path": "/tmp/test.txt"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result, call);
    }

    // ── edge cases ───────────────────────────────────────────────────────

    #[test]
    fn test_repair_empty_arguments() {
        let schema = make_schema("tool", json!({"type": "object"}));
        let call = json!({
            "name": "tool",
            "arguments": {}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"], json!({}));
    }

    #[test]
    fn test_repair_null_arguments() {
        let schema = make_schema("tool", json!({"type": "object"}));
        let call = json!({
            "name": "tool",
            "arguments": null
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert!(result["arguments"].is_null());
    }

    #[test]
    fn test_repair_missing_arguments_field() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "required": ["x"],
                "properties": {
                    "x": {"type": "integer", "default": 0}
                }
            }),
        );
        let call = json!({"name": "tool"});
        // No "arguments" field at all — inject_missing_defaults can't inject
        // because there's no arguments object to inject into
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert!(result.get("arguments").is_none());
    }

    #[test]
    fn test_repair_non_object_call() {
        let schema = make_schema("tool", json!({"type": "object"}));
        let call = json!(42);
        // Non-DeepSeek, non-string — passes through unchanged
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result, json!(42));
    }

    #[test]
    fn test_repair_string_to_integer_with_whitespace() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "count": {"type": "integer"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"count": " 42 "}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["count"], 42);
    }

    #[test]
    fn test_repair_unparseable_string_to_integer() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "count": {"type": "integer"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {"count": "not_a_number"}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        // Can't parse — stays as string
        assert_eq!(result["arguments"]["count"], "not_a_number");
    }

    #[test]
    fn test_repair_multiple_coercions() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                    "name": {"type": "string"},
                    "active": {"type": "boolean"}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {
                "count": "10",
                "name": 42,
                "active": "true"
            }
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["count"], 10);
        assert_eq!(result["arguments"]["name"], "42");
        assert_eq!(result["arguments"]["active"], true);
    }

    #[test]
    fn test_repair_default_numeric_value() {
        let schema = make_schema(
            "tool",
            json!({
                "type": "object",
                "required": ["limit"],
                "properties": {
                    "limit": {"type": "integer", "default": 100}
                }
            }),
        );
        let call = json!({
            "name": "tool",
            "arguments": {}
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        assert_eq!(result["arguments"]["limit"], 100);
    }

    #[test]
    fn test_repair_deepseek_unclosed_think_tag() {
        let schema = make_schema("tool", json!({"type": "object"}));
        let call = json!("<think>partial reasoning");
        // Unclosed think tag — text after <think> is truncated, leaving empty string
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::DeepSeek);
        // Should fail to parse since nothing remains
        assert!(result.is_err());
    }

    #[test]
    fn test_repair_arguments_string_non_object_json() {
        let schema = make_schema("tool", json!({"type": "object"}));
        let call = json!({
            "name": "tool",
            "arguments": "[1, 2, 3]"
        });
        let result = CallRepairer::repair(&call, &schema, &ModelFamily::Generic).unwrap();
        // Parses as array, not object, so string remains
        assert_eq!(result["arguments"], "[1, 2, 3]");
    }

    // ── FIND-R182-002: Code block input size bound ────────────────────────

    #[test]
    fn test_extract_json_from_code_block_exceeds_max_size() {
        // Input > 1 MiB should be rejected.
        let huge = "x".repeat(1_048_577);
        let err = extract_json_from_code_block(&huge).unwrap_err();
        assert!(
            err.to_string().contains("input too large"),
            "Expected 'input too large', got: {}",
            err
        );
    }

    #[test]
    fn test_extract_json_from_code_block_at_max_size() {
        // Input at exactly 1 MiB should be accepted (may fail to parse, but not size-rejected).
        let at_max = "x".repeat(1_048_576);
        let result = extract_json_from_code_block(&at_max);
        // Should be a parse error, not a size error
        if let Err(e) = result {
            assert!(
                !e.to_string().contains("input too large"),
                "1MiB input should not be size-rejected: {}",
                e
            );
        }
    }
}
