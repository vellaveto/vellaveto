//! Elicitation and sampling request inspection (P2.2 + P2.3).
//!
//! MCP 2025-06-18 introduced `elicitation/create` — a mechanism for servers
//! to prompt the user for input. This can be abused for social engineering
//! (requesting passwords, API keys, SSNs). This module inspects elicitation
//! requests against configurable policies.
//!
//! MCP `sampling/createMessage` allows servers to request the LLM to generate
//! text. This can be an exfiltration vector when tool output is included in
//! the sampling prompt ("data laundering"). This module enforces configurable
//! policies on sampling requests.

use serde_json::Value;

/// Result of elicitation inspection.
#[derive(Debug)]
pub enum ElicitationVerdict {
    /// The elicitation request is allowed.
    Allow,
    /// The elicitation request is denied.
    Deny { reason: String },
}

/// Inspect an `elicitation/create` request against the configured policy.
///
/// Checks:
/// 1. Master toggle (`enabled`). Default is disabled (fail-closed).
/// 2. Per-session rate limit (`max_per_session`).
/// 3. Blocked field types in the elicitation schema.
///
/// # Arguments
/// - `params`: The JSON-RPC params from the `elicitation/create` request.
/// - `config`: The elicitation policy configuration.
/// - `session_elicitation_count`: Number of elicitation requests already
///   processed in this session.
pub fn inspect_elicitation(
    params: &Value,
    config: &sentinel_config::ElicitationConfig,
    session_elicitation_count: u32,
) -> ElicitationVerdict {
    if !config.enabled {
        return ElicitationVerdict::Deny {
            reason: "elicitation is disabled".to_string(),
        };
    }

    // Rate limit check
    if session_elicitation_count >= config.max_per_session {
        return ElicitationVerdict::Deny {
            reason: format!(
                "elicitation rate limit exceeded ({}/{})",
                session_elicitation_count, config.max_per_session
            ),
        };
    }

    // Check for blocked field types in the schema.
    // MCP elicitation uses `requestedSchema` per the spec, but we also
    // check `schema` as a defensive measure against variant spellings.
    if let Some(schema) = params
        .get("requestedSchema")
        .or_else(|| params.get("schema"))
    {
        for blocked_type in &config.blocked_field_types {
            if schema_contains_field_type(schema, blocked_type) {
                return ElicitationVerdict::Deny {
                    reason: format!("elicitation requests blocked field type: {}", blocked_type),
                };
            }
        }
    }

    ElicitationVerdict::Allow
}

/// Check if a JSON schema contains a field with a given type or format name.
///
/// Searches recursively through:
/// - `"type"` fields (exact match, case-insensitive)
/// - `"format"` fields (exact match, case-insensitive)
/// - `"properties"` objects (recurse into each property's schema)
/// - `"items"` (for array schemas)
///
/// Also checks if any property *name* matches the blocked type
/// (e.g. a property named "password" is suspicious regardless of its schema type).
fn schema_contains_field_type(schema: &Value, field_type: &str) -> bool {
    schema_contains_field_type_inner(schema, field_type, 0)
}

/// Maximum recursion depth for schema scanning.
const MAX_SCHEMA_SCAN_DEPTH: usize = 32;

fn schema_contains_field_type_inner(schema: &Value, field_type: &str, depth: usize) -> bool {
    if depth >= MAX_SCHEMA_SCAN_DEPTH {
        // SECURITY (R24-MCP-9): Fail-closed — deeply nested schemas are treated
        // as suspicious rather than passing through unchecked.
        return true;
    }

    let ft_lower = field_type.to_lowercase();

    // Check "type" field
    if let Some(type_val) = schema.get("type").and_then(|v| v.as_str()) {
        if type_val.to_lowercase() == ft_lower {
            return true;
        }
    }

    // Check "format" field (e.g. "format": "password")
    if let Some(format_val) = schema.get("format").and_then(|v| v.as_str()) {
        if format_val.to_lowercase() == ft_lower {
            return true;
        }
    }

    // Recurse into "properties"
    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (prop_name, prop_schema) in props {
            // Check if the property name itself matches the blocked type
            if prop_name.to_lowercase() == ft_lower {
                return true;
            }
            if schema_contains_field_type_inner(prop_schema, field_type, depth + 1) {
                return true;
            }
        }
    }

    // Recurse into "items" (array schemas)
    if let Some(items) = schema.get("items") {
        if schema_contains_field_type_inner(items, field_type, depth + 1) {
            return true;
        }
    }

    // Recurse into "oneOf", "anyOf", "allOf" (schema composition keywords)
    for keyword in &["oneOf", "anyOf", "allOf"] {
        if let Some(variants) = schema.get(*keyword).and_then(|v| v.as_array()) {
            for variant in variants {
                if schema_contains_field_type_inner(variant, field_type, depth + 1) {
                    return true;
                }
            }
        }
    }

    // Recurse into "additionalProperties" (if it's a schema object, not a boolean)
    if let Some(additional) = schema.get("additionalProperties") {
        if additional.is_object()
            && schema_contains_field_type_inner(additional, field_type, depth + 1)
        {
            return true;
        }
    }

    // SECURITY (R24-MCP-3): Detect $ref in schema — JSON Schema indirection
    // can bypass blocked field type detection by referencing a definition
    // that contains the sensitive type. Fail-closed: treat any $ref as
    // potentially containing the blocked type.
    if schema.get("$ref").is_some() {
        tracing::debug!(
            field_type = field_type,
            "$ref detected in elicitation schema — treating as suspicious"
        );
        return true;
    }

    false
}

/// Result of sampling inspection.
#[derive(Debug)]
pub enum SamplingVerdict {
    /// The sampling request is allowed.
    Allow,
    /// The sampling request is denied.
    Deny { reason: String },
}

/// Inspect a `sampling/createMessage` request against the configured policy.
///
/// Checks:
/// 1. Master toggle (`enabled`). Default is disabled (fail-closed).
/// 2. Model filter (`allowed_models`).
/// 3. Tool output in messages (`block_if_contains_tool_output`).
///
/// # Arguments
/// - `params`: The JSON-RPC params from the `sampling/createMessage` request.
/// - `config`: The sampling policy configuration.
pub fn inspect_sampling(
    params: &Value,
    config: &sentinel_config::SamplingConfig,
) -> SamplingVerdict {
    if !config.enabled {
        return SamplingVerdict::Deny {
            reason: "sampling is disabled".to_string(),
        };
    }

    // Check model filter.
    // MCP sampling uses modelPreferences.hints[].name for model selection.
    // Also check top-level "model" as a fallback for simpler implementations.
    if !config.allowed_models.is_empty() {
        let model_name = extract_model_name(params);
        match model_name {
            Some(model) => {
                if !config.allowed_models.iter().any(|a| a == &model) {
                    return SamplingVerdict::Deny {
                        reason: format!("model '{}' not in allowed list", model),
                    };
                }
            }
            None => {
                // SECURITY (R23-MCP-4): Fail-closed when allowed_models is
                // configured but the server omits the model field. Without
                // this, a malicious server can bypass model restrictions by
                // simply not specifying a model, letting the agent's default
                // (which may not be on the allowed list) be used instead.
                return SamplingVerdict::Deny {
                    reason: "no model specified but allowed_models is configured".to_string(),
                };
            }
        }
    }

    // Check for tool output in messages
    if config.block_if_contains_tool_output {
        if let Some(messages) = params.get("messages").and_then(|m| m.as_array()) {
            for msg in messages {
                if let Some(role) = msg.get("role").and_then(|r| r.as_str()) {
                    if role == "tool" {
                        return SamplingVerdict::Deny {
                            reason: "sampling request contains tool output".to_string(),
                        };
                    }
                }
                // Also check content for tool_result type blocks
                if let Some(content) = msg.get("content") {
                    if content_contains_tool_result(content) {
                        return SamplingVerdict::Deny {
                            reason: "sampling request contains tool result content".to_string(),
                        };
                    }
                }
            }
        }
    }

    SamplingVerdict::Allow
}

/// Extract the model name from sampling request params.
///
/// Checks:
/// - `modelPreferences.hints[0].name` (MCP spec)
/// - `modelPreferences.model` (simplified form)
/// - `model` (top-level fallback)
fn extract_model_name(params: &Value) -> Option<String> {
    // MCP spec: modelPreferences.hints[].name
    if let Some(prefs) = params.get("modelPreferences") {
        if let Some(hints) = prefs.get("hints").and_then(|h| h.as_array()) {
            if let Some(first_hint) = hints.first() {
                if let Some(name) = first_hint.get("name").and_then(|n| n.as_str()) {
                    return Some(name.to_string());
                }
            }
        }
        // Simplified form: modelPreferences.model
        if let Some(model) = prefs.get("model").and_then(|m| m.as_str()) {
            return Some(model.to_string());
        }
    }

    // Top-level fallback
    params
        .get("model")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
}

/// Check if content contains tool_result type blocks.
///
/// MCP content can be an array of content blocks, each with a `type` field.
/// We check for `type: "tool_result"` or `type: "tool_output"` blocks.
fn content_contains_tool_result(content: &Value) -> bool {
    match content {
        Value::Array(items) => items.iter().any(|item| {
            item.get("type")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t == "tool_result" || t == "tool_output")
        }),
        Value::Object(obj) => obj
            .get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t == "tool_result" || t == "tool_output"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_config::{ElicitationConfig, SamplingConfig};
    use serde_json::json;

    // ═══════════════════════════════════════════════════
    // ELICITATION TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_elicitation_blocked_by_default() {
        let config = ElicitationConfig::default();
        assert!(!config.enabled, "elicitation should be disabled by default");

        let params = json!({
            "message": "Enter your API key",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "api_key": {"type": "string"}
                }
            }
        });

        let verdict = inspect_elicitation(&params, &config, 0);
        match verdict {
            ElicitationVerdict::Deny { reason } => {
                assert!(
                    reason.contains("disabled"),
                    "Expected 'disabled' in reason, got: {}",
                    reason
                );
            }
            ElicitationVerdict::Allow => panic!("Expected Deny when elicitation is disabled"),
        }
    }

    #[test]
    fn test_elicitation_allowed_when_enabled() {
        let config = ElicitationConfig {
            enabled: true,
            blocked_field_types: Vec::new(),
            max_per_session: 5,
        };

        let params = json!({
            "message": "What color do you prefer?",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "color": {"type": "string"}
                }
            }
        });

        let verdict = inspect_elicitation(&params, &config, 0);
        assert!(
            matches!(verdict, ElicitationVerdict::Allow),
            "Expected Allow for benign elicitation, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_elicitation_blocked_field_type_password() {
        let config = ElicitationConfig {
            enabled: true,
            blocked_field_types: vec!["password".to_string(), "ssn".to_string()],
            max_per_session: 10,
        };

        // Schema with a "password" format field
        let params = json!({
            "message": "Enter credentials",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "secret": {"type": "string", "format": "password"}
                }
            }
        });

        let verdict = inspect_elicitation(&params, &config, 0);
        match verdict {
            ElicitationVerdict::Deny { reason } => {
                assert!(
                    reason.contains("password"),
                    "Expected 'password' in reason, got: {}",
                    reason
                );
            }
            ElicitationVerdict::Allow => {
                panic!("Expected Deny for schema with password format field")
            }
        }
    }

    #[test]
    fn test_elicitation_blocked_field_type_by_property_name() {
        let config = ElicitationConfig {
            enabled: true,
            blocked_field_types: vec!["password".to_string()],
            max_per_session: 10,
        };

        // Property named "password" — suspicious regardless of type
        let params = json!({
            "message": "Enter credentials",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "password": {"type": "string"}
                }
            }
        });

        let verdict = inspect_elicitation(&params, &config, 0);
        assert!(
            matches!(verdict, ElicitationVerdict::Deny { .. }),
            "Expected Deny for property named 'password', got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_elicitation_blocked_field_type_case_insensitive() {
        let config = ElicitationConfig {
            enabled: true,
            blocked_field_types: vec!["password".to_string()],
            max_per_session: 10,
        };

        let params = json!({
            "message": "Enter credentials",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "secret": {"type": "string", "format": "PASSWORD"}
                }
            }
        });

        let verdict = inspect_elicitation(&params, &config, 0);
        assert!(
            matches!(verdict, ElicitationVerdict::Deny { .. }),
            "Expected Deny for case-insensitive match, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_elicitation_rate_limited() {
        let config = ElicitationConfig {
            enabled: true,
            blocked_field_types: Vec::new(),
            max_per_session: 3,
        };

        let params = json!({
            "message": "Pick a number",
            "requestedSchema": {"type": "object"}
        });

        // Under limit: allowed
        let verdict = inspect_elicitation(&params, &config, 2);
        assert!(
            matches!(verdict, ElicitationVerdict::Allow),
            "Expected Allow when under limit, got: {:?}",
            verdict
        );

        // At limit: denied
        let verdict = inspect_elicitation(&params, &config, 3);
        match verdict {
            ElicitationVerdict::Deny { reason } => {
                assert!(
                    reason.contains("rate limit"),
                    "Expected 'rate limit' in reason, got: {}",
                    reason
                );
                assert!(
                    reason.contains("3/3"),
                    "Expected count in reason, got: {}",
                    reason
                );
            }
            ElicitationVerdict::Allow => panic!("Expected Deny when at rate limit"),
        }

        // Over limit: denied
        let verdict = inspect_elicitation(&params, &config, 10);
        assert!(
            matches!(verdict, ElicitationVerdict::Deny { .. }),
            "Expected Deny when over limit"
        );
    }

    #[test]
    fn test_elicitation_no_schema_allowed() {
        // If there's no schema in the request, and elicitation is enabled,
        // there are no field types to check, so it should be allowed.
        let config = ElicitationConfig {
            enabled: true,
            blocked_field_types: vec!["password".to_string()],
            max_per_session: 5,
        };

        let params = json!({
            "message": "Tell me something"
        });

        let verdict = inspect_elicitation(&params, &config, 0);
        assert!(
            matches!(verdict, ElicitationVerdict::Allow),
            "Expected Allow when no schema present, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_elicitation_nested_blocked_type() {
        let config = ElicitationConfig {
            enabled: true,
            blocked_field_types: vec!["ssn".to_string()],
            max_per_session: 10,
        };

        // Nested property with blocked name
        let params = json!({
            "message": "Enter info",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "identity": {
                        "type": "object",
                        "properties": {
                            "ssn": {"type": "string"}
                        }
                    }
                }
            }
        });

        let verdict = inspect_elicitation(&params, &config, 0);
        assert!(
            matches!(verdict, ElicitationVerdict::Deny { .. }),
            "Expected Deny for nested blocked field type, got: {:?}",
            verdict
        );
    }

    // ═══════════════════════════════════════════════════
    // SAMPLING TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_sampling_blocked_by_default() {
        let config = SamplingConfig::default();
        assert!(!config.enabled, "sampling should be disabled by default");

        let params = json!({
            "messages": [
                {"role": "user", "content": {"type": "text", "text": "Hello"}}
            ]
        });

        let verdict = inspect_sampling(&params, &config);
        match verdict {
            SamplingVerdict::Deny { reason } => {
                assert!(
                    reason.contains("disabled"),
                    "Expected 'disabled' in reason, got: {}",
                    reason
                );
            }
            SamplingVerdict::Allow => panic!("Expected Deny when sampling is disabled"),
        }
    }

    #[test]
    fn test_sampling_allowed_when_enabled() {
        let config = SamplingConfig {
            enabled: true,
            allowed_models: Vec::new(),
            block_if_contains_tool_output: false,
        };

        let params = json!({
            "messages": [
                {"role": "user", "content": {"type": "text", "text": "Summarize this"}}
            ],
            "maxTokens": 100
        });

        let verdict = inspect_sampling(&params, &config);
        assert!(
            matches!(verdict, SamplingVerdict::Allow),
            "Expected Allow for benign sampling, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_sampling_blocked_with_tool_output() {
        let config = SamplingConfig {
            enabled: true,
            allowed_models: Vec::new(),
            block_if_contains_tool_output: true,
        };

        // Message with role="tool"
        let params = json!({
            "messages": [
                {"role": "user", "content": {"type": "text", "text": "Summarize"}},
                {"role": "tool", "content": {"type": "text", "text": "AWS_SECRET_KEY=abc123"}}
            ]
        });

        let verdict = inspect_sampling(&params, &config);
        match verdict {
            SamplingVerdict::Deny { reason } => {
                assert!(
                    reason.contains("tool output"),
                    "Expected 'tool output' in reason, got: {}",
                    reason
                );
            }
            SamplingVerdict::Allow => panic!("Expected Deny when tool output is present"),
        }
    }

    #[test]
    fn test_sampling_blocked_with_tool_result_content() {
        let config = SamplingConfig {
            enabled: true,
            allowed_models: Vec::new(),
            block_if_contains_tool_output: true,
        };

        // Message with tool_result content block
        let params = json!({
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_result", "content": "sensitive data here"}
                    ]
                }
            ]
        });

        let verdict = inspect_sampling(&params, &config);
        match verdict {
            SamplingVerdict::Deny { reason } => {
                assert!(
                    reason.contains("tool result"),
                    "Expected 'tool result' in reason, got: {}",
                    reason
                );
            }
            SamplingVerdict::Allow => panic!("Expected Deny when tool_result content is present"),
        }
    }

    #[test]
    fn test_sampling_allowed_model_filter() {
        let config = SamplingConfig {
            enabled: true,
            allowed_models: vec!["claude-3-opus".to_string(), "claude-3-sonnet".to_string()],
            block_if_contains_tool_output: false,
        };

        // Allowed model via modelPreferences.hints
        let params = json!({
            "messages": [{"role": "user", "content": {"type": "text", "text": "Hi"}}],
            "modelPreferences": {
                "hints": [{"name": "claude-3-opus"}]
            }
        });

        let verdict = inspect_sampling(&params, &config);
        assert!(
            matches!(verdict, SamplingVerdict::Allow),
            "Expected Allow for allowed model, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_sampling_blocked_model_filter() {
        let config = SamplingConfig {
            enabled: true,
            allowed_models: vec!["claude-3-opus".to_string()],
            block_if_contains_tool_output: false,
        };

        // Disallowed model
        let params = json!({
            "messages": [{"role": "user", "content": {"type": "text", "text": "Hi"}}],
            "modelPreferences": {
                "hints": [{"name": "gpt-4"}]
            }
        });

        let verdict = inspect_sampling(&params, &config);
        match verdict {
            SamplingVerdict::Deny { reason } => {
                assert!(
                    reason.contains("gpt-4"),
                    "Expected model name in reason, got: {}",
                    reason
                );
                assert!(
                    reason.contains("not in allowed list"),
                    "Expected 'not in allowed list' in reason, got: {}",
                    reason
                );
            }
            SamplingVerdict::Allow => panic!("Expected Deny for disallowed model"),
        }
    }

    #[test]
    fn test_sampling_no_model_with_filter_denies() {
        // SECURITY (R23-MCP-4): If no model is specified but allowed_models
        // is non-empty, deny (fail-closed). A malicious server can bypass
        // model restrictions by simply omitting the model field.
        let config = SamplingConfig {
            enabled: true,
            allowed_models: vec!["claude-3-opus".to_string()],
            block_if_contains_tool_output: false,
        };

        let params = json!({
            "messages": [{"role": "user", "content": {"type": "text", "text": "Hi"}}]
        });

        let verdict = inspect_sampling(&params, &config);
        assert!(
            matches!(verdict, SamplingVerdict::Deny { .. }),
            "Expected Deny when no model specified but allowed_models configured, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_sampling_model_via_top_level_field() {
        let config = SamplingConfig {
            enabled: true,
            allowed_models: vec!["claude-3-opus".to_string()],
            block_if_contains_tool_output: false,
        };

        // Model specified at top level (simplified form)
        let params = json!({
            "messages": [{"role": "user", "content": {"type": "text", "text": "Hi"}}],
            "model": "gpt-4"
        });

        let verdict = inspect_sampling(&params, &config);
        assert!(
            matches!(verdict, SamplingVerdict::Deny { .. }),
            "Expected Deny for top-level disallowed model, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_sampling_tool_output_allowed_when_not_blocking() {
        let config = SamplingConfig {
            enabled: true,
            allowed_models: Vec::new(),
            block_if_contains_tool_output: false,
        };

        let params = json!({
            "messages": [
                {"role": "tool", "content": {"type": "text", "text": "tool output data"}}
            ]
        });

        let verdict = inspect_sampling(&params, &config);
        assert!(
            matches!(verdict, SamplingVerdict::Allow),
            "Expected Allow when block_if_contains_tool_output is false, got: {:?}",
            verdict
        );
    }

    // ═══════════════════════════════════════════════════
    // SCHEMA SCANNING EDGE CASES
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_schema_contains_field_type_in_array_items() {
        let config = ElicitationConfig {
            enabled: true,
            blocked_field_types: vec!["secret".to_string()],
            max_per_session: 10,
        };

        let params = json!({
            "message": "Enter secrets",
            "requestedSchema": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "secret": {"type": "string"}
                    }
                }
            }
        });

        let verdict = inspect_elicitation(&params, &config, 0);
        assert!(
            matches!(verdict, ElicitationVerdict::Deny { .. }),
            "Expected Deny for blocked field type in array items, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_schema_scan_depth_limit_fail_closed() {
        // R24-MCP-9: Build a deeply nested schema to test depth limiting.
        // The depth limit should fail-closed (return true = suspicious).
        let mut schema = json!({"type": "string", "format": "password"});
        for _ in 0..(MAX_SCHEMA_SCAN_DEPTH + 5) {
            schema = json!({
                "type": "object",
                "properties": {
                    "nested": schema
                }
            });
        }

        // Should flag as suspicious because depth limit exceeded (fail-closed)
        assert!(
            schema_contains_field_type(&schema, "password"),
            "Should flag deeply nested schemas as suspicious (fail-closed)"
        );
    }

    #[test]
    fn test_schema_ref_detected_as_suspicious() {
        // R24-MCP-3: $ref in schema can bypass blocked field type detection
        // by referencing a definition that contains the sensitive type.
        let schema = json!({
            "type": "object",
            "properties": {
                "auth": {"$ref": "#/definitions/credentials"}
            }
        });
        assert!(
            schema_contains_field_type(&schema, "password"),
            "Should detect $ref as potentially containing blocked type"
        );
    }

    #[test]
    fn test_schema_no_false_positive_without_ref() {
        // Normal schema without $ref should not trigger the $ref check
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            }
        });
        assert!(
            !schema_contains_field_type(&schema, "password"),
            "Normal schema should not be flagged as suspicious"
        );
    }

    // ── Adversarial Tests: Schema Composition Keyword Scanning ──

    #[test]
    fn test_schema_oneof_hidden_password() {
        // Attacker hides "password" type inside oneOf
        let schema = json!({
            "type": "object",
            "oneOf": [
                {"type": "string"},
                {"type": "object", "properties": {"secret": {"format": "password"}}}
            ]
        });
        assert!(
            schema_contains_field_type(&schema, "password"),
            "Should detect password hidden in oneOf"
        );
    }

    #[test]
    fn test_schema_anyof_hidden_credential() {
        let schema = json!({
            "anyOf": [
                {"type": "string"},
                {"type": "object", "properties": {"credential": {"type": "string"}}}
            ]
        });
        assert!(
            schema_contains_field_type(&schema, "credential"),
            "Should detect credential hidden in anyOf"
        );
    }

    #[test]
    fn test_schema_allof_hidden_api_key() {
        let schema = json!({
            "allOf": [
                {"type": "object", "properties": {"name": {"type": "string"}}},
                {"type": "object", "properties": {"api_key": {"type": "string"}}}
            ]
        });
        assert!(
            schema_contains_field_type(&schema, "api_key"),
            "Should detect api_key hidden in allOf"
        );
    }

    #[test]
    fn test_schema_additional_properties_hidden_token() {
        let schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "token": {"format": "password"}
                }
            }
        });
        assert!(
            schema_contains_field_type(&schema, "password"),
            "Should detect password in additionalProperties schema"
        );
        assert!(
            schema_contains_field_type(&schema, "token"),
            "Should detect token property name in additionalProperties"
        );
    }

    #[test]
    fn test_schema_additional_properties_boolean_ignored() {
        // additionalProperties: false (boolean) should not recurse
        let schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": false
        });
        assert!(
            !schema_contains_field_type(&schema, "password"),
            "Boolean additionalProperties should not cause false positives"
        );
    }

    #[test]
    fn test_schema_nested_oneof_in_anyof() {
        // Multi-level composition nesting
        let schema = json!({
            "anyOf": [
                {"oneOf": [
                    {"type": "string"},
                    {"format": "password"}
                ]}
            ]
        });
        assert!(
            schema_contains_field_type(&schema, "password"),
            "Should detect password in nested oneOf inside anyOf"
        );
    }
}
