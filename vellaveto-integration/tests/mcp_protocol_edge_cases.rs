//! MCP protocol edge case tests exercised through the engine+types layer.
//! Tests deserialization edge cases for request/response JSON shapes
//! that would hit the MCP server. Since vellaveto-integration doesn't
//! depend on vellaveto-mcp, we test the shared type boundaries.

use serde_json::json;
use vellaveto_types::{Action, Policy, Verdict};

// ═══════════════════════════════════════════
// MALFORMED ACTION JSON
// ═══════════════════════════════════════════

#[test]
fn action_with_integer_tool_fails() {
    let bad = json!({"tool": 42, "function": "exec", "parameters": {}});
    assert!(serde_json::from_value::<Action>(bad).is_err());
}

#[test]
fn action_with_null_tool_fails() {
    let bad = json!({"tool": null, "function": "exec", "parameters": {}});
    assert!(serde_json::from_value::<Action>(bad).is_err());
}

#[test]
fn action_with_boolean_function_fails() {
    let bad = json!({"tool": "bash", "function": true, "parameters": {}});
    assert!(serde_json::from_value::<Action>(bad).is_err());
}

#[test]
fn action_with_string_parameters_fails() {
    // parameters must be a JSON value, but a string IS a valid JSON value
    // So this should actually succeed — string is valid serde_json::Value
    let val = json!({"tool": "bash", "function": "exec", "parameters": "string_params"});
    let result = serde_json::from_value::<Action>(val);
    assert!(
        result.is_ok(),
        "String is a valid serde_json::Value for parameters"
    );
    assert_eq!(result.unwrap().parameters, json!("string_params"));
}

#[test]
fn action_with_completely_wrong_shape() {
    let bad = json!("just a string");
    assert!(serde_json::from_value::<Action>(bad).is_err());

    let bad = json!(42);
    assert!(serde_json::from_value::<Action>(bad).is_err());

    let bad = json!(null);
    assert!(serde_json::from_value::<Action>(bad).is_err());

    let bad = json!([1, 2, 3]);
    assert!(serde_json::from_value::<Action>(bad).is_err());
}

// ══════════════════════════════════════════
// MALFORMED POLICY JSON
// ════════════════════════════════════════════

#[test]
fn policy_with_float_priority_fails() {
    let bad = json!({
        "id": "*", "name": "test",
        "policy_type": "Allow",
        "priority": 10.5
    });
    // serde_json should fail since priority is i32 and 10.5 is not an integer
    assert!(serde_json::from_value::<Policy>(bad).is_err());
}

#[test]
fn policy_with_string_priority_fails() {
    let bad = json!({
        "id": "*", "name": "test",
        "policy_type": "Allow",
        "priority": "high"
    });
    assert!(serde_json::from_value::<Policy>(bad).is_err());
}

#[test]
fn policy_with_null_priority_fails() {
    let bad = json!({
        "id": "*", "name": "test",
        "policy_type": "Allow",
        "priority": null
    });
    assert!(serde_json::from_value::<Policy>(bad).is_err());
}

#[test]
fn policy_with_unknown_policy_type_fails() {
    let bad = json!({
        "id": "*", "name": "test",
        "policy_type": "Reject",
        "priority": 10
    });
    assert!(serde_json::from_value::<Policy>(bad).is_err());
}

#[test]
fn policy_with_conditional_missing_conditions_fails() {
    let bad = json!({
        "id": "*", "name": "test",
        "policy_type": {"Conditional": {}},
        "priority": 10
    });
    assert!(serde_json::from_value::<Policy>(bad).is_err());
}

// ═══════════════════════════════════════════
// MALFORMED VERDICT JSON
// ═══════════════════════════════════════════

#[test]
fn verdict_deny_without_reason_fails() {
    let bad = json!({"Deny": {}});
    assert!(serde_json::from_value::<Verdict>(bad).is_err());
}

#[test]
fn verdict_require_approval_without_reason_fails() {
    let bad = json!({"RequireApproval": {}});
    assert!(serde_json::from_value::<Verdict>(bad).is_err());
}

#[test]
fn verdict_unknown_variant_fails() {
    let bad = json!("Block");
    assert!(serde_json::from_value::<Verdict>(bad).is_err());
}

#[test]
fn verdict_empty_object_fails() {
    let bad = json!({});
    assert!(serde_json::from_value::<Verdict>(bad).is_err());
}

// ═══════════════════════════════════════════
// HUGE PAYLOAD HANDLING
// ═══════════════════════════════════════════

/// A very large action (huge parameters) can still be deserialized.
/// The engine's condition evaluation has size limits, but deserialization
/// itself should work for any valid JSON.
#[test]
fn large_action_deserializes_successfully() {
    let large_params: serde_json::Value = {
        let mut map = serde_json::Map::new();
        for i in 0..1000 {
            map.insert(
                format!("key_{}", i),
                json!(format!("value_{}", "x".repeat(100))),
            );
        }
        serde_json::Value::Object(map)
    };

    let action_json = json!({
        "tool": "bulk",
        "function": "process",
        "parameters": large_params
    });

    let action: Action = serde_json::from_value(action_json).unwrap();
    assert_eq!(action.tool, "bulk");
}

/// Large number of policies can be deserialized.
#[test]
fn many_policies_deserialize() {
    let policies_json: Vec<serde_json::Value> = (0..500)
        .map(|i| {
            json!({
                "id": format!("tool_{}:func_{}", i, i),
                "name": format!("Policy {}", i),
                "policy_type": if i % 2 == 0 { json!("Allow") } else { json!("Deny") },
                "priority": i
            })
        })
        .collect();

    let val = serde_json::Value::Array(policies_json);
    let policies: Vec<Policy> = serde_json::from_value(val).unwrap();
    assert_eq!(policies.len(), 500);
}

// ═══════════════════════════════════════════
// MCP-STYLE REQUEST SHAPE VALIDATION
// ═══════════════════════════════════════════

/// Simulate an MCP request JSON and verify that the embedded action
/// and policy types deserialize correctly when extracted from the
/// request envelope.
#[test]
fn mcp_request_envelope_extraction() {
    let request = json!({
        "id": "req-001",
        "method": "evaluate_action",
        "params": {
            "tool": "bash",
            "function": "execute",
            "parameters": {"cmd": "ls -la"}
        }
    });

    // Extract params and deserialize as Action (what MCP server does)
    let params = request.get("params").unwrap().clone();
    let action: Action = serde_json::from_value(params).unwrap();
    assert_eq!(action.tool, "bash");
    assert_eq!(action.function, "execute");
}

#[test]
fn mcp_add_policy_envelope_extraction() {
    let request = json!({
        "id": "req-002",
        "method": "add_policy",
        "params": {
            "id": "file:*",
            "name": "Allow file ops",
            "policy_type": "Allow",
            "priority": 10
        }
    });

    let params = request.get("params").unwrap().clone();
    let policy: Policy = serde_json::from_value(params).unwrap();
    assert_eq!(policy.id, "file:*");
    assert_eq!(policy.priority, 10);
}

#[test]
fn mcp_remove_policy_envelope_extraction() {
    let request = json!({
        "id": "req-003",
        "method": "remove_policy",
        "params": "bash:*"
    });

    let params = request.get("params").unwrap().clone();
    let policy_id: String = serde_json::from_value(params).unwrap();
    assert_eq!(policy_id, "bash:*");
}

/// Simulate the MCP response shape for a verdict.
#[test]
fn mcp_response_verdict_shape() {
    // Simulate engine producing a verdict and MCP serializing it
    let verdict = Verdict::RequireApproval {
        reason: "Dangerous operation".to_string(),
    };

    let response = json!({
        "id": "req-001",
        "result": serde_json::to_value(&verdict).unwrap(),
        "error": null
    });

    // Client-side: extract and deserialize the verdict
    let result = response.get("result").unwrap().clone();
    let deserialized: Verdict = serde_json::from_value(result).unwrap();
    assert_eq!(deserialized, verdict);
}

/// MCP response with error shape.
#[test]
fn mcp_error_response_shape() {
    let response = json!({
        "id": "req-bad",
        "result": null,
        "error": {
            "code": -32601,
            "message": "Method not found: bad_method"
        }
    });

    assert!(response.get("error").unwrap().is_object());
    let error = response.get("error").unwrap();
    assert_eq!(error.get("code").unwrap().as_i64().unwrap(), -32601);
}
