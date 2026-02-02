//! Adversarial tests for MCP-style request/response flows.
//! Exercises JSON deserialization edge cases that would hit the MCP server.
//! Tests are done through the engine+types layer (sentinel-integration
//! doesn't directly depend on sentinel-mcp).

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

// ════════════════════════════════════════════
// DESERIALIZATION OF MALFORMED MCP-STYLE PAYLOADS
// ═══════════════════════════════════════════

#[test]
fn action_missing_tool_field_fails_deserialization() {
    let bad_json = json!({"function": "exec", "parameters": {}});
    let result: Result<Action, _> = serde_json::from_value(bad_json);
    assert!(
        result.is_err(),
        "Missing 'tool' should fail deserialization"
    );
}

#[test]
fn action_missing_function_field_fails_deserialization() {
    let bad_json = json!({"tool": "bash", "parameters": {}});
    let result: Result<Action, _> = serde_json::from_value(bad_json);
    assert!(
        result.is_err(),
        "Missing 'function' should fail deserialization"
    );
}

#[test]
fn action_missing_parameters_field_fails_deserialization() {
    let bad_json = json!({"tool": "bash", "function": "exec"});
    let result: Result<Action, _> = serde_json::from_value(bad_json);
    assert!(
        result.is_err(),
        "Missing 'parameters' should fail deserialization"
    );
}

#[test]
fn action_with_extra_fields_still_deserializes() {
    let json_with_extra = json!({
        "tool": "bash",
        "function": "exec",
        "parameters": {},
        "extra_field": "ignored",
        "another": 42
    });
    let result: Result<Action, _> = serde_json::from_value(json_with_extra);
    // serde by default ignores unknown fields (unless deny_unknown_fields)
    assert!(
        result.is_ok(),
        "Extra fields should be silently ignored by default"
    );
}

#[test]
fn policy_missing_id_fails_deserialization() {
    let bad_json = json!({
        "name": "test",
        "policy_type": "Allow",
        "priority": 1
    });
    let result: Result<Policy, _> = serde_json::from_value(bad_json);
    assert!(result.is_err());
}

#[test]
fn policy_missing_priority_fails_deserialization() {
    let bad_json = json!({
        "id": "test",
        "name": "test",
        "policy_type": "Allow"
    });
    let result: Result<Policy, _> = serde_json::from_value(bad_json);
    assert!(result.is_err());
}

#[test]
fn policy_with_invalid_policy_type_fails() {
    let bad_json = json!({
        "id": "test",
        "name": "test",
        "policy_type": "InvalidType",
        "priority": 1
    });
    let result: Result<Policy, _> = serde_json::from_value(bad_json);
    assert!(result.is_err(), "Unknown policy_type variant should fail");
}

#[test]
fn verdict_allow_roundtrips_through_json() {
    let v = Verdict::Allow;
    let json_str = serde_json::to_string(&v).unwrap();
    let back: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_deny_roundtrips_through_json() {
    let v = Verdict::Deny {
        reason: "test reason".to_string(),
    };
    let json_str = serde_json::to_string(&v).unwrap();
    let back: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_deny_with_empty_reason_roundtrips() {
    let v = Verdict::Deny {
        reason: String::new(),
    };
    let json_str = serde_json::to_string(&v).unwrap();
    let back: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_require_approval_roundtrips() {
    let v = Verdict::RequireApproval {
        reason: "needs human".to_string(),
    };
    let json_str = serde_json::to_string(&v).unwrap();
    let back: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, back);
}

// ════════════════════════════════════════════
// UNICODE AND SPECIAL CHARACTERS IN MCP PAYLOADS
// ═══════════════════════════════════════════

#[test]
fn action_with_unicode_tool_name_works() {
    let action_json = json!({
        "tool": "工具_🔧",
        "function": "行",
        "parameters": {"パス": "/tmp/テスト"}
    });
    let action: Action = serde_json::from_value(action_json).unwrap();

    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "allow-all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
    }];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(result, Verdict::Allow);
}

#[test]
fn action_with_very_long_tool_name_evaluates() {
    let long_name = "a".repeat(10_000);
    let action = Action {
        tool: long_name.clone(),
        function: "func".to_string(),
        parameters: json!({}),
    };

    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "wildcard".to_string(),
        policy_type: PolicyType::Deny,
        priority: 1,
    }];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

#[test]
fn policy_id_with_multiple_colons_only_splits_on_first() {
    // "a:b:c" → split_once(':') → tool="a", function="b:c"
    let engine = PolicyEngine::new(false);
    let action = Action {
        tool: "a".to_string(),
        function: "b:c".to_string(),
        parameters: json!({}),
    };
    let policies = vec![Policy {
        id: "a:b:c".to_string(),
        name: "multi-colon".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
    }];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "split_once should match tool=a, func=b:c"
    );
}

#[test]
fn policy_id_with_empty_function_after_colon() {
    // "bash:"  tool="bash", function=""
    let engine = PolicyEngine::new(false);
    let action = Action {
        tool: "bash".to_string(),
        function: String::new(),
        parameters: json!({}),
    };
    let policies = vec![Policy {
        id: "bash:".to_string(),
        name: "empty-func".to_string(),
        policy_type: PolicyType::Deny,
        priority: 10,
    }];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "bash: should match tool=bash, func=\"\" exactly"
    );
}

#[test]
fn policy_id_with_empty_tool_before_colon() {
    // ":execute" → tool="", function="execute"
    let engine = PolicyEngine::new(false);
    let action = Action {
        tool: String::new(),
        function: "execute".to_string(),
        parameters: json!({}),
    };
    let policies = vec![Policy {
        id: ":execute".to_string(),
        name: "empty-tool".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
    }];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        ":execute should match tool=\"\", func=execute"
    );
}
