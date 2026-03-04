// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Boundary and serialization tests for vellaveto-types.
//! Exercises edge cases in Action, Policy, Verdict, and PolicyType
//! serialization/deserialization to find breakage.

use serde_json::json;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

// ═════════════════════════════════════════════════
// ACTION SERIALIZATION ROUNDTRIPS
// ════════════════════════════════════════════════

#[test]
fn action_with_null_parameters_roundtrips() {
    let action = Action::new("t".to_string(), "f".to_string(), json!(null));
    let serialized = serde_json::to_string(&action).unwrap();
    let deserialized: Action = serde_json::from_str(&serialized).unwrap();
    assert_eq!(action, deserialized);
}

#[test]
fn action_with_array_parameters_roundtrips() {
    let action = Action::new(
        "t".to_string(),
        "f".to_string(),
        json!([1, "two", null, true, 3.15]),
    );
    let serialized = serde_json::to_string(&action).unwrap();
    let deserialized: Action = serde_json::from_str(&serialized).unwrap();
    assert_eq!(action, deserialized);
}

#[test]
fn action_with_empty_strings_roundtrips() {
    let action = Action::new(String::new(), String::new(), json!({}));
    let serialized = serde_json::to_string(&action).unwrap();
    let deserialized: Action = serde_json::from_str(&serialized).unwrap();
    assert_eq!(action, deserialized);
}

#[test]
fn action_with_deeply_nested_params_roundtrips() {
    let mut val = json!(42);
    for _ in 0..15 {
        val = json!({"inner": val});
    }
    let action = Action::new("t".to_string(), "f".to_string(), val.clone());
    let serialized = serde_json::to_string(&action).unwrap();
    let deserialized: Action = serde_json::from_str(&serialized).unwrap();
    assert_eq!(action, deserialized);
}

#[test]
fn action_with_unicode_roundtrips() {
    let action = Action::new(
        "工具".to_string(),
        "함수".to_string(),
        json!({"путь": "значение", "🔑": "🔒"}),
    );
    let serialized = serde_json::to_string(&action).unwrap();
    let deserialized: Action = serde_json::from_str(&serialized).unwrap();
    assert_eq!(action, deserialized);
}

// ═════════════════════════════════════════════════
// VERDICT SERIALIZATION
// ═════════════════════════════════════════════════

#[test]
fn verdict_allow_roundtrips() {
    let v = Verdict::Allow;
    let s = serde_json::to_string(&v).unwrap();
    let d: Verdict = serde_json::from_str(&s).unwrap();
    assert_eq!(v, d);
}

#[test]
fn verdict_deny_with_empty_reason_roundtrips() {
    let v = Verdict::Deny {
        reason: String::new(),
    };
    let s = serde_json::to_string(&v).unwrap();
    let d: Verdict = serde_json::from_str(&s).unwrap();
    assert_eq!(v, d);
}

#[test]
fn verdict_deny_with_long_reason_roundtrips() {
    let v = Verdict::Deny {
        reason: "x".repeat(10_000),
    };
    let s = serde_json::to_string(&v).unwrap();
    let d: Verdict = serde_json::from_str(&s).unwrap();
    assert_eq!(v, d);
}

#[test]
fn verdict_deny_with_special_chars_roundtrips() {
    let v = Verdict::Deny {
        reason: "has \"quotes\" and \\backslashes\\ and\nnewlines\tand\ttabs".to_string(),
    };
    let s = serde_json::to_string(&v).unwrap();
    let d: Verdict = serde_json::from_str(&s).unwrap();
    assert_eq!(v, d);
}

#[test]
fn verdict_require_approval_roundtrips() {
    let v = Verdict::RequireApproval {
        reason: "needs manager sign-off".to_string(),
    };
    let s = serde_json::to_string(&v).unwrap();
    let d: Verdict = serde_json::from_str(&s).unwrap();
    assert_eq!(v, d);
}

// ═════════════════════════════════════════════════
// POLICY TYPE SERIALIZATION
// ════════════════════════════════════════════════

#[test]
fn policy_type_allow_roundtrips() {
    let pt = PolicyType::Allow;
    let s = serde_json::to_string(&pt).unwrap();
    let d: PolicyType = serde_json::from_str(&s).unwrap();
    assert_eq!(pt, d);
}

#[test]
fn policy_type_deny_roundtrips() {
    let pt = PolicyType::Deny;
    let s = serde_json::to_string(&pt).unwrap();
    let d: PolicyType = serde_json::from_str(&s).unwrap();
    assert_eq!(pt, d);
}

#[test]
fn policy_type_conditional_complex_roundtrips() {
    let pt = PolicyType::Conditional {
        conditions: json!({
            "forbidden_parameters": ["rm", "delete", "format"],
            "required_parameters": ["auth"],
            "require_approval": false,
            "nested": {
                "list": [1, 2, 3],
                "flag": true
            }
        }),
    };
    let s = serde_json::to_string(&pt).unwrap();
    let d: PolicyType = serde_json::from_str(&s).unwrap();
    assert_eq!(pt, d);
}

// ═════════════════════════════════════════════════
// POLICY SERIALIZATION
// ════════════════════════════════════════════════

#[test]
fn policy_with_negative_priority_roundtrips() {
    let p = Policy {
        id: "test".to_string(),
        name: "Negative Priority".to_string(),
        policy_type: PolicyType::Allow,
        priority: -999,
        path_rules: None,
        network_rules: None,
    };
    let s = serde_json::to_string(&p).unwrap();
    let d: Policy = serde_json::from_str(&s).unwrap();
    assert_eq!(d.priority, -999);
    assert_eq!(d.id, "test");
}

#[test]
fn policy_with_i32_extremes_roundtrips() {
    for priority in [i32::MIN, i32::MAX, 0, -1, 1] {
        let p = Policy {
            id: format!("pri_{priority}"),
            name: format!("Priority {priority}"),
            policy_type: PolicyType::Deny,
            priority,
            path_rules: None,
            network_rules: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        let d: Policy = serde_json::from_str(&s).unwrap();
        assert_eq!(d.priority, priority, "Priority {priority} should roundtrip");
    }
}

// ═════════════════════════════════════════════════
// DESERIALIZATION FROM INVALID JSON
// ════════════════════════════════════════════════

#[test]
fn action_missing_tool_field_fails() {
    let bad = json!({"function": "f", "parameters": {}});
    let result: Result<Action, _> = serde_json::from_value(bad);
    assert!(result.is_err(), "Action without 'tool' field should fail");
}

#[test]
fn action_missing_function_field_fails() {
    let bad = json!({"tool": "t", "parameters": {}});
    let result: Result<Action, _> = serde_json::from_value(bad);
    assert!(
        result.is_err(),
        "Action without 'function' field should fail"
    );
}

#[test]
fn action_missing_parameters_field_fails() {
    let bad = json!({"tool": "t", "function": "f"});
    let result: Result<Action, _> = serde_json::from_value(bad);
    assert!(
        result.is_err(),
        "Action without 'parameters' field should fail"
    );
}

#[test]
fn policy_missing_id_fails() {
    let bad = json!({"name": "n", "policy_type": "Allow", "priority": 1});
    let result: Result<Policy, _> = serde_json::from_value(bad);
    assert!(result.is_err());
}

#[test]
fn policy_with_wrong_priority_type_fails() {
    let bad = json!({"id": "x", "name": "n", "policy_type": "Allow", "priority": "high"});
    let result: Result<Policy, _> = serde_json::from_value(bad);
    assert!(
        result.is_err(),
        "String priority should fail deserialization"
    );
}

#[test]
fn verdict_unknown_variant_fails() {
    let bad = json!("Unknown");
    let result: Result<Verdict, _> = serde_json::from_value(bad);
    assert!(result.is_err(), "Unknown verdict variant should fail");
}

#[test]
fn policy_type_unknown_variant_fails() {
    let bad = json!("Block");
    let result: Result<PolicyType, _> = serde_json::from_value(bad);
    assert!(result.is_err(), "Unknown policy type 'Block' should fail");
}

// ════════════════════════════════════════════════
// CROSS-TYPE: Engine accepts deserialized JSON policies
// ════════════════════════════════════════════════

#[test]
fn engine_evaluates_json_deserialized_policy_and_action() {
    let engine = vellaveto_engine::PolicyEngine::new(false);

    let policy_json = json!({
        "id": "*",
        "name": "Allow everything",
        "policy_type": "Allow",
        "priority": 1
    });
    let policy: Policy = serde_json::from_value(policy_json).unwrap();

    let action_json = json!({
        "tool": "anything",
        "function": "whatever",
        "parameters": {"key": "val"}
    });
    let action: Action = serde_json::from_value(action_json).unwrap();

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn engine_evaluates_conditional_from_json() {
    let engine = vellaveto_engine::PolicyEngine::new(false);

    let policy_json = json!({
        "id": "net:*",
        "name": "Network approval",
        "policy_type": {
            "Conditional": {
                "conditions": {
                    "require_approval": true
                }
            }
        },
        "priority": 50
    });
    let policy: Policy = serde_json::from_value(policy_json).unwrap();

    let action = Action::new("net".to_string(), "fetch".to_string(), json!({}));

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    match verdict {
        Verdict::RequireApproval { .. } => {}
        other => panic!("Expected RequireApproval, got {other:?}"),
    }
}
