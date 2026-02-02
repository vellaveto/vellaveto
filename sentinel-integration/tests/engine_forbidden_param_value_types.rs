//! Tests for forbidden_parameters matching against various JSON value types
//! in action parameters. The engine checks `action.parameters.get(param_str).is_some()`
//! which only checks KEY presence, not value type. These tests verify that.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action_with_params(params: serde_json::Value) -> Action {
    Action {
        tool: "tool".to_string(),
        function: "func".to_string(),
        parameters: params,
    }
}

fn forbidden_policy(forbidden: Vec<&str>) -> Vec<Policy> {
    vec![Policy {
        id: "*".to_string(),
        name: "forbidden-check".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": forbidden}),
        },
        priority: 100,
    }]
}

// ═══════════════════════════════
// FORBIDDEN PARAM WITH VARIOUS VALUE TYPES
// ═══════════════════════════════

/// Forbidden param with null value — key exists, value is null.
#[test]
fn forbidden_param_null_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": null}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }),
        "Key 'danger' exists even though value is null — should be denied");
}

/// Forbidden param with boolean false value.
#[test]
fn forbidden_param_false_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": false}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Forbidden param with zero value.
#[test]
fn forbidden_param_zero_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": 0}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Forbidden param with empty string value.
#[test]
fn forbidden_param_empty_string_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": ""}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Forbidden param with empty array value.
#[test]
fn forbidden_param_empty_array_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": []}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Forbidden param with empty object value.
#[test]
fn forbidden_param_empty_object_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": {}}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Forbidden param with complex nested value.
#[test]
fn forbidden_param_complex_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": {"nested": [1, 2, {"deep": true}]}}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ════════════════════════════════
// FORBIDDEN PARAM NOT PRESENT — SHOULD ALLOW
// ════════════════════════════════

/// Action has different keys, forbidden param is absent.
#[test]
fn forbidden_param_absent_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"safe": "value", "also_safe": 42}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// Action parameters is an empty object — no keys to match.
#[test]
fn forbidden_param_empty_params_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({}));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// Action parameters is null — .get() on null Value returns None.
#[test]
fn forbidden_param_null_params_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!(null));
    let policies = forbidden_policy(vec!["danger"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

// ════════════════════════════════
// MULTIPLE FORBIDDEN PARAMS — FIRST MATCH WINS
// ════════════════════════════════

/// Multiple forbidden params, only the second one is present.
#[test]
fn second_forbidden_param_present_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"safe": 1, "secret": "val"}));
    let policies = forbidden_policy(vec!["danger", "secret", "other"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(reason.contains("secret"), "Denial reason should name 'secret', got: {}", reason);
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

/// Multiple forbidden params, all present  first one in the list triggers denial.
#[test]
fn first_forbidden_param_in_list_triggers_denial() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"alpha": 1, "beta": 2, "gamma": 3}));
    let policies = forbidden_policy(vec!["alpha", "beta", "gamma"]);
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            // The engine iterates forbidden params in order, so "alpha" should trigger first
            assert!(reason.contains("alpha"), "First forbidden param should trigger, got: {}", reason);
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}