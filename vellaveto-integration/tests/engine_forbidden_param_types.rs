// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests for forbidden_parameters matching against various JSON value types
//! in action parameters. The engine checks `action.parameters.get(param_str).is_some()`
//! which only checks KEY presence, not value type. These tests verify that.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action_with_params(params: serde_json::Value) -> Action {
    Action::new("tool".to_string(), "func".to_string(), params)
}

fn conditional_policy(conditions: serde_json::Value) -> Policy {
    Policy {
        id: "*".to_string(),
        name: "cond-test".to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

// ════════════════════════════════
// FORBIDDEN PARAM PRESENT WITH VARIOUS VALUE TYPES
// ════════════════════════════════

/// Forbidden param with null value — key exists, value is null.
#[test]
fn forbidden_param_with_null_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": null}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Forbidden param with null value should still be denied (key exists)"
    );
}

/// Forbidden param with boolean value.
#[test]
fn forbidden_param_with_boolean_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": false}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Forbidden param with boolean value should be denied (key exists)"
    );
}

/// Forbidden param with numeric value.
#[test]
fn forbidden_param_with_numeric_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": 42}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Forbidden param with numeric value should be denied (key exists)"
    );
}

/// Forbidden param with array value.
#[test]
fn forbidden_param_with_array_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": [1, 2, 3]}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Forbidden param with array value should be denied (key exists)"
    );
}

/// Forbidden param with object value.
#[test]
fn forbidden_param_with_object_value_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": {"nested": true}}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Forbidden param with object value should be denied (key exists)"
    );
}

/// Forbidden param with empty string value.
#[test]
fn forbidden_param_with_empty_string_is_denied() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"danger": ""}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Forbidden param with empty string value should be denied (key exists)"
    );
}

// ════════════════════════════════
// FORBIDDEN PARAM ABSENT
// ═══════════════════════════════

/// Forbidden param not in action params at all → Allow.
#[test]
fn forbidden_param_absent_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"safe": "value"}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Absent forbidden param should allow: got {result:?}"
    );
}

/// Action parameters is null (not an object) — get() returns None  Allow.
#[test]
fn forbidden_param_with_null_params_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!(null));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Null params should not match forbidden param: got {result:?}"
    );
}

/// Action parameters is an array — get("danger") on array returns None → Allow.
#[test]
fn forbidden_param_with_array_params_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!([1, 2, 3]));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Array params should not match forbidden param key: got {result:?}"
    );
}

// ═══════════════════════════════════
// MULTIPLE FORBIDDEN PARAMS: PARTIAL MATCH
// ═══════════════════════════════════

/// Two forbidden params, only one present → Deny (any match triggers).
#[test]
fn one_of_two_forbidden_params_present_denies() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"safe": "ok", "secret": "oops"}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger", "secret"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Should deny when any forbidden param is present"
    );
}

/// Two forbidden params, neither present → Allow.
#[test]
fn neither_forbidden_param_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(json!({"safe": "ok", "also_safe": true}));
    let policies = vec![conditional_policy(json!({
        "forbidden_parameters": ["danger", "secret"]
    }))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Should allow when no forbidden param is present: got {result:?}"
    );
}
