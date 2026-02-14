//! Proves the exact evaluation order inside evaluate_conditions:
//!   1. JSON depth > 10 → EngineError::InvalidCondition
//!   2. JSON size > 100KB → EngineError::InvalidCondition
//!   3. require_approval == true → RequireApproval
//!   4. forbidden_parameters match → Deny
//!   5. required_parameters missing  Deny
//!   6. Fall-through → Allow
//!
//! Each test constructs conditions that would trigger multiple steps,
//! then verifies only the FIRST applicable step fires.

use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(params: serde_json::Value) -> Action {
    Action::new("tool".to_string(), "func".to_string(), params)
}

fn cond(conditions: serde_json::Value) -> Vec<Policy> {
    vec![Policy {
        id: "*".to_string(),
        name: "test-cond".to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }]
}

// ═════════════════════════════
// STEP 3 BEATS STEP 4: require_approval before forbidden
// ═════════════════════════════

/// Action has a forbidden parameter AND require_approval=true.
/// require_approval is checked first → RequireApproval, not Deny.
#[test]
fn require_approval_checked_before_forbidden_params() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"secret": "value"}));
    let policies = cond(json!({
        "require_approval": true,
        "forbidden_parameters": ["secret"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "require_approval should fire before forbidden_parameters, got {:?}",
        result
    );
}

// ═════════════════════════════
// STEP 3 BEATS STEP 5: require_approval before required
// ═════════════════════════════

/// Action is missing a required parameter AND require_approval=true.
/// require_approval fires first.
#[test]
fn require_approval_checked_before_required_params() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({})); // missing "token"
    let policies = cond(json!({
        "require_approval": true,
        "required_parameters": ["token"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::RequireApproval { .. }));
}

// ═════════════════════════════
// STEP 4 BEATS STEP 5: forbidden before required
// ═════════════════════════════

/// Action has a forbidden param AND is missing a required param.
/// forbidden_parameters is checked before required_parameters.
#[test]
fn forbidden_checked_before_required() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"danger": true})); // has forbidden, missing "token"
    let policies = cond(json!({
        "forbidden_parameters": ["danger"],
        "required_parameters": ["token"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("forbidden"),
                "Should be denied for forbidden param, got: {}",
                reason
            );
        }
        other => panic!("Expected Deny for forbidden param, got {:?}", other),
    }
}

// ═════════════════════════════
// STEP 5: required param missing  Deny
// ═════════════════════════════

#[test]
fn missing_required_param_denies() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"other": "stuff"}));
    let policies = cond(json!({
        "required_parameters": ["token"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("token"),
                "Reason should mention 'token', got: {}",
                reason
            );
        }
        other => panic!("Expected Deny for missing required param, got {:?}", other),
    }
}

// ═════════════════════════════
// STEP 6: all conditions pass → Allow
// ═════════════════════════════

#[test]
fn all_conditions_satisfied_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"token": "abc123"}));
    let policies = cond(json!({
        "require_approval": false,
        "forbidden_parameters": ["danger"],
        "required_parameters": ["token"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(result, Verdict::Allow);
}

// ═════════════════════════════
// EMPTY CONDITIONS → Allow (step 6)
// ═════════════════════════════

#[test]
fn empty_conditions_object_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({}));
    let policies = cond(json!({}));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(result, Verdict::Allow);
}

// ═════════════════════════════
// REQUIRE_APPROVAL EXPLICITLY FALSE → skipped
// ═════════════════════════════

#[test]
fn require_approval_false_does_not_trigger() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({}));
    let policies = cond(json!({
        "require_approval": false
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "require_approval=false should not trigger RequireApproval"
    );
}

// ═════════════════════════════
// REQUIRE_APPROVAL NON-BOOLEAN → skipped (unwrap_or(false))
// ═════════════════════════════

#[test]
fn require_approval_string_value_does_not_trigger() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({}));
    // "true" as a string, not a boolean — as_bool() returns None, unwrap_or(false)
    let policies = cond(json!({
        "require_approval": "true"
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "String 'true' is not bool true, should fall through to Allow"
    );
}

#[test]
fn require_approval_integer_one_does_not_trigger() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({}));
    // 1 as integer  as_bool() returns None for integers
    let policies = cond(json!({
        "require_approval": 1
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Integer 1 is not bool true, should fall through"
    );
}

// ═════════════════════════════
// FORBIDDEN_PARAMETERS NON-ARRAY → silently skipped
// ════════════════════════════

#[test]
fn forbidden_parameters_as_string_is_ignored() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"danger": true}));
    // forbidden_parameters is a string, not array — as_array() returns None
    let policies = cond(json!({
        "forbidden_parameters": "danger"
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Non-array forbidden_parameters should be silently skipped"
    );
}

// ═════════════════════════════
// REQUIRED_PARAMETERS NON-ARRAY → silently skipped
// ═════════════════════════════

#[test]
fn required_parameters_as_object_is_ignored() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({})); // missing everything
                                         // required_parameters is an object, not array
    let policies = cond(json!({
        "required_parameters": {"key": "token"}
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Non-array required_parameters should be silently skipped"
    );
}

// ═════════════════════════════
// FORBIDDEN_PARAMETERS WITH NON-STRING ITEMS → silently skipped
// ═════════════════════════════

#[test]
fn forbidden_parameters_with_integer_items_skipped() {
    let engine = PolicyEngine::new(false);
    // Action has key "123" but forbidden list contains integer 123 (not string)
    let action = make_action(json!({"123": "value"}));
    let policies = cond(json!({
        "forbidden_parameters": [123, true, null]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Non-string items in forbidden array should be skipped"
    );
}
