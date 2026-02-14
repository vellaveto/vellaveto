//! Tests the precedence of condition checks within conditional policies.
//! The engine evaluates conditions in this order:
//!   1. require_approval (if true, returns RequireApproval immediately)
//!   2. forbidden_parameters (if any match, returns Deny)
//!   3. required_parameters (if any missing, returns Deny)
//!   4. Default: Allow
//!
//! This means if require_approval is true, forbidden/required params are NEVER checked.
//! These tests document and verify this precedence.

use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn conditional_policy(id: &str, priority: i32, conditions: serde_json::Value) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("cond-{}", id),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ══════════════════════════════════════
// REQUIRE_APPROVAL SHORT-CIRCUITS
// ═══════════════════════════════════════

/// require_approval=true AND forbidden param present:
/// require_approval wins, forbidden param is never checked.
#[test]
fn require_approval_beats_forbidden_param() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({"dangerous": true}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "require_approval": true,
            "forbidden_parameters": ["dangerous"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::RequireApproval { .. }),
        "require_approval should short-circuit before forbidden_parameters check"
    );
}

/// require_approval=true AND required param missing:
/// require_approval wins, required param is never checked.
#[test]
fn require_approval_beats_missing_required_param() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({})); // missing "auth_token"
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "require_approval": true,
            "required_parameters": ["auth_token"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::RequireApproval { .. }),
        "require_approval should short-circuit before required_parameters check"
    );
}

/// require_approval=false should NOT short-circuit.
/// Forbidden params should then be evaluated.
#[test]
fn require_approval_false_does_not_short_circuit() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({"dangerous": true}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "require_approval": false,
            "forbidden_parameters": ["dangerous"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "require_approval=false should not short-circuit; forbidden param should deny"
    );
}

// ═══════════════════════════════════════
// FORBIDDEN BEFORE REQUIRED PRECEDENCE
// ══════════════════════════════════════

/// Action has a forbidden param AND is missing a required param.
/// Forbidden is checked first, so Deny should cite the forbidden param.
#[test]
fn forbidden_checked_before_required() {
    let engine = PolicyEngine::new(false);
    let action = make_action("net", "post", json!({"password": "secret"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "forbidden_parameters": ["password"],
            "required_parameters": ["auth_token"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("password"),
                "Should deny due to forbidden 'password', got: {}",
                reason
            );
        }
        other => panic!("Expected Deny for forbidden param, got {:?}", other),
    }
}

/// Action has no forbidden params but is missing a required param.
/// Should deny due to missing required param.
#[test]
fn missing_required_param_denied_when_no_forbidden_match() {
    let engine = PolicyEngine::new(false);
    let action = make_action("net", "post", json!({"safe_key": "value"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "forbidden_parameters": ["password"],
            "required_parameters": ["auth_token"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("auth_token"),
                "Should deny due to missing 'auth_token', got: {}",
                reason
            );
        }
        other => panic!("Expected Deny for missing required param, got {:?}", other),
    }
}

/// Action satisfies all conditions: no forbidden params present,
/// all required params present, require_approval is false.
/// Should allow.
#[test]
fn all_conditions_satisfied_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("net", "post", json!({"auth_token": "abc123", "safe": true}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "require_approval": false,
            "forbidden_parameters": ["password", "secret"],
            "required_parameters": ["auth_token"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Action satisfying all conditions should be allowed, got {:?}",
        verdict
    );
}

// ══════════════════════════════════════
// EDGE: require_approval WITH NON-BOOL VALUES
// ══════════════════════════════════════

/// require_approval set to string "true" — as_bool() returns None,
/// unwrap_or(false) kicks in, so it should NOT require approval.
#[test]
fn require_approval_string_true_is_not_bool_true() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "require_approval": "true"
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "String 'true' is not bool true; as_bool() returns None; should allow. Got {:?}",
        verdict
    );
}

/// require_approval set to integer 1 — as_bool() returns None for integers.
#[test]
fn require_approval_integer_1_is_not_bool_true() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "require_approval": 1
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Integer 1 is not bool true; as_bool() returns None; should allow. Got {:?}",
        verdict
    );
}

/// require_approval set to null — as_bool() returns None.
#[test]
fn require_approval_null_is_not_bool_true() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "require_approval": null
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Null is not bool true; should allow. Got {:?}",
        verdict
    );
}
