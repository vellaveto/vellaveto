//! Documents that strict_mode=true has NO behavioral difference from false.
//! The engine stores strict_mode but never reads it (confirmed by dead_code warning).
//! These tests will BREAK if someone implements strict mode — that's intentional.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType};

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("allow-{}", id),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny-{}", id),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
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

/// Helper: evaluates same action+policies with both strict and non-strict,
/// returns true if verdicts are identical.
fn verdicts_match(action: &Action, policies: &[Policy]) -> bool {
    let strict = PolicyEngine::new(true);
    let relaxed = PolicyEngine::new(false);

    let v_strict = strict.evaluate_action(action, policies);
    let v_relaxed = relaxed.evaluate_action(action, policies);

    match (v_strict, v_relaxed) {
        (Ok(a), Ok(b)) => a == b,
        (Err(_), Err(_)) => true, // both error — same behavior
        _ => false,
    }
}

// ═══════════════════════════════════════
// STRICT MODE PARITY: BASIC POLICIES
// ══════════════════════════════════════

#[test]
fn empty_policies_same_in_strict_and_relaxed() {
    let action = make_action("bash", "exec", json!({}));
    assert!(
        verdicts_match(&action, &[]),
        "Empty policies should produce same Deny in both modes"
    );
}

#[test]
fn simple_allow_same_in_both_modes() {
    let action = make_action("file", "read", json!({}));
    let policies = vec![allow_policy("file:read", 10)];
    assert!(verdicts_match(&action, &policies));
}

#[test]
fn simple_deny_same_in_both_modes() {
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![deny_policy("bash:exec", 10)];
    assert!(verdicts_match(&action, &policies));
}

#[test]
fn wildcard_policy_same_in_both_modes() {
    let action = make_action("anything", "whatever", json!({"x": 1}));
    let policies = vec![allow_policy("*", 1)];
    assert!(verdicts_match(&action, &policies));
}

// ═══════════════════════════════════════
// STRICT MODE PARITY: CONDITIONALS
// ══════════════════════════════════════

#[test]
fn require_approval_same_in_both_modes() {
    let action = make_action("shell", "exec", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"require_approval": true}),
    )];
    assert!(verdicts_match(&action, &policies));
}

#[test]
fn forbidden_param_denial_same_in_both_modes() {
    let action = make_action("tool", "func", json!({"secret": "value"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": ["secret"]}),
    )];
    assert!(verdicts_match(&action, &policies));
}

#[test]
fn required_param_missing_denial_same_in_both_modes() {
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"required_parameters": ["auth_token"]}),
    )];
    assert!(verdicts_match(&action, &policies));
}

// ══════════════════════════════════════
// STRICT MODE PARITY: PRIORITY RESOLUTION
// ══════════════════════════════════════

#[test]
fn deny_before_allow_at_same_priority_same_in_both_modes() {
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![allow_policy("*", 100), deny_policy("*", 100)];
    assert!(verdicts_match(&action, &policies));
}

#[test]
fn many_policies_same_verdict_in_both_modes() {
    let action = make_action("tool_5", "func_3", json!({}));
    let mut policies = Vec::new();
    for i in 0..50 {
        if i % 3 == 0 {
            policies.push(allow_policy(&format!("tool_{}:func_{}", i, i % 10), i));
        } else {
            policies.push(deny_policy(&format!("tool_{}:*", i), i * 2));
        }
    }
    assert!(verdicts_match(&action, &policies));
}

// ══════════════════════════════════════
// STRICT MODE PARITY: CONDITION DEPTH/SIZE LIMITS
// ══════════════════════════════════════

#[test]
fn deep_condition_error_same_in_both_modes() {
    let action = make_action("t", "f", json!({}));
    // Build depth > 10
    let mut val = json!("leaf");
    for _ in 0..12 {
        val = json!({"nested": val});
    }
    let policies = vec![conditional_policy("*", 10, val)];
    // Both should return InvalidCondition error
    assert!(verdicts_match(&action, &policies));
}

#[test]
fn large_condition_error_same_in_both_modes() {
    let action = make_action("t", "f", json!({}));
    let big = "x".repeat(110_000);
    let conditions = json!({"data": big});
    let policies = vec![conditional_policy("*", 10, conditions)];
    assert!(verdicts_match(&action, &policies));
}
