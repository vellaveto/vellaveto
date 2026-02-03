//! Tests that explore PolicyEngine's strict_mode parameter.
//! The engine stores strict_mode but the current implementation
//! never reads it (confirmed by dead_code warning). These tests
//! verify that strict_mode=true behaves identically to strict_mode=false,
//! documenting the current (possibly unfinished) behavior.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn make_action_with_params(tool: &str, function: &str, params: serde_json::Value) -> Action {
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

// ═══════════════════════════════════
// STRICT MODE DOES NOT CHANGE EMPTY POLICY BEHAVIOR
// ═══════════════════════════════════

#[test]
fn strict_empty_policies_still_deny() {
    let engine = PolicyEngine::new(true);
    let action = make_action("tool", "func");
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════
// STRICT MODE DOES NOT CHANGE BASIC EVALUATION
// ═══════════════════════════════════

#[test]
fn strict_allow_policy_still_allows() {
    let engine = PolicyEngine::new(true);
    let action = make_action("file", "read");
    let policies = vec![allow_policy("file:read", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn strict_deny_policy_still_denies() {
    let engine = PolicyEngine::new(true);
    let action = make_action("bash", "exec");
    let policies = vec![deny_policy("bash:*", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════
// STRICT MODE DOES NOT CHANGE CONDITIONAL EVALUATION
// ═══════════════════════════════════

#[test]
fn strict_conditional_require_approval_still_works() {
    let engine = PolicyEngine::new(true);
    let action = make_action("shell", "exec");
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"require_approval": true}),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn strict_conditional_forbidden_params_still_denies() {
    let engine = PolicyEngine::new(true);
    let action = make_action_with_params("net", "upload", json!({"credentials": "secret"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "forbidden_parameters": ["credentials"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn strict_conditional_required_params_missing_denies() {
    let engine = PolicyEngine::new(true);
    let action = make_action("api", "call");
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "required_parameters": ["auth_token"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════
// STRICT MODE DOES NOT CHANGE PRIORITY ORDERING
// ═══════════════════════════════════

#[test]
fn strict_priority_ordering_same_as_non_strict() {
    let strict_engine = PolicyEngine::new(true);
    let normal_engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![allow_policy("*", 1), deny_policy("*", 100)];

    let strict_verdict = strict_engine.evaluate_action(&action, &policies).unwrap();
    let normal_verdict = normal_engine.evaluate_action(&action, &policies).unwrap();

    // Both should deny (priority 100 deny beats priority 1 allow)
    assert!(matches!(strict_verdict, Verdict::Deny { .. }));
    assert!(matches!(normal_verdict, Verdict::Deny { .. }));
}

#[test]
fn strict_tie_breaking_same_as_non_strict() {
    let strict_engine = PolicyEngine::new(true);
    let normal_engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![allow_policy("*", 50), deny_policy("*", 50)];

    let strict_verdict = strict_engine.evaluate_action(&action, &policies).unwrap();
    let normal_verdict = normal_engine.evaluate_action(&action, &policies).unwrap();

    // Both should deny (deny-overrides-allow at same priority)
    assert!(matches!(strict_verdict, Verdict::Deny { .. }));
    assert!(matches!(normal_verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════
// STRICT MODE DOES NOT CHANGE DEPTH LIMIT BEHAVIOR
// ═══════════════════════════════════

#[test]
fn strict_deep_condition_still_rejected() {
    let engine = PolicyEngine::new(true);
    let action = make_action("t", "f");

    // Build condition with depth > 10
    let mut val = json!("leaf");
    for _ in 0..11 {
        val = json!({"d": val});
    }

    let policies = vec![conditional_policy("*", 10, val)];
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}
