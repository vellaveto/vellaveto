//! Tests that verify specific policies override wildcards correctly,
//! and that fallthrough to default-deny works when no policy matches.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
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

// ═════════════════════════════════════════
// SPECIFIC POLICY OVERRIDES WILDCARD
// ═════════════════════════════════════════

#[test]
fn specific_deny_overrides_wildcard_allow_at_higher_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "delete");

    let policies = vec![
        allow_policy("*", 10),           // low-priority allow-all
        deny_policy("file:delete", 100), // high-priority specific deny
    ];

    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::Deny { reason } => {
            assert!(reason.contains("deny-file:delete"), "reason: {}", reason);
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

#[test]
fn specific_allow_overrides_wildcard_deny_at_higher_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");

    let policies = vec![deny_policy("*", 10), allow_policy("file:read", 100)];

    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Allow
    ));
}

#[test]
fn wildcard_deny_wins_when_specific_allow_has_lower_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");

    let policies = vec![deny_policy("*", 500), allow_policy("file:read", 10)];

    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

// ══════════════════════════════════════════
// FALLTHROUGH TO DEFAULT DENY
// ═════════════════════════════════════════

#[test]
fn no_matching_policy_falls_through_to_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("network", "connect");

    // Policies that don't match this action
    let policies = vec![allow_policy("file:read", 10), deny_policy("bash:*", 100)];

    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::Deny { reason } => {
            assert!(reason.contains("No matching policy"), "reason: {}", reason);
        }
        other => panic!("Expected default Deny, got {:?}", other),
    }
}

#[test]
fn empty_policies_is_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("anything", "at_all");

    match engine.evaluate_action(&action, &[]).unwrap() {
        Verdict::Deny { reason } => {
            assert!(reason.contains("No policies defined"), "reason: {}", reason);
        }
        other => panic!("Expected Deny for empty policies, got {:?}", other),
    }
}

// ═════════════════════════════════════════
// TOOL-ONLY WILDCARD VS TOOL:FUNCTION PATTERNS
// ══════════════════════════════════════════

#[test]
fn tool_only_id_matches_any_function_for_that_tool() {
    let engine = PolicyEngine::new(false);

    let policies = vec![deny_policy("bash", 100)];

    // "bash" as policy ID (no colon) should match tool="bash" regardless of function
    let action1 = make_action("bash", "execute");
    let action2 = make_action("bash", "eval");
    let action3 = make_action("file", "read");

    assert!(matches!(
        engine.evaluate_action(&action1, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
    assert!(matches!(
        engine.evaluate_action(&action2, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
    // "file" tool should NOT match "bash" policy
    assert!(
        matches!(engine.evaluate_action(&action3, &policies).unwrap(), Verdict::Deny { reason } if reason.contains("No matching"))
    );
}

#[test]
fn prefix_wildcard_on_tool_part() {
    let engine = PolicyEngine::new(false);

    // "*system" should match "file_system" tool
    let policies = vec![deny_policy("*system:read", 100)];

    let action = make_action("file_system", "read");
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));

    let action2 = make_action("network", "read");
    assert!(
        matches!(engine.evaluate_action(&action2, &policies).unwrap(), Verdict::Deny { reason } if reason.contains("No matching"))
    );
}

#[test]
fn suffix_wildcard_on_function_part() {
    let engine = PolicyEngine::new(false);

    // "file:delete*" should match function "delete_recursive"
    let policies = vec![deny_policy("file:delete*", 100)];

    let action = make_action("file", "delete_recursive");
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));

    let action2 = make_action("file", "read");
    assert!(
        matches!(engine.evaluate_action(&action2, &policies).unwrap(), Verdict::Deny { reason } if reason.contains("No matching"))
    );
}

// ═════════════════════════════════════════
// CONDITIONAL + WILDCARD INTERACTIONS
// ══════════════════════════════════════════

#[test]
fn conditional_wildcard_applies_to_all_actions() {
    let engine = PolicyEngine::new(false);

    let policies = vec![conditional_policy(
        "*",
        100,
        json!({ "require_approval": true }),
    )];

    let action = make_action("anything", "at_all");
    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::RequireApproval { .. } => {}
        other => panic!("Expected RequireApproval, got {:?}", other),
    }
}

#[test]
fn specific_allow_at_higher_priority_bypasses_conditional_wildcard() {
    let engine = PolicyEngine::new(false);

    let policies = vec![
        conditional_policy("*", 50, json!({ "require_approval": true })),
        allow_policy("file:read", 200),
    ];

    let action = make_action("file", "read");
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Allow
    ));

    // But other actions still hit the conditional
    let action2 = make_action("bash", "exec");
    assert!(matches!(
        engine.evaluate_action(&action2, &policies).unwrap(),
        Verdict::RequireApproval { .. }
    ));
}

#[test]
fn multiple_wildcards_highest_priority_wins() {
    let engine = PolicyEngine::new(false);

    let policies = vec![allow_policy("*", 10), deny_policy("*", 100)];

    let action = make_action("any", "thing");
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

// ══════════════════════════════════════════
// PRIORITY BOUNDARY: i32 extremes
// ══════════════════════════════════════════

#[test]
fn i32_max_priority_beats_everything() {
    let engine = PolicyEngine::new(false);

    let policies = vec![deny_policy("*", i32::MAX), allow_policy("*", i32::MAX - 1)];

    let action = make_action("x", "y");
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

#[test]
fn i32_min_priority_loses_to_everything() {
    let engine = PolicyEngine::new(false);

    let policies = vec![allow_policy("*", i32::MIN), deny_policy("*", 0)];

    let action = make_action("x", "y");
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

#[test]
fn negative_priority_is_valid_and_ordered_correctly() {
    let engine = PolicyEngine::new(false);

    let policies = vec![
        allow_policy("*", -100),
        deny_policy("*", -50), // -50 > -100, so deny wins
    ];

    let action = make_action("x", "y");
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}
