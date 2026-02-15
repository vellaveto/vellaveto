//! Tests engine behavior when multiple policies share the same ID.
//! The engine matches on policy.id using pattern matching, so duplicate
//! IDs create ambiguity. The first match after priority sort wins.
//! These tests verify determinism and document edge cases.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn allow_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn conditional_policy(
    id: &str,
    name: &str,
    priority: i32,
    conditions: serde_json::Value,
) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════════════════
// DUPLICATE IDS WITH DIFFERENT PRIORITIES
// ═══════════════════════════════════════

/// Two policies with same ID "*", different priorities and types.
/// Higher priority deny should win.
#[test]
fn duplicate_wildcard_id_higher_priority_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("anything", "anything");
    let policies = vec![
        allow_policy("*", "allow-all", 1),
        deny_policy("*", "deny-all", 100),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Higher priority deny should win over lower priority allow with same ID"
    );
}

/// Same ID, same priority, deny vs allow. Deny-overrides-allow tie-break.
#[test]
fn duplicate_id_same_priority_deny_overrides_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![
        allow_policy("bash:exec", "allow-bash", 50),
        deny_policy("bash:exec", "deny-bash", 50),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "At equal priority, deny should override allow (deny-overrides rule)"
    );
}

/// Three policies with same wildcard ID, different priorities.
/// Highest priority (conditional with require_approval) should win.
#[test]
fn triple_duplicate_id_highest_priority_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("net", "fetch");
    let policies = vec![
        allow_policy("*", "allow-low", 1),
        deny_policy("*", "deny-mid", 50),
        conditional_policy("*", "approval-high", 100, json!({"require_approval": true})),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::RequireApproval { .. }),
        "Highest priority conditional should win: got {:?}",
        verdict
    );
}

// ═══════════════════════════════════════
// DUPLICATE IDS WITH DIFFERENT SPECIFICITY
// ══════════════════════════════════════

/// Two policies: one specific "bash:exec", one wildcard "*".
/// If the specific one has lower priority, the wildcard still wins
/// because priority trumps specificity.
#[test]
fn wildcard_at_higher_priority_beats_specific_at_lower() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![
        allow_policy("bash:exec", "specific-allow", 1),
        deny_policy("*", "wildcard-deny", 100),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Higher priority wildcard should beat lower priority specific match"
    );
}

/// Reverse: specific at higher priority beats wildcard at lower.
#[test]
fn specific_at_higher_priority_beats_wildcard_at_lower() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![
        deny_policy("*", "wildcard-deny", 1),
        allow_policy("bash:exec", "specific-allow", 100),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Higher priority specific should beat lower priority wildcard"
    );
}

// ═══════════════════════════════════════
// MANY DUPLICATES: STABILITY
// ═══════════════════════════════════════

/// 10 allow policies and 10 deny policies all with ID "*" and priority 50.
/// Deny-overrides should consistently win regardless of insertion order.
#[test]
fn many_duplicates_deny_overrides_is_stable() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing");

    // Interleave allows and denies
    let mut policies: Vec<Policy> = Vec::new();
    for i in 0..10 {
        policies.push(allow_policy("*", &format!("allow-{}", i), 50));
        policies.push(deny_policy("*", &format!("deny-{}", i), 50));
    }

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "With interleaved allow/deny at same priority, deny should always win"
    );

    // Reverse the order
    policies.reverse();
    let verdict2 = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict2, Verdict::Deny { .. }),
        "Reversing input order should not change deny-overrides behavior"
    );
}

/// Same test but all allows — should consistently allow.
#[test]
fn many_duplicate_allows_consistently_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    let policies: Vec<Policy> = (0..20)
        .map(|i| allow_policy("*", &format!("allow-{}", i), 50))
        .collect();

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}
