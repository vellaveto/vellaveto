//! Tests that the engine's policy sorting is deterministic and stable.
//! When multiple policies have the same priority, deny-overrides-allow
//! must be consistent regardless of input order.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: json!({}),
    }
}

fn allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("allow-{}", id),
        policy_type: PolicyType::Allow,
        priority,
    }
}

fn deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny-{}", id),
        policy_type: PolicyType::Deny,
        priority,
    }
}

// ═══════════════════════════════════════
// DENY-OVERRIDES-ALLOW AT SAME PRIORITY
// ════════════════════════════════════════

#[test]
fn deny_wins_over_allow_at_same_priority_allow_first() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y");

    let policies = vec![
        allow_policy("*", 100),
        deny_policy("*", 100),
    ];

    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

#[test]
fn deny_wins_over_allow_at_same_priority_deny_first() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y");

    let policies = vec![
        deny_policy("*", 100),
        allow_policy("*", 100),
    ];

    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

#[test]
fn deny_overrides_allow_regardless_of_insertion_order() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    // Test all permutations of 3 policies at the same priority
    let base = vec![
        allow_policy("*", 50),
        deny_policy("*", 50),
        allow_policy("tool:*", 50),
    ];

    let permutations: Vec<Vec<usize>> = vec![
        vec![0, 1, 2],
        vec![0, 2, 1],
        vec![1, 0, 2],
        vec![1, 2, 0],
        vec![2, 0, 1],
        vec![2, 1, 0],
    ];

    for perm in &permutations {
        let policies: Vec<Policy> = perm.iter().map(|&i| base[i].clone()).collect();
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Permutation {:?} should produce Deny, got {:?}", perm, verdict
        );
    }
}

// ═══════════════════════════════════════
// DETERMINISTIC ACROSS REPEATED EVALUATIONS
// ════════════════════════════════════════

#[test]
fn same_input_produces_same_verdict_1000_times() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "write");

    let policies = vec![
        allow_policy("file:read", 200),
        deny_policy("file:write", 150),
        allow_policy("*", 10),
        deny_policy("file:delete", 300),
    ];

    let first = engine.evaluate_action(&action, &policies).unwrap();
    for i in 0..1000 {
        let current = engine.evaluate_action(&action, &policies).unwrap();
        assert_eq!(
            first, current,
            "Verdict changed on iteration {}: {:?} vs {:?}", i, first, current
        );
    }
}

#[test]
fn evaluation_is_pure_no_side_effects() {
    let engine = PolicyEngine::new(false);

    let policies = vec![
        deny_policy("bash:*", 100),
        allow_policy("*", 1),
    ];

    // Evaluate many different actions, then re-evaluate the first
    let first_action = make_action("bash", "exec");
    let first_verdict = engine.evaluate_action(&first_action, &policies).unwrap();

    for i in 0..100 {
        let action = make_action(&format!("tool_{}", i), "func");
        let _ = engine.evaluate_action(&action, &policies);
    }

    let second_verdict = engine.evaluate_action(&first_action, &policies).unwrap();
    assert_eq!(first_verdict, second_verdict, "Engine evaluation should be pure/stateless");
}

// ═══════════════════════════════════════
// PRIORITY ORDERING IS STRICT
// ════════════════════════════════════════

#[test]
fn higher_priority_always_takes_precedence() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y");

    // Build a chain: priority 1 (allow) < 2 (deny) < 3 (allow) < ... < 100 (deny)
    // The highest priority policy (100, deny) should win.
    let mut policies = Vec::new();
    for p in 1..=100 {
        if p % 2 == 0 {
            policies.push(deny_policy("*", p));
        } else {
            policies.push(allow_policy("*", p));
        }
    }

    // Priority 100 is even → deny
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

#[test]
fn reversed_insertion_still_respects_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y");

    // Insert in reverse priority order
    let mut policies = Vec::new();
    for p in (1..=100).rev() {
        if p % 2 == 0 {
            policies.push(deny_policy("*", p));
        } else {
            policies.push(allow_policy("*", p));
        }
    }

    // Still priority 100 (deny) wins
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

// ═══════════════════════════════════════
// CONDITIONAL TIE-BREAKING
// ════════════════════════════════════════

#[test]
fn conditional_does_not_override_deny_at_same_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y");

    // At same priority, Deny is not Conditional — the secondary sort only
    // puts Deny before Allow. Conditional is neither, so let's see what happens.
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "conditional".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({ "require_approval": true }),
            },
            priority: 50,
        },
        deny_policy("*", 50),
    ];

    // Deny should win at same priority (deny-overrides)
    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Deny { .. }
    ));
}

#[test]
fn conditional_at_higher_priority_beats_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y");

    let policies = vec![
        deny_policy("*", 10),
        Policy {
            id: "*".to_string(),
            name: "conditional".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({ "require_approval": true }),
            },
            priority: 100,
        },
    ];

    assert!(matches!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::RequireApproval { .. }
    ));
}