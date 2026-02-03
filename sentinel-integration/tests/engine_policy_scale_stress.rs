//! Stress tests with large numbers of policies.
//! Existing fuzz tests generate ~hundreds of policies.
//! These tests push to 1000+ to stress the sort and linear scan.
//! Primary goal: no panics, correct results, no quadratic blowup.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

// ═══════════════════════════════
// 1000 NON-MATCHING POLICIES + 1 MATCHING
// ═══════════════════════════════

/// 1000 policies that don't match, plus one Allow at the end that does.
/// The engine must scan all 1000 before finding the match.
#[test]
fn thousand_non_matching_then_one_match() {
    let engine = PolicyEngine::new(false);
    let action = make_action("target", "func");

    let mut policies: Vec<Policy> = (0..1000)
        .map(|i| Policy {
            id: format!("nonmatch_{}:nonmatch_{}", i, i),
            name: format!("noise-{}", i),
            policy_type: PolicyType::Allow,
            priority: i,
            path_rules: None,
            network_rules: None,
        })
        .collect();

    policies.push(Policy {
        id: "target:func".to_string(),
        name: "the-match".to_string(),
        policy_type: PolicyType::Allow,
        priority: 0,
        path_rules: None,
        network_rules: None,
    });

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Should find the matching Allow policy among 1000 non-matching, got {:?}",
        result
    );
}

/// 1000 non-matching policies, none matching → default Deny.
#[test]
fn thousand_non_matching_defaults_to_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("target", "func");

    let policies: Vec<Policy> = (0..1000)
        .map(|i| Policy {
            id: format!("other_{}:other_{}", i, i),
            name: format!("noise-{}", i),
            policy_type: PolicyType::Allow,
            priority: i,
            path_rules: None,
            network_rules: None,
        })
        .collect();

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert_eq!(reason, "No matching policy");
        }
        other => panic!("1000 non-matching should default to Deny, got {:?}", other),
    }
}

// ════════════════════════════════
// 1000 MATCHING POLICIES: HIGHEST PRIORITY WINS
// ═══════════════════════════════

/// 1000 Allow policies all matching "*", priorities 0..999. Priority 999 wins.
/// Then add a Deny at priority 1000 — it should override.
#[test]
fn thousand_matching_allows_highest_priority_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing");

    let mut policies: Vec<Policy> = (0..1000)
        .map(|i| Policy {
            id: "*".to_string(),
            name: format!("allow-{}", i),
            policy_type: PolicyType::Allow,
            priority: i,
            path_rules: None,
            network_rules: None,
        })
        .collect();

    // All should result in Allow (highest priority Allow wins, all are Allow)
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));

    // Add a Deny at priority 1000
    policies.push(Policy {
        id: "*".to_string(),
        name: "deny-override".to_string(),
        policy_type: PolicyType::Deny,
        priority: 1000,
        path_rules: None,
        network_rules: None,
    });

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny at priority 1000 should override 1000 Allows, got {:?}",
        result
    );
}

// ════════════════════════════════
// MIXED TYPES AT SCALE
// ════════════════════════════════

/// 500 Allow, 500 Deny, all matching "*", shuffled priorities.
/// The highest priority wins. We'll put a Deny at the top.
#[test]
fn mixed_500_allow_500_deny_highest_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing");

    let mut policies: Vec<Policy> = Vec::with_capacity(1000);
    for i in 0..500 {
        policies.push(Policy {
            id: "*".to_string(),
            name: format!("allow-{}", i),
            policy_type: PolicyType::Allow,
            priority: i * 2, // even priorities: 0, 2, 4, ..., 998,
            path_rules: None,
            network_rules: None,
        });
    }
    for i in 0..500 {
        policies.push(Policy {
            id: "*".to_string(),
            name: format!("deny-{}", i),
            policy_type: PolicyType::Deny,
            priority: i * 2 + 1, // odd priorities: 1, 3, 5, ..., 999,
            path_rules: None,
            network_rules: None,
        });
    }

    // Highest priority is 999 (Deny)
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny at priority 999 (highest) should win, got {:?}",
        result
    );
}

/// Same as above but highest priority is Allow at 1000.
#[test]
fn mixed_types_allow_at_top_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing");

    let mut policies: Vec<Policy> = Vec::with_capacity(1001);
    for i in 0..500 {
        policies.push(Policy {
            id: "*".to_string(),
            name: format!("allow-{}", i),
            policy_type: PolicyType::Allow,
            priority: i,
            path_rules: None,
            network_rules: None,
        });
        policies.push(Policy {
            id: "*".to_string(),
            name: format!("deny-{}", i),
            policy_type: PolicyType::Deny,
            priority: i,
            path_rules: None,
            network_rules: None,
        });
    }
    // At each priority 0..499, Deny beats Allow (deny-overrides tiebreaker).
    // Add an Allow at priority 1000 — it should win outright.
    policies.push(Policy {
        id: "*".to_string(),
        name: "allow-top".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1000,
        path_rules: None,
        network_rules: None,
    });

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Allow at priority 1000 should beat all others, got {:?}",
        result
    );
}
