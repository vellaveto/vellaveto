//! Tests engine behavior when multiple policies share the same pattern ID
//! but have different types (Allow, Deny, Conditional) at various priorities.
//! The key insight: the engine sorts by priority first, then applies
//! deny-overrides at equal priority. The first MATCHING policy wins.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

// ═══════════════════════════════
// THREE TYPES AT THREE DIFFERENT PRIORITIES
// ═══════════════════════════════

/// Deny(100), Conditional-approval(50), Allow(10)  all match "*".
/// Deny wins because it has highest priority.
#[test]
fn deny_highest_allow_lowest_conditional_middle() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing", json!({}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "allow-low".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "conditional-mid".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "deny-high".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Allow(100), Conditional-approval(50), Deny(10) — all match "*".
/// Allow wins because it has highest priority.
#[test]
fn allow_highest_deny_lowest_conditional_middle() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing", json!({}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "deny-low".to_string(),
            policy_type: PolicyType::Deny,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "conditional-mid".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "allow-high".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// Conditional-approval(100), Deny(50), Allow(10) — all match "*".
/// Conditional wins because it has highest priority.
#[test]
fn conditional_highest_produces_require_approval() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing", json!({}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "allow-low".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "deny-mid".to_string(),
            policy_type: PolicyType::Deny,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "conditional-high".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::RequireApproval { .. }));
}

// ════════════════════════════════
// THREE TYPES AT SAME PRIORITY — TIEBREAKER
// ════════════════════════════════

/// At equal priority, the engine sorts Deny before Allow (deny-overrides).
/// Conditional is neither Deny nor Allow for the tiebreaker comparison,
/// so it comes after Deny but its position relative to Allow depends on
/// the sort stability. Let's verify Deny wins.
#[test]
fn three_types_same_priority_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y", json!({}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "allow-50".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "conditional-50".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "deny-50".to_string(),
            policy_type: PolicyType::Deny,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // Deny should win due to deny-overrides tiebreaker at equal priority
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Expected Deny to win at equal priority due to deny-overrides, got {:?}",
        result,
    );
}

// ════════════════════════════════
// CONDITIONAL WITH FORBIDDEN PARAM VS DENY AT DIFFERENT PRIORITIES
// ═══════════════════════════════

/// Conditional at priority 100 with forbidden_parameters, Deny at 50.
/// If action has the forbidden param, conditional's Deny fires (not the explicit Deny policy).
#[test]
fn conditional_forbidden_param_at_higher_priority_than_explicit_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"secret": "value"}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "explicit-deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "conditional-forbidden".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"forbidden_parameters": ["secret"]}),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            // Should be the conditional's deny, not the explicit deny
            assert!(
                reason.contains("forbidden"),
                "Expected conditional's forbidden-param denial, got: {}",
                reason,
            );
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

/// Conditional at priority 100 with forbidden_parameters, action does NOT have the param.
/// Conditional falls through to Allow. The Deny at 50 is never reached because
/// conditional already matched and returned Allow.
#[test]
fn conditional_no_forbidden_match_falls_through_to_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"safe_key": "value"}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "explicit-deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "conditional-forbidden".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"forbidden_parameters": ["secret"]}),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // The conditional at priority 100 matches "*", evaluates conditions,
    // finds no forbidden params, no required params, no require_approval  returns Allow.
    // The Deny at priority 50 is never reached.
    assert!(
        matches!(result, Verdict::Allow),
        "Expected Allow (conditional passthrough), got {:?}",
        result,
    );
}
