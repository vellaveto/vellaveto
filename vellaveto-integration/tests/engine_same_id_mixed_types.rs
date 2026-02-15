//! Tests engine behavior when multiple policies share the same pattern ID
//! but have different types (Allow, Deny, Conditional) at different priorities.
//! The engine sorts by priority first, then deny-overrides-allow at equal priority.
//! The first matching policy wins — subsequent ones are never evaluated.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn make_action_with_params(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

// ════════════════════════════
// SAME WILDCARD ID, THREE TYPES, DIFFERENT PRIORITIES
// ════════════════════════════

/// Deny at 100, Allow at 50, Conditional at 10.
/// Deny at highest priority wins for any action.
#[test]
fn deny_highest_priority_wins_over_all() {
    let engine = PolicyEngine::new(false);
    let action = make_action("anything", "whatever");
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "conditional-low".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "allow-mid".to_string(),
            policy_type: PolicyType::Allow,
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
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny at 100 should win: got {:?}",
        result
    );
}

/// Allow at 100, Deny at 50, Conditional at 10.
/// Allow at highest priority wins.
#[test]
fn allow_highest_priority_wins_over_deny_and_conditional() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y");
    let policies = vec![
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
            name: "allow-high".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "cond-low".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Allow at 100 should win: got {:?}",
        result
    );
}

/// Conditional (require_approval) at 100, Deny at 50, Allow at 10.
/// Conditional at highest priority wins → RequireApproval.
#[test]
fn conditional_highest_priority_wins_over_deny_and_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("a", "b");
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
            name: "cond-high".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Conditional at 100 should win: got {:?}",
        result
    );
}

// ════════════════════════════════
// SAME ID, SAME PRIORITY, MIXED TYPES
// ════════════════════════════════

/// Allow and Deny at same priority, same ID: deny-overrides.
/// Add Conditional at same priority too — does deny still win?
/// The sort is: higher priority first, then Deny before non-Deny.
/// All three at priority 50: Deny sorts first, matches, wins.
#[test]
fn three_types_same_priority_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
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
            name: "cond-50".to_string(),
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
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny should win at equal priority via deny-overrides: got {:?}",
        result
    );
}

// ═════════════════════════════════════
// CONDITIONAL WITH FORBIDDEN PARAMS: SAME ID AS ALLOW
// ══════════════════════════════════════

/// Conditional (forbids "secret") at 100, Allow at 50. Same wildcard ID.
/// Action HAS "secret" → Conditional denies it.
#[test]
fn conditional_forbids_param_before_allow_can_permit() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params("tool", "func", json!({"secret": "value"}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "cond-forbid".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"forbidden_parameters": ["secret"]}),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "allow-all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Conditional should deny because 'secret' is forbidden: got {:?}",
        result
    );
}

/// Same setup but action does NOT have "secret" → Conditional passes through to Allow.
#[test]
fn conditional_passes_through_when_forbidden_param_absent() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params("tool", "func", json!({"safe": "value"}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "cond-forbid".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"forbidden_parameters": ["secret"]}),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "allow-all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // Conditional matches (id "*"), no forbidden param found, falls through to Allow
    assert!(
        matches!(result, Verdict::Allow),
        "Conditional should pass through to Allow when forbidden param absent: got {:?}",
        result
    );
}
