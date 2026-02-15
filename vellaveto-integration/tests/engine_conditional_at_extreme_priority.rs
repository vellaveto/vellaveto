//! Tests conditional policies at i32::MIN and i32::MAX priorities.
//! Existing extreme priority tests cover Allow/Deny only.
//! Conditional policies at extremes exercise the sort + condition eval path.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn conditional_policy(id: &str, priority: i32, conditions: serde_json::Value) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("cond-{}", priority),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("allow-{}", priority),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny-{}", priority),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════════
// CONDITIONAL AT i32::MAX
// ═══════════════════════════════

/// Conditional require_approval at i32::MAX beats Deny at i32::MAX - 1.
#[test]
fn conditional_approval_at_max_beats_deny_below() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![
        deny_policy("*", i32::MAX - 1),
        conditional_policy("*", i32::MAX, json!({"require_approval": true})),
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Conditional at i32::MAX should win over Deny at i32::MAX-1, got {:?}",
        result
    );
}

/// Conditional forbidden_parameters at i32::MAX beats Allow at i32::MAX - 1.
#[test]
fn conditional_forbidden_at_max_beats_allow_below() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"secret": "val"}));
    let policies = vec![
        allow_policy("*", i32::MAX - 1),
        conditional_policy("*", i32::MAX, json!({"forbidden_parameters": ["secret"]})),
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Conditional forbidden at i32::MAX should deny, got {:?}",
        result
    );
}

// ════════════════════════════════
// CONDITIONAL AT i32::MIN
// ════════════════════════════════

/// Conditional at i32::MIN loses to Allow at 0.
#[test]
fn conditional_at_min_loses_to_allow_at_zero() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![
        conditional_policy("*", i32::MIN, json!({"require_approval": true})),
        allow_policy("*", 0),
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Allow at 0 should beat conditional at i32::MIN, got {:?}",
        result
    );
}

/// When ONLY a conditional at i32::MIN exists and it doesn't trigger,
/// the fall-through is Allow (from evaluate_conditions returning Allow).
#[test]
fn conditional_at_min_with_no_trigger_falls_through_to_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    // Conditional with require_approval=false and no forbidden/required params
    let policies = vec![conditional_policy(
        "*",
        i32::MIN,
        json!({"require_approval": false}),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Conditional with no triggered conditions should fall through to Allow, got {:?}",
        result
    );
}

// ════════════════════════════════
// CONDITIONAL vs DENY AT SAME EXTREME PRIORITY
// ════════════════════════════════

/// At equal priority i32::MAX, Deny beats Conditional (deny-overrides tiebreaker).
/// Source: sort comparator puts Deny before non-Deny at equal priority.
#[test]
fn deny_beats_conditional_at_equal_max_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![
        conditional_policy("*", i32::MAX, json!({"require_approval": true})),
        deny_policy("*", i32::MAX),
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny should beat Conditional at equal priority (deny-overrides), got {:?}",
        result
    );
}

/// At equal priority i32::MIN, Deny still beats Conditional.
#[test]
fn deny_beats_conditional_at_equal_min_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![
        conditional_policy("*", i32::MIN, json!({"require_approval": true})),
        deny_policy("*", i32::MIN),
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny should beat Conditional at equal i32::MIN priority, got {:?}",
        result
    );
}

// ═══════════════════════════════
// THREE-WAY TIE AT EXTREME PRIORITIES
// ════════════════════════════════

/// Allow, Deny, and Conditional all at i32::MAX. Deny wins (deny-overrides).
#[test]
fn three_way_tie_at_max_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![
        allow_policy("*", i32::MAX),
        conditional_policy("*", i32::MAX, json!({"require_approval": true})),
        deny_policy("*", i32::MAX),
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny should win three-way tie at i32::MAX, got {:?}",
        result
    );
}

/// Allow, Deny, Conditional all at i32::MIN. Deny still wins.
#[test]
fn three_way_tie_at_min_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![
        allow_policy("*", i32::MIN),
        conditional_policy("*", i32::MIN, json!({"require_approval": true})),
        deny_policy("*", i32::MIN),
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny should win three-way tie at i32::MIN, got {:?}",
        result
    );
}
