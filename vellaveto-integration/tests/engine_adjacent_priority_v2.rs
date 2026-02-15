//! Tests that the engine correctly orders policies with adjacent priority
//! values (e.g., 99 vs 100) and verifies deny-overrides ONLY applies
//! at EQUAL priority, not at adjacent priorities.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action() -> Action {
    Action::new("tool".to_string(), "func".to_string(), json!({}))
}

fn allow(priority: i32) -> Policy {
    Policy {
        id: "*".to_string(),
        name: format!("allow-{}", priority),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny(priority: i32) -> Policy {
    Policy {
        id: "*".to_string(),
        name: format!("deny-{}", priority),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════════
// ONE APART: HIGHER PRIORITY WINS
// ════════════════════════════════

/// Allow at 100, Deny at 99 → Allow wins.
#[test]
fn allow_100_beats_deny_99() {
    let engine = PolicyEngine::new(false);
    let policies = vec![deny(99), allow(100)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Allow at 100 should beat Deny at 99"
    );
}

/// Deny at 100, Allow at 99 → Deny wins.
#[test]
fn deny_100_beats_allow_99() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow(99), deny(100)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny at 100 should beat Allow at 99"
    );
}

/// Allow at 1, Deny at 0  Allow wins.
#[test]
fn allow_1_beats_deny_0() {
    let engine = PolicyEngine::new(false);
    let policies = vec![deny(0), allow(1)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// Deny at 1, Allow at 0 → Deny wins.
#[test]
fn deny_1_beats_allow_0() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow(0), deny(1)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Allow at -99, Deny at -100 → Allow wins (higher = -99 > -100).
#[test]
fn allow_neg99_beats_deny_neg100() {
    let engine = PolicyEngine::new(false);
    let policies = vec![deny(-100), allow(-99)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

// ═══════════════════════════════
// EQUAL PRIORITY: DENY OVERRIDES ALLOW
// ═══════════════════════════════

/// At equal priority, deny beats allow regardless of input order.
#[test]
fn deny_overrides_allow_at_equal_priority_deny_first() {
    let engine = PolicyEngine::new(false);
    let policies = vec![deny(50), allow(50)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

#[test]
fn deny_overrides_allow_at_equal_priority_allow_first() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow(50), deny(50)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Equal priority at 0.
#[test]
fn deny_overrides_allow_at_priority_zero() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow(0), deny(0)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Equal priority at negative value.
#[test]
fn deny_overrides_allow_at_negative_priority() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow(-50), deny(-50)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ═══════════════════════════════
// CHAIN OF ADJACENT PRIORITIES
// ═══════════════════════════════

/// Deny(5), Allow(4), Deny(3), Allow(2), Deny(1) — highest priority wins.
#[test]
fn chain_of_adjacent_priorities_highest_wins() {
    let engine = PolicyEngine::new(false);
    let policies = vec![deny(1), allow(2), deny(3), allow(4), deny(5)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny at priority 5 should win"
    );
}

/// Allow(5), Deny(4), Allow(3), Deny(2), Allow(1) — Allow at 5 wins.
#[test]
fn chain_of_adjacent_priorities_allow_highest_wins() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow(1), deny(2), allow(3), deny(4), allow(5)];
    let result = engine.evaluate_action(&make_action(), &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Allow at priority 5 should win"
    );
}
