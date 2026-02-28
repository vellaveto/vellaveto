// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that the engine correctly orders policies with adjacent priority values
//! (e.g., 99 vs 100) and that the deny-overrides-allow tiebreaker only applies
//! at EQUAL priority, not at adjacent priorities.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

// ════════════════════════════
// ADJACENT PRIORITIES: 1 APART
// ═══════════════════════════

/// Allow at 100, Deny at 99. Allow wins because 100 > 99.
/// The deny-overrides rule only applies at EQUAL priority.
#[test]
fn allow_at_100_beats_deny_at_99() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "allow-100".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "deny-99".to_string(),
            policy_type: PolicyType::Deny,
            priority: 99,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Allow at priority 100 should beat Deny at 99: got {:?}",
        result
    );
}

/// Deny at 100, Allow at 99. Deny wins because 100 > 99.
#[test]
fn deny_at_100_beats_allow_at_99() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "deny-100".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "allow-99".to_string(),
            policy_type: PolicyType::Allow,
            priority: 99,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny at priority 100 should beat Allow at 99: got {:?}",
        result
    );
}

/// Confirm that deny-overrides IS active at equal priority (not adjacent).
#[test]
fn deny_overrides_allow_at_equal_priority_50() {
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
        "Deny should override Allow at equal priority 50: got {:?}",
        result
    );
}

/// Allow at 1, Deny at 0. Allow wins (1 > 0), deny-overrides does NOT apply.
#[test]
fn allow_at_1_beats_deny_at_0() {
    let engine = PolicyEngine::new(false);
    let action = make_action("x", "y");
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "deny-0".to_string(),
            policy_type: PolicyType::Deny,
            priority: 0,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "allow-1".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Allow at 1 should beat Deny at 0: got {:?}",
        result
    );
}

/// Deny at -1, Allow at 0. Allow wins (0 > -1).
#[test]
fn allow_at_0_beats_deny_at_negative_1() {
    let engine = PolicyEngine::new(false);
    let action = make_action("a", "b");
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "deny-neg1".to_string(),
            policy_type: PolicyType::Deny,
            priority: -1,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "allow-0".to_string(),
            policy_type: PolicyType::Allow,
            priority: 0,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Allow at 0 should beat Deny at -1: got {:?}",
        result
    );
}

// ═════════════════════════════════
// ADJACENT PRIORITIES WITH CONDITIONAL
// ════════════════════════════════

/// Conditional (require_approval) at 100, Deny at 99.
/// Conditional wins because 100 > 99.
#[test]
fn conditional_at_100_beats_deny_at_99() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "cond-100".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "deny-99".to_string(),
            policy_type: PolicyType::Deny,
            priority: 99,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Conditional at 100 should beat Deny at 99: got {:?}",
        result
    );
}

/// Deny at 100, Conditional at 99. Deny wins.
#[test]
fn deny_at_100_beats_conditional_at_99() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "deny-100".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "cond-99".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 99,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Deny at 100 should beat Conditional at 99: got {:?}",
        result
    );
}
