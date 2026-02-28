// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests for negative and extreme i32 priority values.
//! Priority is i32, so negative values are valid and should be ordered correctly.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

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

// ════════════════════════════════════
// NEGATIVE PRIORITIES
// ═══════════════════════════════════

/// A positive-priority deny should beat a negative-priority allow.
#[test]
fn positive_deny_beats_negative_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![allow_policy("*", -100), deny_policy("*", 1)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

/// Both negative: higher (less negative) wins.
#[test]
fn less_negative_wins_over_more_negative() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![
        allow_policy("*", -1),  // higher
        deny_policy("*", -100), // lower
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

/// i32::MIN vs i32::MAX — MAX should always win.
#[test]
fn i32_max_beats_i32_min() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![deny_policy("*", i32::MIN), allow_policy("*", i32::MAX)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

/// i32::MAX vs i32::MAX — same priority, deny-overrides-allow.
#[test]
fn i32_max_tie_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![allow_policy("*", i32::MAX), deny_policy("*", i32::MAX)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

/// i32::MIN vs i32::MIN  same priority, deny-overrides-allow.
#[test]
fn i32_min_tie_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![allow_policy("*", i32::MIN), deny_policy("*", i32::MIN)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ════════════════════════════════════
// NEGATIVE PRIORITY WITH SPECIFIC PATTERNS
// ═══════════════════════════════════

/// A specific deny at priority -1 should lose to a wildcard allow at priority 0.
#[test]
fn specific_negative_deny_loses_to_wildcard_zero_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![deny_policy("file:read", -1), allow_policy("*", 0)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

/// Priority 0 vs priority 0 — deny overrides allow at zero.
#[test]
fn zero_priority_deny_overrides_zero_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![allow_policy("*", 0), deny_policy("*", 0)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════
// PRIORITY ORDERING ACROSS MANY POLICIES
// ═══════════════════════════════════

/// 10 policies spanning negative to positive. Only the highest-priority matching one applies.
#[test]
fn ten_policies_highest_priority_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![
        allow_policy("*", -50),
        deny_policy("*", -40),
        allow_policy("*", -30),
        deny_policy("*", -20),
        allow_policy("*", -10),
        deny_policy("*", 0),
        allow_policy("*", 10),
        deny_policy("*", 20),
        allow_policy("*", 30),
        deny_policy("*", 40),
    ];
    // Highest priority is 40, which is deny
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

/// Same as above but add an allow at priority 50 — it should win.
#[test]
fn highest_allow_at_top_wins_over_mixed() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let mut policies = vec![
        allow_policy("*", -50),
        deny_policy("*", -40),
        allow_policy("*", -30),
        deny_policy("*", -20),
        allow_policy("*", -10),
        deny_policy("*", 0),
        allow_policy("*", 10),
        deny_policy("*", 20),
        allow_policy("*", 30),
        deny_policy("*", 40),
    ];
    policies.push(allow_policy("*", 50));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// ═══════════════════════════════════
// NEGATIVE PRIORITY WITH CONDITIONAL
// ═══════════════════════════════════

/// Conditional at negative priority still fires if it's the highest match.
#[test]
fn conditional_at_negative_priority_fires_when_highest() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![
        allow_policy("*", -100),
        Policy {
            id: "*".to_string(),
            name: "cond-negative".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: -50,
            path_rules: None,
            network_rules: None,
        },
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

/// Conditional at -50 loses to deny at 0.
#[test]
fn conditional_negative_loses_to_deny_zero() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "cond-negative".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: -50,
            path_rules: None,
            network_rules: None,
        },
        deny_policy("*", 0),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════
// SERIALIZATION OF NEGATIVE PRIORITIES
// ═══════════════════════════════════

/// Negative priority survives JSON roundtrip.
#[test]
fn negative_priority_roundtrips_through_json() {
    let policy = deny_policy("*", -999);
    let json_str = serde_json::to_string(&policy).unwrap();
    let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.priority, -999);
}

/// i32::MIN priority survives JSON roundtrip.
#[test]
fn i32_min_priority_roundtrips_through_json() {
    let policy = allow_policy("*", i32::MIN);
    let json_str = serde_json::to_string(&policy).unwrap();
    let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.priority, i32::MIN);
}

/// i32::MAX priority survives JSON roundtrip.
#[test]
fn i32_max_priority_roundtrips_through_json() {
    let policy = deny_policy("*", i32::MAX);
    let json_str = serde_json::to_string(&policy).unwrap();
    let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.priority, i32::MAX);
}
