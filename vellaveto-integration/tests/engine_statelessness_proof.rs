// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Proves that PolicyEngine::evaluate_action is stateless.
//! The engine stores no mutable state, so interleaving different
//! policy sets through the same engine instance must produce
//! identical results to using separate engine instances.

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

// ═══════════════════════════════════════
// INTERLEAVED EVALUATION: NO STATE LEAKAGE
// ═══════════════════════════════════════

/// Evaluate with deny policies, then allow policies, then deny again.
/// The second deny evaluation must NOT be influenced by the allow evaluation.
#[test]
fn interleaved_policy_sets_no_state_leakage() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    let deny_set = vec![deny_policy("*", 100)];
    let allow_set = vec![allow_policy("*", 100)];

    // Deny → Allow → Deny: each must be independent
    let v1 = engine.evaluate_action(&action, &deny_set).unwrap();
    assert!(matches!(v1, Verdict::Deny { .. }));

    let v2 = engine.evaluate_action(&action, &allow_set).unwrap();
    assert!(matches!(v2, Verdict::Allow));

    let v3 = engine.evaluate_action(&action, &deny_set).unwrap();
    assert!(matches!(v3, Verdict::Deny { .. }));

    // v1 and v3 must be identical
    assert_eq!(
        v1, v3,
        "Same input must produce same output regardless of prior evaluations"
    );
}

/// Run 1000 alternating evaluations and verify no drift.
#[test]
fn high_volume_interleaved_evaluations() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec");

    let deny_set = vec![deny_policy("shell:*", 50)];
    let allow_set = vec![allow_policy("shell:*", 50)];

    for i in 0..1000 {
        let verdict = if i % 2 == 0 {
            engine.evaluate_action(&action, &deny_set).unwrap()
        } else {
            engine.evaluate_action(&action, &allow_set).unwrap()
        };

        if i % 2 == 0 {
            assert!(
                matches!(verdict, Verdict::Deny { .. }),
                "Iteration {}: expected Deny with deny_set",
                i
            );
        } else {
            assert!(
                matches!(verdict, Verdict::Allow),
                "Iteration {}: expected Allow with allow_set",
                i
            );
        }
    }
}

/// Different engine instances with same input must produce identical output.
#[test]
fn separate_engine_instances_same_result() {
    let engines: Vec<PolicyEngine> = (0..10).map(|_| PolicyEngine::new(false)).collect();
    let action = make_action("net", "fetch");
    let policies = vec![deny_policy("net:*", 100), allow_policy("*", 1)];

    let baseline = engines[0].evaluate_action(&action, &policies).unwrap();
    for (i, engine) in engines.iter().enumerate().skip(1) {
        let v = engine.evaluate_action(&action, &policies).unwrap();
        assert_eq!(
            baseline, v,
            "Engine instance {} produced different result",
            i
        );
    }
}

/// Evaluating with an empty policy set between two real evaluations
/// must not taint subsequent results.
#[test]
fn empty_policy_evaluation_does_not_taint() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let real_policies = vec![allow_policy("file:read", 10)];

    let v1 = engine.evaluate_action(&action, &real_policies).unwrap();
    assert!(matches!(v1, Verdict::Allow));

    // Empty set → Deny (fail-closed)
    let v_empty = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(v_empty, Verdict::Deny { .. }));

    // Real set again → must still Allow
    let v2 = engine.evaluate_action(&action, &real_policies).unwrap();
    assert!(matches!(v2, Verdict::Allow));
    assert_eq!(v1, v2);
}

// ═══════════════════════════════════════
// STRICT MODE VS NON-STRICT: SAME BEHAVIOR
// ═══════════════════════════════════════

/// Since strict_mode is stored but never read, both modes must
/// produce identical results for every possible input.
#[test]
fn strict_and_nonstrict_identical_across_all_policy_types() {
    let strict = PolicyEngine::new(true);
    let relaxed = PolicyEngine::new(false);

    let action = make_action("any", "thing");

    let policy_sets: Vec<Vec<Policy>> = vec![
        vec![],
        vec![allow_policy("*", 0)],
        vec![deny_policy("*", 0)],
        vec![allow_policy("*", 100), deny_policy("*", 100)],
        vec![Policy {
            id: "*".to_string(),
            name: "cond".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
        }],
        vec![Policy {
            id: "*".to_string(),
            name: "cond-forbidden".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"forbidden_parameters": ["secret"]}),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
        }],
    ];

    for (i, policies) in policy_sets.iter().enumerate() {
        let vs = strict.evaluate_action(&action, policies).unwrap();
        let vr = relaxed.evaluate_action(&action, policies).unwrap();
        assert_eq!(
            vs, vr,
            "Policy set {} produced different results for strict vs relaxed",
            i
        );
    }
}
