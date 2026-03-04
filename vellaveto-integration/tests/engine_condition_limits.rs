// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests for the engine's defensive limits on condition JSON:
//! nesting depth (>10) and size (>100KB).

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType};

fn make_action() -> Action {
    Action::new("tool".to_string(), "func".to_string(), json!({}))
}

fn conditional_policy_with(conditions: serde_json::Value) -> Policy {
    Policy {
        id: "*".to_string(),
        name: "test-conditional".to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }
}

// ════════════════════════════════════════════════
// CONDITION NESTING DEPTH LIMIT (>10)
// ═════════════════════════════════════════════════

#[test]
fn condition_depth_exactly_10_is_accepted() {
    let engine = PolicyEngine::new(false);
    let action = make_action();

    // Build depth exactly 10
    let mut val = json!("leaf");
    for _ in 0..9 {
        val = json!({"d": val});
    }
    // depth = 9 objects wrapping a leaf = 9. Plus one more:
    val = json!({"d": val}); // depth = 10

    let policy = conditional_policy_with(val);
    let result = engine.evaluate_action(&action, &[policy]);
    assert!(
        result.is_ok(),
        "Condition depth exactly 10 should be accepted, got: {:?}",
        result.err()
    );
}

#[test]
fn condition_depth_11_is_rejected() {
    let engine = PolicyEngine::new(false);
    let action = make_action();

    let mut val = json!("leaf");
    for _ in 0..11 {
        val = json!({"d": val});
    }

    let policy = conditional_policy_with(val);
    let result = engine.evaluate_action(&action, &[policy]);
    assert!(result.is_err(), "Condition depth 11 should be rejected");

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("nesting depth"),
        "Error should mention nesting depth: {msg}"
    );
}

#[test]
fn condition_depth_via_arrays_also_counted() {
    let engine = PolicyEngine::new(false);
    let action = make_action();

    // Alternate between arrays and objects to depth 12
    let mut val = json!("leaf");
    for i in 0..12 {
        if i % 2 == 0 {
            val = json!([val]);
        } else {
            val = json!({"d": val});
        }
    }

    let policy = conditional_policy_with(val);
    let result = engine.evaluate_action(&action, &[policy]);
    assert!(
        result.is_err(),
        "Mixed array/object depth >10 should be rejected"
    );
}

// ════════════════════════════════════════════════
// CONDITION SIZE LIMIT (>100KB)
// ═════════════════════════════════════════════════

#[test]
fn condition_size_over_100kb_is_rejected() {
    let engine = PolicyEngine::new(false);
    let action = make_action();

    // Create a conditions object > 100KB
    let big_string = "x".repeat(110_000);
    let conditions = json!({"data": big_string});

    let policy = conditional_policy_with(conditions);
    let result = engine.evaluate_action(&action, &[policy]);
    assert!(result.is_err(), "Conditions >100KB should be rejected");

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("too large"),
        "Error should mention size: {msg}"
    );
}

#[test]
fn condition_size_under_100kb_is_accepted() {
    let engine = PolicyEngine::new(false);
    let action = make_action();

    let small_string = "y".repeat(50_000);
    let conditions = json!({"data": small_string, "require_approval": false});

    let policy = conditional_policy_with(conditions);
    let result = engine.evaluate_action(&action, &[policy]);
    assert!(result.is_ok(), "Conditions under 100KB should be accepted");
}

// ═════════════════════════════════════════════════
// DEEPLY NESTED NON-MATCHING POLICY SKIPPED
// ═════════════════════════════════════════════════

#[test]
fn deeply_nested_condition_on_non_matching_policy_not_checked() {
    let engine = PolicyEngine::new(false);
    let action = Action::new("safe_tool".to_string(), "safe_func".to_string(), json!({}));

    // This policy has depth > 10 in conditions but shouldn't match our action
    let mut deep = json!("leaf");
    for _ in 0..15 {
        deep = json!({"d": deep});
    }

    let policies = vec![
        // Non-matching policy with bad conditions
        Policy {
            id: "dangerous:delete".to_string(),
            name: "deep-cond".to_string(),
            policy_type: PolicyType::Conditional { conditions: deep },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        // Matching allow policy
        Policy {
            id: "safe_tool:safe_func".to_string(),
            name: "safe-allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];

    // The dangerous policy is higher priority but doesn't match our tool:func.
    // The safe policy matches at priority 50.
    let result = engine.evaluate_action(&action, &policies);
    // This should succeed because the non-matching policy is skipped entirely.
    assert!(result.is_ok(), "Non-matching deep policy should be skipped");
    let verdict = result.unwrap();
    assert_eq!(verdict, vellaveto_types::Verdict::Allow);
}
