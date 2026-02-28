// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that verify the EXACT reason strings in engine verdicts.
//! Every assertion is derived from specific lines in vellaveto-engine/src/lib.rs.
//! If someone changes a reason string, these tests catch it immediately.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

// ═══════════════════════════════
// EMPTY POLICIES: EXACT REASON STRING
// ════════════════════════════════

/// Engine with empty policies returns Deny with reason "No policies defined".
/// Source: vellaveto-engine/src/lib.rs line ~39
#[test]
fn empty_policies_deny_reason_is_exact() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing", json!({}));
    let result = engine.evaluate_action(&action, &[]).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert_eq!(
                reason, "No policies defined",
                "Empty policies must produce exact reason string"
            );
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ════════════════════════════════
// NO MATCHING POLICY: EXACT REASON STRING
// ════════════════════════════════

/// When policies exist but none match, reason is "No matching policy".
/// Source: vellaveto-engine/src/lib.rs line ~58
#[test]
fn no_matching_policy_deny_reason_is_exact() {
    let engine = PolicyEngine::new(false);
    let action = make_action("unknown_tool", "unknown_func", json!({}));
    // Policy only matches "specific_tool"
    let policies = vec![Policy {
        id: "specific_tool:specific_func".to_string(),
        name: "Specific only".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert_eq!(reason, "No matching policy");
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ═══════════════════════════════
// DENY POLICY: REASON INCLUDES POLICY NAME
// ════════════════════════════════

/// Deny verdict reason format is "Denied by policy '{name}'".
/// Source: vellaveto-engine/src/lib.rs apply_policy method
#[test]
fn deny_policy_reason_includes_policy_name() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Block Everything".to_string(),
        policy_type: PolicyType::Deny,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert_eq!(reason, "Denied by policy 'Block Everything'");
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ════════════════════════════════
// REQUIRE APPROVAL: REASON FORMAT
// ═══════════════════════════════

/// RequireApproval reason format is "Approval required by policy '{name}'".
/// Source: vellaveto-engine/src/lib.rs evaluate_conditions method
#[test]
fn require_approval_reason_includes_policy_name() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "run", json!({}));
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Needs Human Review".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"require_approval": true}),
        },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::RequireApproval { reason } => {
            assert_eq!(reason, "Approval required by policy 'Needs Human Review'");
        }
        other => panic!("Expected RequireApproval, got {:?}", other),
    }
}

// ════════════════════════════════
// FORBIDDEN PARAMETER: REASON FORMAT
// ════════════════════════════════

/// Forbidden param reason: "Parameter '{param}' is forbidden by policy '{name}'"
/// Source: vellaveto-engine/src/lib.rs evaluate_conditions
#[test]
fn forbidden_param_reason_includes_param_and_policy_name() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"secret": "value"}));
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "No Secrets".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": ["secret"]}),
        },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert_eq!(
                reason,
                "Parameter 'secret' is forbidden by policy 'No Secrets'"
            );
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ════════════════════════════════
// REQUIRED PARAMETER MISSING: REASON FORMAT
// ═══════════════════════════════

/// Missing required param reason: "Required parameter '{param}' missing (policy '{name}')"
/// Source: vellaveto-engine/src/lib.rs evaluate_conditions
#[test]
fn required_param_missing_reason_format() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({})); // missing "token"
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Auth Required".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"required_parameters": ["token"]}),
        },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert_eq!(
                reason,
                "Required parameter 'token' missing (policy 'Auth Required')"
            );
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ════════════════════════════════
// CONDITION DEPTH EXCEEDED: ERROR TYPE
// ═══════════════════════════════

/// Conditions nested >10 levels produce EngineError::InvalidCondition.
/// Source: vellaveto-engine/src/lib.rs evaluate_conditions
#[test]
fn condition_depth_11_returns_error() {
    let engine = PolicyEngine::new(false);
    let action = make_action("t", "f", json!({}));

    // Build depth 11
    let mut val = json!("leaf");
    for _ in 0..11 {
        val = json!({"nested": val});
    }

    let policies = vec![Policy {
        id: "*".to_string(),
        name: "deep".to_string(),
        policy_type: PolicyType::Conditional { conditions: val },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err(), "Depth >10 must produce an error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("nesting depth"),
        "Error should mention nesting depth: {}",
        err_msg
    );
}
