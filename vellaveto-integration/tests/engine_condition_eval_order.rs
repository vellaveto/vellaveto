// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests the exact order of condition evaluation within conditional policies.
//! Source: vellaveto-engine/src/lib.rs evaluate_conditions method.
//!
//! Order:
//!   1. Depth check (>10 → Error)
//!   2. Size check (>100KB → Error)
//!   3. require_approval (true → RequireApproval)
//!   4. forbidden_parameters (match → Deny)
//!   5. required_parameters (missing  Deny)
//!   6. Fall-through → Allow
//!
//! This means require_approval=true ALWAYS wins over forbidden/required params.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(params: serde_json::Value) -> Action {
    Action::new("tool".to_string(), "func".to_string(), params)
}

fn cond_policy(conditions: serde_json::Value) -> Vec<Policy> {
    vec![Policy {
        id: "*".to_string(),
        name: "test-cond".to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }]
}

// ════════════════════════════════
// REQUIRE_APPROVAL BEATS FORBIDDEN
// ════════════════════════════════

/// require_approval=true + forbidden param present → RequireApproval (not Deny).
/// require_approval is checked BEFORE forbidden_parameters.
#[test]
fn require_approval_true_overrides_forbidden_param() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"secret": "val"}));
    let policies = cond_policy(json!({
        "require_approval": true,
        "forbidden_parameters": ["secret"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "require_approval checked first, should return RequireApproval not Deny"
    );
}

// ════════════════════════════════
// REQUIRE_APPROVAL BEATS REQUIRED MISSING
// ═══════════════════════════════

/// require_approval=true + required param missing → RequireApproval (not Deny).
#[test]
fn require_approval_true_overrides_missing_required() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({})); // missing "token"
    let policies = cond_policy(json!({
        "require_approval": true,
        "required_parameters": ["token"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "require_approval checked first, should return RequireApproval not Deny"
    );
}

// ════════════════════════════════
// FORBIDDEN BEATS REQUIRED MISSING
// ════════════════════════════════

/// Forbidden param present + required param missing → Deny for forbidden (checked first).
#[test]
fn forbidden_checked_before_required() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"danger": "val"})); // has forbidden, missing required
    let policies = cond_policy(json!({
        "forbidden_parameters": ["danger"],
        "required_parameters": ["token"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("forbidden"),
                "Should deny for forbidden param, not missing required. Got: {reason}"
            );
        }
        other => panic!("Expected Deny, got {other:?}"),
    }
}

// ═══════════════════════════════
// REQUIRE_APPROVAL FALSE → FALLS THROUGH
// ════════════════════════════════

/// require_approval=false does NOT trigger RequireApproval.
/// unwrap_or(false) in source means false is treated same as absent.
#[test]
fn require_approval_false_falls_through_to_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({}));
    let policies = cond_policy(json!({
        "require_approval": false
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "require_approval=false should fall through to Allow"
    );
}

/// require_approval absent entirely → falls through.
#[test]
fn require_approval_absent_falls_through_to_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({}));
    let policies = cond_policy(json!({}));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Empty conditions should fall through to Allow"
    );
}

// ════════════════════════════════
// ALL THREE PRESENT: REQUIRE_APPROVAL WINS
// ════════════════════════════════

/// All three condition types present: require_approval=true wins.
#[test]
fn all_three_conditions_require_approval_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"forbidden_key": "x"})); // has forbidden, missing required
    let policies = cond_policy(json!({
        "require_approval": true,
        "forbidden_parameters": ["forbidden_key"],
        "required_parameters": ["missing_key"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "require_approval=true always wins, regardless of other conditions"
    );
}

// ════════════════════════════════
// NO CONDITIONS TRIGGERED → ALLOW
// ════════════════════════════════

/// Conditional with forbidden_parameters that DON'T match → Allow.
#[test]
fn forbidden_params_not_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"safe_key": "val"}));
    let policies = cond_policy(json!({
        "forbidden_parameters": ["danger", "secret"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "No forbidden params match, should allow"
    );
}

/// Required params all present → Allow.
#[test]
fn required_params_all_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({"token": "abc", "user": "test"}));
    let policies = cond_policy(json!({
        "required_parameters": ["token", "user"]
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "All required params present, should allow"
    );
}

// ═══════════════════════════════
// REQUIRE_APPROVAL AS NON-BOOLEAN TYPE
// ═══════════════════════════════

/// require_approval set to string "true" — as_bool() returns None,
/// unwrap_or(false) makes it false. Should NOT trigger RequireApproval.
#[test]
fn require_approval_string_true_fails_closed() {
    // FIND-IMP-013: Non-boolean require_approval fails closed → RequireApproval.
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({}));
    let policies = cond_policy(json!({
        "require_approval": "true"  // string, not bool
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Non-boolean require_approval should fail-closed to RequireApproval, got {result:?}"
    );
}

/// FIND-IMP-013: Integer require_approval fails closed → RequireApproval.
#[test]
fn require_approval_integer_1_fails_closed() {
    let engine = PolicyEngine::new(false);
    let action = make_action(json!({}));
    let policies = cond_policy(json!({
        "require_approval": 1
    }));
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Non-boolean require_approval should fail-closed to RequireApproval, got {result:?}"
    );
}
