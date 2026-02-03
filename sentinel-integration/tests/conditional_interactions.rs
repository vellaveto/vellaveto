//! Tests for interactions between multiple conditional policies,
//! and edge cases in condition evaluation (forbidden + required params together).

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn conditional_policy(
    id: &str,
    name: &str,
    priority: i32,
    conditions: serde_json::Value,
) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
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

// ═══════════════════════════════════════════
// FORBIDDEN + REQUIRED PARAMETER INTERACTIONS
// ════════════════════════════════════════════

#[test]
fn forbidden_param_present_causes_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({"force": true, "path": "/tmp"}));
    let policies = vec![conditional_policy(
        "shell:*",
        "no-force",
        10,
        json!({
            "forbidden_parameters": ["force"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match verdict {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("force"),
                "reason should mention 'force': {}",
                reason
            );
        }
        other => panic!("expected Deny for forbidden param, got {:?}", other),
    }
}

#[test]
fn forbidden_param_absent_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({"path": "/tmp"}));
    let policies = vec![conditional_policy(
        "shell:*",
        "no-force",
        10,
        json!({
            "forbidden_parameters": ["force"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // No forbidden param present, no require_approval → Allow
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn required_param_missing_causes_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("api", "call", json!({"endpoint": "/data"}));
    let policies = vec![conditional_policy(
        "api:*",
        "need-auth",
        10,
        json!({
            "required_parameters": ["auth_token"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match verdict {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("auth_token"),
                "reason should mention missing param: {}",
                reason
            );
        }
        other => panic!("expected Deny for missing required param, got {:?}", other),
    }
}

#[test]
fn required_param_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action(
        "api",
        "call",
        json!({"endpoint": "/data", "auth_token": "abc123"}),
    );
    let policies = vec![conditional_policy(
        "api:*",
        "need-auth",
        10,
        json!({
            "required_parameters": ["auth_token"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn require_approval_takes_precedence_over_forbidden_check() {
    // Per the code: require_approval is checked FIRST
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({"force": true}));
    let policies = vec![conditional_policy(
        "*",
        "approval-first",
        10,
        json!({
            "require_approval": true,
            "forbidden_parameters": ["force"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // Should be RequireApproval, not Deny, because require_approval is checked first
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn require_approval_false_does_not_trigger() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        "no-approval",
        10,
        json!({
            "require_approval": false
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // require_approval=false → falls through to forbidden/required checks → nothing triggered → Allow
    assert!(matches!(verdict, Verdict::Allow));
}

// ═══════════════════════════════════════════
// MULTIPLE FORBIDDEN PARAMETERS
// ═══════════════════════════════════════════

#[test]
fn first_forbidden_param_triggers_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action(
        "db",
        "query",
        json!({
            "drop": true,
            "truncate": true,
            "select": "users"
        }),
    );
    let policies = vec![conditional_policy(
        "db:*",
        "no-destructive",
        10,
        json!({
            "forbidden_parameters": ["drop", "truncate"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match verdict {
        Verdict::Deny { reason } => {
            // Should mention whichever is found first in the iteration
            assert!(
                reason.contains("drop") || reason.contains("truncate"),
                "reason should mention a forbidden param: {}",
                reason
            );
        }
        other => panic!("expected Deny, got {:?}", other),
    }
}

#[test]
fn multiple_required_params_all_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action(
        "api",
        "call",
        json!({
            "auth_token": "abc",
            "request_id": "123",
            "user_id": "u1"
        }),
    );
    let policies = vec![conditional_policy(
        "api:*",
        "need-all",
        10,
        json!({
            "required_parameters": ["auth_token", "request_id", "user_id"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn multiple_required_params_one_missing_denies() {
    let engine = PolicyEngine::new(false);
    let action = make_action(
        "api",
        "call",
        json!({
            "auth_token": "abc",
            "user_id": "u1"
            // missing request_id
        }),
    );
    let policies = vec![conditional_policy(
        "api:*",
        "need-all",
        10,
        json!({
            "required_parameters": ["auth_token", "request_id", "user_id"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match verdict {
        Verdict::Deny { reason } => {
            assert!(reason.contains("request_id"), "reason: {}", reason);
        }
        other => panic!("expected Deny, got {:?}", other),
    }
}

// ═══════════════════════════════════════════
// CONDITIONAL + UNCONDITIONAL POLICY LAYERING
// ═══════════════════════════════════════════

#[test]
fn conditional_at_higher_priority_overrides_unconditional_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({"force": true}));
    let policies = vec![
        allow_policy("*", 1),
        conditional_policy(
            "shell:*",
            "check-force",
            100,
            json!({
                "forbidden_parameters": ["force"]
            }),
        ),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn unconditional_deny_at_higher_priority_overrides_conditional_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![
        deny_policy("bash:*", 1000),
        conditional_policy(
            "bash:*",
            "maybe-allow",
            1,
            json!({
                // This would allow, but deny at higher priority wins
            }),
        ),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════
// EDGE CASES IN CONDITION JSON STRUCTURE
// ════════════════════════════════════════════

#[test]
fn empty_conditions_object_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy("*", "empty-conditions", 10, json!({}))];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn empty_forbidden_array_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"anything": true}));
    let policies = vec![conditional_policy(
        "*",
        "no-forbidden",
        10,
        json!({
            "forbidden_parameters": []
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn empty_required_array_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        "no-required",
        10,
        json!({
            "required_parameters": []
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn non_array_forbidden_parameters_is_silently_ignored() {
    // If forbidden_parameters is not an array, `as_array()` returns None  skip
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"force": true}));
    let policies = vec![conditional_policy(
        "*",
        "bad-forbidden",
        10,
        json!({
            "forbidden_parameters": "force"  // string, not array
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // Silently ignored → no denial → Allow
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn non_string_items_in_forbidden_array_ignored() {
    // Items that aren't strings (as_str() returns None) should be skipped
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"123": "val"}));
    let policies = vec![conditional_policy(
        "*",
        "mixed-forbidden",
        10,
        json!({
            "forbidden_parameters": [123, null, true, "123"]
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // Only "123" (the string) should be checked, and action has key "123" → Deny
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn require_approval_non_bool_is_treated_as_false() {
    // as_bool().unwrap_or(false) → non-bool → false
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        "bad-approval",
        10,
        json!({
            "require_approval": "yes"  // string, not bool
        }),
    )];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}
