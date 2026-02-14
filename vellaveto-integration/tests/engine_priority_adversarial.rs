//! Adversarial tests targeting policy priority resolution, tie-breaking,
//! and edge cases in the engine's sort-and-match algorithm.

use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn make_action_with_params(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn allow_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
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

// ════════════════════════════════════════════════
// NEGATIVE PRIORITIES
// ═════════════════════════════════════════════════

#[test]
fn negative_priority_is_lower_than_zero() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    // Deny at priority 0 should win over Allow at priority -100
    let policies = vec![
        allow_policy("*", "low-allow", -100),
        deny_policy("*", "zero-deny", 0),
    ];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {} // correct: higher priority wins
        other => panic!(
            "Expected Deny from priority 0 over Allow at -100, got {:?}",
            other
        ),
    }
}

#[test]
fn negative_priority_allow_vs_negative_deny_same_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    // At equal priority, Deny should override Allow (deny-overrides tie-breaking)
    let policies = vec![
        allow_policy("*", "neg-allow", -50),
        deny_policy("*", "neg-deny", -50),
    ];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {} // deny-overrides at same priority
        other => panic!("Expected Deny at tied negative priority, got {:?}", other),
    }
}

#[test]
fn i32_min_priority_policy_still_evaluated() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    let policies = vec![allow_policy("*", "min-priority", i32::MIN)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        verdict,
        Verdict::Allow,
        "Policy at i32::MIN should still match"
    );
}

#[test]
fn i32_max_priority_policy_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    let policies = vec![
        allow_policy("*", "max-priority-allow", i32::MAX),
        deny_policy("*", "almost-max-deny", i32::MAX - 1),
    ];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        verdict,
        Verdict::Allow,
        "i32::MAX priority should beat i32::MAX-1"
    );
}

// ═════════════════════════════════════════════════
// TIE-BREAKING: Deny overrides Allow at same priority
// ═════════════════════════════════════════════════

#[test]
fn deny_overrides_allow_at_same_priority_with_many_policies() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    // Flood with allows at priority 50, single deny at priority 50
    let mut policies: Vec<Policy> = (0..10)
        .map(|i| allow_policy("*", &format!("allow-{}", i), 50))
        .collect();
    policies.push(deny_policy("*", "single-deny", 50));

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {} // deny-overrides
        other => panic!(
            "Deny should override many Allows at same priority, got {:?}",
            other
        ),
    }
}

// ════════════════════════════════════════════════
// PATTERN MATCHING EDGE CASES
// ════════════════════════════════════════════════

#[test]
fn empty_tool_and_function_match_exact_empty_id() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "");

    // Policy with empty id — does it match empty tool?
    let policies = vec![allow_policy("", "empty-id", 10)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // Empty pattern "" should match empty tool "" via exact match
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn wildcard_star_matches_empty_strings() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "");

    let policies = vec![deny_policy("*", "wildcard-deny", 10)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {} // * matches everything
        other => panic!("Wildcard '*' should match empty tool/func, got {:?}", other),
    }
}

#[test]
fn colon_in_id_splits_tool_and_function_patterns() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "execute");

    let policies = vec![deny_policy("bash:execute", "exact-match", 10)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {}
        other => panic!(
            "'bash:execute' should match action bash/execute, got {:?}",
            other
        ),
    }
}

#[test]
fn colon_id_with_wildcard_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "delete");

    let policies = vec![deny_policy("file:*", "file-any-func", 10)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {}
        other => panic!("'file:*' should match file/delete, got {:?}", other),
    }
}

#[test]
fn colon_id_with_wildcard_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("network", "upload");

    let policies = vec![deny_policy("*:upload", "any-tool-upload", 10)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {}
        other => panic!("'*:upload' should match network/upload, got {:?}", other),
    }
}

#[test]
fn prefix_wildcard_in_tool_pattern() {
    let engine = PolicyEngine::new(false);
    let action = make_action("my_bash_tool", "run");

    // "my_bash*" should match "my_bash_tool" (suffix wildcard)
    let policies = vec![deny_policy("my_bash*", "prefix-match", 10)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {}
        other => panic!("'my_bash*' should match 'my_bash_tool', got {:?}", other),
    }
}

#[test]
fn suffix_wildcard_in_tool_pattern() {
    let engine = PolicyEngine::new(false);
    let action = make_action("super_bash", "run");

    // "*bash" should match "super_bash" (prefix wildcard / suffix match)
    let policies = vec![deny_policy("*bash", "suffix-match", 10)];

    // Actually wait: match_pattern("*bash", "super_bash") strips leading * and checks ends_with("bash")
    // "super_bash" ends with "bash"? Yes!
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {}
        other => panic!("'*bash' should match 'super_bash', got {:?}", other),
    }
}

#[test]
fn no_match_falls_through_to_default_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("unknown_tool", "unknown_func");

    // Policies exist but none match this action
    let policies = vec![
        allow_policy("file:read", "file-read-only", 10),
        deny_policy("bash:*", "bash-deny", 100),
    ];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("No matching policy"),
                "Default deny reason should mention 'No matching policy', got: {}",
                reason
            );
        }
        other => panic!(
            "Unmatched action should be denied by default, got {:?}",
            other
        ),
    }
}

// ════════════════════════════════════════════════
// CONDITIONAL POLICY EDGE CASES
// ═════════════════════════════════════════════════

#[test]
fn conditional_with_empty_conditions_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    // Conditional with no recognized condition keys should fall through to Allow
    let policies = vec![conditional_policy("*", "empty-conditions", 10, json!({}))];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        verdict,
        Verdict::Allow,
        "Empty conditions should result in Allow"
    );
}

#[test]
fn conditional_forbidden_param_present_denies() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params("tool", "func", json!({"force": true, "path": "/tmp"}));

    let policies = vec![conditional_policy(
        "*",
        "forbid-force",
        10,
        json!({
            "forbidden_parameters": ["force"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("force"),
                "Reason should mention forbidden param 'force': {}",
                reason
            );
        }
        other => panic!("Forbidden parameter present should deny, got {:?}", other),
    }
}

#[test]
fn conditional_forbidden_param_absent_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params("tool", "func", json!({"path": "/tmp"}));

    let policies = vec![conditional_policy(
        "*",
        "forbid-force",
        10,
        json!({
            "forbidden_parameters": ["force"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn conditional_required_param_missing_denies() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params("tool", "func", json!({"path": "/tmp"}));

    let policies = vec![conditional_policy(
        "*",
        "require-auth",
        10,
        json!({
            "required_parameters": ["auth_token"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("auth_token"),
                "Should mention missing param: {}",
                reason
            );
        }
        other => panic!("Missing required param should deny, got {:?}", other),
    }
}

#[test]
fn conditional_required_param_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params("tool", "func", json!({"auth_token": "abc123"}));

    let policies = vec![conditional_policy(
        "*",
        "require-auth",
        10,
        json!({
            "required_parameters": ["auth_token"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn conditional_require_approval_takes_precedence_over_forbidden() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params("tool", "func", json!({"force": true}));

    // Both require_approval and forbidden_parameters are set.
    // The code checks require_approval FIRST, so it should return RequireApproval
    // even though a forbidden parameter is present.
    let policies = vec![conditional_policy(
        "*",
        "approval-and-forbidden",
        10,
        json!({
            "require_approval": true,
            "forbidden_parameters": ["force"]
        }),
    )];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::RequireApproval { .. } => {} // require_approval checked first
        other => panic!(
            "require_approval should take precedence over forbidden_parameters, got {:?}",
            other
        ),
    }
}

// ═════════════════════════════════════════════════
// MANY POLICIES: ensure O(n) scan works correctly
// ════════════════════════════════════════════════

#[test]
fn hundred_policies_correct_verdict_from_highest_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("target", "func");

    let mut policies: Vec<Policy> = (0..99)
        .map(|i| allow_policy(&format!("other_{}:*", i), &format!("filler-{}", i), i))
        .collect();

    // The one deny policy at highest priority targeting our action
    policies.push(deny_policy("target:*", "the-deny", 1000));

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {}
        other => panic!(
            "Highest priority deny among 100 policies should win, got {:?}",
            other
        ),
    }
}

#[test]
fn policies_evaluated_in_priority_order_not_insertion_order() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    // Insert low priority first, high priority last
    let policies = vec![
        allow_policy("*", "low", 1),
        allow_policy("*", "mid", 50),
        deny_policy("*", "high", 100),
    ];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    match &verdict {
        Verdict::Deny { .. } => {} // priority 100 deny wins
        other => panic!(
            "Highest priority should win regardless of insertion order, got {:?}",
            other
        ),
    }

    // Now reverse: high priority first, but it's Allow
    let policies2 = vec![
        allow_policy("*", "high-allow", 100),
        deny_policy("*", "low-deny", 1),
    ];

    let verdict2 = engine.evaluate_action(&action, &policies2).unwrap();
    assert_eq!(verdict2, Verdict::Allow, "Higher priority Allow should win");
}

// ════════════════════════════════════════════════
// STRICT MODE: verify it doesn't change basic behavior
// ═════════════════════════════════════════════════

#[test]
fn strict_mode_empty_policies_still_denies() {
    let engine = PolicyEngine::new(true);
    let action = make_action("tool", "func");

    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    match &verdict {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("No policies"),
                "Strict mode empty policies reason: {}",
                reason
            );
        }
        other => panic!("Strict mode empty policies should deny, got {:?}", other),
    }
}

#[test]
fn strict_and_non_strict_agree_on_simple_policies() {
    let strict = PolicyEngine::new(true);
    let relaxed = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![allow_policy("file:read", "allow-read", 10)];

    let v1 = strict.evaluate_action(&action, &policies).unwrap();
    let v2 = relaxed.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        v1, v2,
        "Strict and non-strict should agree on simple policies"
    );
}
