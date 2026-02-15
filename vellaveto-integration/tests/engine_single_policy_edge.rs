//! Tests engine behavior with exactly one policy.
//! Isolates matching logic from priority/sorting concerns.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn make_action_with_params(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

// ═══════════════════════════════════
// SINGLE ALLOW POLICY: MATCH VARIATIONS
// ════════════════════════════════════

#[test]
fn single_wildcard_allow_permits_any_action() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "allow-all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    // Various action shapes
    let actions = vec![
        make_action("a", "b"),
        make_action("", ""),
        make_action("tool:with:colons", "func"),
        make_action("🔥", "日本語"),
    ];

    for action in &actions {
        let v = engine.evaluate_action(action, &policies).unwrap();
        assert_eq!(
            v,
            Verdict::Allow,
            "Wildcard allow should permit {:?}",
            action
        );
    }
}

#[test]
fn single_wildcard_deny_blocks_any_action() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "deny-all".to_string(),
        policy_type: PolicyType::Deny,
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    let v = engine
        .evaluate_action(&make_action("anything", "at_all"), &policies)
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

#[test]
fn single_exact_match_allows_only_matching_action() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "file:read".to_string(),
        name: "allow-file-read".to_string(),
        policy_type: PolicyType::Allow,
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    // Matching action
    let v = engine
        .evaluate_action(&make_action("file", "read"), &policies)
        .unwrap();
    assert_eq!(v, Verdict::Allow);

    // Non-matching actions fall through to default deny
    let v = engine
        .evaluate_action(&make_action("file", "write"), &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Non-matching function should deny"
    );

    let v = engine
        .evaluate_action(&make_action("shell", "read"), &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Non-matching tool should deny"
    );
}

#[test]
fn single_tool_only_id_matches_by_tool() {
    // Policy ID without colon: matches on tool name only
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "bash".to_string(),
        name: "allow-bash".to_string(),
        policy_type: PolicyType::Allow,
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    let v = engine
        .evaluate_action(&make_action("bash", "anything"), &policies)
        .unwrap();
    assert_eq!(
        v,
        Verdict::Allow,
        "Tool-only ID should match regardless of function"
    );

    let v = engine
        .evaluate_action(&make_action("bash", "execute"), &policies)
        .unwrap();
    assert_eq!(v, Verdict::Allow);

    let v = engine
        .evaluate_action(&make_action("shell", "bash"), &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Should not match different tool"
    );
}

// ═══════════════════════════════════
// SINGLE CONDITIONAL POLICY EDGE CASES
// ═══════════════════════════════════

#[test]
fn single_conditional_with_empty_conditions_allows() {
    // Empty conditions object: no require_approval, no forbidden, no required
    // → falls through to Allow
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "empty-conditions".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({}),
        },
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    let v = engine
        .evaluate_action(&make_action("any", "thing"), &policies)
        .unwrap();
    assert_eq!(v, Verdict::Allow, "Empty conditions should allow");
}

#[test]
fn single_conditional_with_require_approval_false_allows() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "approval-false".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"require_approval": false}),
        },
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    let v = engine
        .evaluate_action(&make_action("any", "thing"), &policies)
        .unwrap();
    assert_eq!(v, Verdict::Allow, "require_approval=false should allow");
}

#[test]
fn single_conditional_forbidden_param_present_denies() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "forbid-secret".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": ["secret"]}),
        },
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    let action = make_action_with_params("tool", "func", json!({"secret": "value", "other": "ok"}));
    let v = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Forbidden param present should deny"
    );
}

#[test]
fn single_conditional_forbidden_param_absent_allows() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "forbid-secret".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": ["secret"]}),
        },
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    let action = make_action_with_params("tool", "func", json!({"public": "data"}));
    let v = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(v, Verdict::Allow, "No forbidden param should allow");
}

#[test]
fn single_conditional_required_param_missing_denies() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "require-token".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"required_parameters": ["auth_token"]}),
        },
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    let action = make_action_with_params("tool", "func", json!({"other": "stuff"}));
    let v = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Missing required param should deny"
    );
}

#[test]
fn single_conditional_required_param_present_allows() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "require-token".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"required_parameters": ["auth_token"]}),
        },
        priority: 0,
        path_rules: None,
        network_rules: None,
    }];

    let action = make_action_with_params("tool", "func", json!({"auth_token": "abc123"}));
    let v = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(v, Verdict::Allow, "Present required param should allow");
}

// ═══════════════════════════════════
// SINGLE POLICY WITH EXTREME PRIORITY
// ═══════════════════════════════════

#[test]
fn single_policy_at_i32_min_still_matches() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "min-priority".to_string(),
        policy_type: PolicyType::Allow,
        priority: i32::MIN,
        path_rules: None,
        network_rules: None,
    }];

    let v = engine
        .evaluate_action(&make_action("t", "f"), &policies)
        .unwrap();
    assert_eq!(
        v,
        Verdict::Allow,
        "Single policy should match regardless of priority value"
    );
}

#[test]
fn single_policy_at_i32_max_still_matches() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "max-priority".to_string(),
        policy_type: PolicyType::Deny,
        priority: i32::MAX,
        path_rules: None,
        network_rules: None,
    }];

    let v = engine
        .evaluate_action(&make_action("t", "f"), &policies)
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

// ════════════════════════════════════
// SUFFIX AND PREFIX WILDCARDS (SINGLE POLICY)
// ═══════════════════════════════════

#[test]
fn suffix_wildcard_on_tool_part() {
    let engine = PolicyEngine::new(false);
    // ID "file*:read"  tool pattern "file*", function pattern "read"
    let policies = vec![Policy {
        id: "file*:read".to_string(),
        name: "file-prefix-read".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];

    let v = engine
        .evaluate_action(&make_action("file_system", "read"), &policies)
        .unwrap();
    assert_eq!(v, Verdict::Allow, "file_system starts with 'file'");

    let v = engine
        .evaluate_action(&make_action("filesystem", "read"), &policies)
        .unwrap();
    assert_eq!(v, Verdict::Allow);

    let v = engine
        .evaluate_action(&make_action("file", "read"), &policies)
        .unwrap();
    assert_eq!(v, Verdict::Allow, "Exact prefix match");

    let v = engine
        .evaluate_action(&make_action("file_system", "write"), &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Function doesn't match 'read'"
    );

    let v = engine
        .evaluate_action(&make_action("myfile", "read"), &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "'myfile' doesn't start with 'file'"
    );
}

#[test]
fn prefix_wildcard_on_function_part() {
    let engine = PolicyEngine::new(false);
    // ID "shell:*execute" — tool pattern "shell", function pattern "*execute"
    let policies = vec![Policy {
        id: "shell:*execute".to_string(),
        name: "shell-execute-suffix".to_string(),
        policy_type: PolicyType::Deny,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];

    let v = engine
        .evaluate_action(&make_action("shell", "execute"), &policies)
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }), "Exact suffix match");

    let v = engine
        .evaluate_action(&make_action("shell", "safe_execute"), &policies)
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }), "Ends with 'execute'");

    // "execute_cmd" does NOT end with "execute", so the *execute pattern won't match.
    // Engine is fail-closed: no match → Deny with "No matching policy" (not the policy's own deny).
    let v = engine
        .evaluate_action(&make_action("shell", "execute_cmd"), &policies)
        .unwrap();
    match &v {
        Verdict::Deny { reason } => assert!(
            reason.contains("No matching policy"),
            "Should be default deny, got: {}",
            reason
        ),
        other => panic!("Expected Deny, got {:?}", other),
    }
}
