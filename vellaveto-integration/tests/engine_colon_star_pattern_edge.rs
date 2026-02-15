//! Tests for policy IDs with unusual colon + wildcard combinations.
//! Specifically targets "*:" and ":*" which create empty-string
//! patterns on one side of the colon split.

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

// ════════════════════════════════
// POLICY ID "*:" → split_once gives ("*", "")
// Tool part: "*" matches everything
// Function part: "" matches only empty function
// ═══════════════════════════════

/// "*:" should match actions with ANY tool but ONLY empty function.
#[test]
fn star_colon_matches_any_tool_empty_function() {
    let engine = PolicyEngine::new(false);
    // Tool = "bash", function = ""  should match "*:"
    let action = make_action("bash", "");
    let policies = vec![allow_policy("*:", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Policy '*:' should match tool='bash', function='', got {:?}",
        result
    );
}

/// "*:" should NOT match actions with non-empty function.
#[test]
fn star_colon_does_not_match_nonempty_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![allow_policy("*:", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert_eq!(reason, "No matching policy");
        }
        other => panic!(
            "Policy '*:' should NOT match function='exec', got {:?}",
            other
        ),
    }
}

// ════════════════════════════════
// POLICY ID ":*" → split_once gives ("", "*")
// Tool part: "" matches only empty tool
// Function part: "*" matches everything
// ════════════════════════════════

/// ":*" should match actions with empty tool and ANY function.
#[test]
fn colon_star_matches_empty_tool_any_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "anything");
    let policies = vec![allow_policy(":*", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Policy ':*' should match tool='', function='anything', got {:?}",
        result
    );
}

/// ":*" should NOT match actions with non-empty tool.
#[test]
fn colon_star_does_not_match_nonempty_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![allow_policy(":*", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert_eq!(reason, "No matching policy");
        }
        other => panic!("Policy ':*' should NOT match tool='bash', got {:?}", other),
    }
}

// ════════════════════════════════
// POLICY ID "*:*" → split_once gives ("*", "*")
// Both parts match everything  universal match
// ════════════════════════════════

/// "*:*" matches ANY action (both wildcards match everything).
#[test]
fn star_colon_star_matches_everything() {
    let engine = PolicyEngine::new(false);
    let actions = vec![
        make_action("bash", "exec"),
        make_action("", ""),
        make_action("file_system", "read_file"),
        make_action("a", "b"),
    ];
    let policies = vec![allow_policy("*:*", 10)];

    for action in &actions {
        let result = engine.evaluate_action(action, &policies).unwrap();
        assert!(
            matches!(result, Verdict::Allow),
            "Policy '*:*' should match {:?}, got {:?}",
            action,
            result
        );
    }
}

/// "*:*" vs "*"  both are universal matchers. Priority decides.
/// "*" (no colon) at higher priority should win.
#[test]
fn star_colon_star_vs_star_priority_decides() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    // "*" Allow at 100, "*:*" Deny at 50
    let policies = vec![allow_policy("*", 100), deny_policy("*:*", 50)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "'*' at priority 100 should beat '*:*' at priority 50, got {:?}",
        result
    );

    // Flip: "*:*" Deny at 100, "*" Allow at 50
    let policies = vec![allow_policy("*", 50), deny_policy("*:*", 100)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "'*:*' Deny at priority 100 should beat '*' Allow at 50, got {:?}",
        result
    );
}
