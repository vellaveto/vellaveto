//! Tests for prefix and suffix wildcard matching in policy IDs.
//! Source: sentinel-engine/src/lib.rs match_pattern method.
//! - "*suffix" matches values ending with suffix (strip_prefix('*'))
//! - "prefix*" matches values starting with prefix (strip_suffix('*'))
//! - "*" matches everything
//! - anything else is exact match

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: json!({}),
    }
}

fn allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("allow-{}", id),
        policy_type: PolicyType::Allow,
        priority,
    }
}

fn deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny-{}", id),
        policy_type: PolicyType::Deny,
        priority,
    }
}

// ═══════════════════════════════
// SUFFIX WILDCARD ON TOOL (no colon — ID matches tool only)
// ════════════════════════════════

/// "file*" as policy ID (no colon) matches tool "file_system" via starts_with("file").
#[test]
fn suffix_wildcard_tool_only_matches_prefix() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file_system", "read");
    let policies = vec![allow_policy("file*", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "file* should match file_system"
    );
}

/// "file*" does NOT match tool "my_file" (doesn't start with "file").
#[test]
fn suffix_wildcard_tool_only_rejects_non_prefix() {
    let engine = PolicyEngine::new(false);
    let action = make_action("my_file", "read");
    let policies = vec![allow_policy("file*", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "file* should NOT match my_file — falls through to default deny"
    );
}

// ═══════════════════════════════
// PREFIX WILDCARD ON TOOL (no colon)
// ════════════════════════════════

/// "*system" as policy ID (no colon) matches tool "file_system" via ends_with("system").
#[test]
fn prefix_wildcard_tool_only_matches_suffix() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file_system", "read");
    let policies = vec![allow_policy("*system", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "*system should match file_system"
    );
}

/// "*system" does NOT match tool "system_admin" (doesn't end with "system").
#[test]
fn prefix_wildcard_tool_only_rejects_non_suffix() {
    let engine = PolicyEngine::new(false);
    let action = make_action("system_admin", "read");
    let policies = vec![allow_policy("*system", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "*system should NOT match system_admin"
    );
}

// ════════════════════════════════
// COLON-SEPARATED WITH WILDCARDS ON BOTH SIDES
// ════════════════════════════════

/// "file*:*read" — tool starts with "file", function ends with "read".
#[test]
fn suffix_wildcard_tool_prefix_wildcard_func() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file_system", "batch_read");
    let policies = vec![allow_policy("file*:*read", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "file* matches file_system, *read matches batch_read"
    );
}

/// "file*:*read" does NOT match tool "file_system" function "write".
#[test]
fn suffix_wildcard_tool_prefix_wildcard_func_rejects_wrong_func() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file_system", "write");
    let policies = vec![allow_policy("file*:*read", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "*read should NOT match write"
    );
}

// ═══════════════════════════════
// EXACT MATCH (NO WILDCARD, NO COLON)
// ═══════════════════════════════

/// "bash" matches tool "bash" exactly.
#[test]
fn exact_match_tool_only() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![deny_policy("bash", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "bash matches bash exactly"
    );
}

/// "bash" does NOT match tool "bash_shell" — exact match, not prefix.
#[test]
fn exact_match_rejects_longer_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash_shell", "exec");
    let policies = vec![deny_policy("bash", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // "bash" without wildcard is exact match — doesn't match "bash_shell"
    assert!(
        matches!(result, Verdict::Deny { reason } if reason == "No matching policy"),
        "Exact 'bash' should not match 'bash_shell'"
    );
}

// ════════════════════════════════
// WILDCARD "*" ALONE MATCHES EVERYTHING
// ═══════════════════════════════

/// Single "*" policy matches any tool/function combination.
#[test]
fn star_alone_matches_everything() {
    let engine = PolicyEngine::new(false);
    let actions = vec![
        make_action("", ""),
        make_action("x", "y"),
        make_action("very_long_tool_name", "very_long_function_name"),
    ];
    let policies = vec![allow_policy("*", 10)];
    for action in &actions {
        let result = engine.evaluate_action(action, &policies).unwrap();
        assert!(
            matches!(result, Verdict::Allow),
            "* should match action {:?}",
            action
        );
    }
}

// ═══════════════════════════════
// EDGE: WILDCARD IS THE ENTIRE PATTERN PART
// ═══════════════════════════════

/// "*:*" — both tool and function are wildcards via colon split.
/// split_once(':') on "*:*" → ("*", "*"), both match anything.
#[test]
fn star_colon_star_matches_everything() {
    let engine = PolicyEngine::new(false);
    let action = make_action("anything", "whatever");
    let policies = vec![allow_policy("*:*", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// "tool:*" — exact tool match, wildcard function.
#[test]
fn exact_tool_wildcard_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "any_function");
    let policies = vec![allow_policy("file:*", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// "*:exec" — wildcard tool, exact function.
#[test]
fn wildcard_tool_exact_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any_tool", "exec");
    let policies = vec![allow_policy("*:exec", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// "*:exec" does NOT match function "execute" (exact match, not prefix).
#[test]
fn wildcard_tool_exact_function_rejects_different_func() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "execute");
    let policies = vec![allow_policy("*:exec", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "*:exec should not match function 'execute'"
    );
}
