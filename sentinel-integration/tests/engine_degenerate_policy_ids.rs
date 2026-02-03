//! Tests for degenerate policy IDs that stress the split_once(':') parser.
//! Specifically targets IDs that are just ":", just colons, or have
//! unusual whitespace/unicode around the colon.

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

fn _deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny-{}", id),
        policy_type: PolicyType::Deny,
        priority,
    }
}

// ═══════════════════════════════════
// COLON-ONLY POLICY ID: ":"
// ═══════════════════════════════════

/// Policy ID ":" → split_once(':') → ("", "").
/// This matches actions with empty tool AND empty function.
#[test]
fn colon_only_id_matches_empty_tool_and_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "");
    let policies = vec![allow_policy(":", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// Policy ID ":" should NOT match a non-empty tool.
#[test]
fn colon_only_id_does_not_match_nonempty_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![allow_policy(":", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // ":" splits to ("", "") which does exact match: "" != "bash"
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Colon-only ID should not match non-empty tool"
    );
}

/// Policy ID ":" with empty tool but non-empty function.
#[test]
fn colon_only_id_does_not_match_nonempty_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "exec");
    let policies = vec![allow_policy(":", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // split(":", ":") → ("", "") — match_pattern("", "exec") is "" == "exec" → false
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Colon-only ID should not match non-empty function"
    );
}

// ═══════════════════════════════════
// DOUBLE COLON "::"
// ═══════════════════════════════════

/// "::" → split_once(':') → ("", ":"), then qualifier strip → func="".
/// Tool pattern is "", function pattern is "" (second colon treated as qualifier separator).
#[test]
fn double_colon_id_tool_empty_function_colon() {
    let engine = PolicyEngine::new(false);
    // Action with empty tool and function literally ":"
    let action = make_action("", ":");
    let policies = vec![allow_policy("::", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // match_pattern("", "") → exact match "" == "" → true
    // match_pattern("", ":") → exact match "" != ":" → false
    // Policy doesn't match → Deny
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// "::" should NOT match action with normal tool/function.
#[test]
fn double_colon_id_does_not_match_normal_action() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![allow_policy("::", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ════════════════════════════════════
// TRIPLE COLON ":::"
// ═══════════════════════════════════

/// ":::" → split_once(':') → ("", "::"), then qualifier strip → func="".
/// Tool pattern is "", function pattern is "" (second colon treated as qualifier separator).
#[test]
fn triple_colon_id_matches_action_with_double_colon_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "::");
    let policies = vec![allow_policy(":::", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // func_pat="" doesn't match function="::" → Deny
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ═══════════════════════════════════
// WHITESPACE AROUND COLONS
// ═══════════════════════════════════

/// " : " → split_once(':') → (" ", " "). Matches action with tool=" " function=" ".
#[test]
fn whitespace_colon_whitespace_matches_space_action() {
    let engine = PolicyEngine::new(false);
    let action = make_action(" ", " ");
    let policies = vec![allow_policy(" : ", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// Verify whitespace colon doesn't accidentally match trimmed values.
#[test]
fn whitespace_colon_does_not_match_trimmed_action() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![allow_policy(" bash : exec ", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // " bash " != "bash", so no match → default deny
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Engine should not trim whitespace from patterns"
    );
}

// ═══════════════════════════════════
// WILDCARD ADJACENT TO COLON
// ═══════════════════════════════════

/// "*:" → split_once(':') → ("*", ""). Tool matches anything, function must be "".
#[test]
fn star_colon_matches_any_tool_empty_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("anything", "");
    let policies = vec![allow_policy("*:", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

#[test]
fn star_colon_does_not_match_nonempty_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![allow_policy("*:", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // Tool matches (wildcard), but function pattern "" != "exec"
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Function pattern '' should not match 'exec'"
    );
}

/// ":*" → split_once(':') → ("", "*"). Tool must be "", function matches anything.
#[test]
fn colon_star_matches_empty_tool_any_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "anything");
    let policies = vec![allow_policy(":*", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

#[test]
fn colon_star_does_not_match_nonempty_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![allow_policy(":*", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // Tool pattern "" does exact match: "" != "bash"
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ═══════════════════════════════════
// UNICODE IN POLICY IDS
// ═══════════════════════════════════

#[test]
fn unicode_tool_and_function_exact_match() {
    let engine = PolicyEngine::new(false);
    let action = make_action("工具", "関数");
    let policies = vec![allow_policy("工具:関数", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

#[test]
fn emoji_in_policy_id_exact_match() {
    let engine = PolicyEngine::new(false);
    let action = make_action("🔧", "🔨");
    let policies = vec![allow_policy("🔧:🔨", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

#[test]
fn wildcard_with_unicode_suffix() {
    let engine = PolicyEngine::new(false);
    // Pattern "*工具" should match any tool ending with "工具"
    let action = make_action("安全工具", "func");
    let policies = vec![allow_policy("*工具:func", 10)];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}
