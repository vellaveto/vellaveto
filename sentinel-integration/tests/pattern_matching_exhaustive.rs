//! Exhaustive tests for the engine's pattern-matching and policy-ID parsing logic.
//! Targets `matches_action` and `match_pattern` through the public `evaluate_action` API.

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

// ═══════════════════════════════════════════
// COLON-SEPARATED ID PARSING
// ════════════════════════════════════════════

#[test]
fn id_with_colon_matches_tool_and_function_exactly() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![allow_policy("file:read", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn id_with_colon_does_not_match_wrong_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "write");
    // Only matches file:read, not file:write  no match → default deny
    let policies = vec![allow_policy("file:read", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn id_with_colon_does_not_match_wrong_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("network", "read");
    let policies = vec![allow_policy("file:read", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn id_with_wildcard_function_matches_any_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "delete");
    let policies = vec![deny_policy("file:*", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn id_with_wildcard_tool_matches_any_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("network", "upload");
    let policies = vec![deny_policy("*:upload", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn id_with_both_wildcards_matches_everything() {
    let engine = PolicyEngine::new(false);
    let action = make_action("anything", "whatever");
    let policies = vec![allow_policy("*:*", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// ═══════════════════════════════════════════
// NON-COLON ID (tool-only matching)
// ═══════════════════════════════════════════

#[test]
fn id_without_colon_matches_tool_name() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "execute");
    let policies = vec![deny_policy("bash", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn id_without_colon_does_not_match_different_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![deny_policy("bash", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // No match → default deny (different reason)
    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::Deny { reason } => {
            assert!(reason.contains("No matching policy"), "got: {}", reason);
        }
        other => panic!("expected Deny, got {:?}", other),
    }
}

// ═══════════════════════════════════════════
// PREFIX WILDCARD PATTERNS
// ═══════════════════════════════════════════

#[test]
fn prefix_wildcard_in_tool_part_of_colon_id() {
    let engine = PolicyEngine::new(false);
    // Policy id "file*:read" should match tool starting with "file"
    let action = make_action("file_system", "read");
    let policies = vec![allow_policy("file*:read", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn prefix_wildcard_in_function_part_of_colon_id() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "execute_command");
    let policies = vec![deny_policy("shell:execute*", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn suffix_wildcard_in_tool_part() {
    let engine = PolicyEngine::new(false);
    // "*system" should match tools ending in "system"
    let action = make_action("file_system", "read");
    let policies = vec![allow_policy("*system:read", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn suffix_wildcard_does_not_match_partial() {
    let engine = PolicyEngine::new(false);
    // "*system" should NOT match "system_v2" (it matches suffix, not prefix)
    let action = make_action("system_v2", "read");
    let policies = vec![allow_policy("*system:read", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════
// MULTIPLE COLONS IN ID
// ═══════════════════════════════════════════

#[test]
fn id_with_multiple_colons_splits_on_first() {
    // split_once(':') on "a:b:c" gives ("a", "b:c")
    // So tool pattern is "a", function pattern is "b:c"
    // This means it matches tool="a" and function="b:c" exactly
    let engine = PolicyEngine::new(false);
    let action = make_action("a", "b:c");
    let policies = vec![allow_policy("a:b:c", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn id_with_multiple_colons_does_not_match_plain_function() {
    let engine = PolicyEngine::new(false);
    // Action function is just "b", but policy expects "b:c"
    let action = make_action("a", "b");
    let policies = vec![allow_policy("a:b:c", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════
// EMPTY STRING EDGE CASES
// ═══════════════════════════════════════════

#[test]
fn empty_policy_id_matches_empty_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "func");
    // ID "" without colon → matches tool "" exactly
    let policies = vec![allow_policy("", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn empty_tool_pattern_in_colon_id_matches_empty_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "read");
    // ":read" splits to ("", "read")
    let policies = vec![allow_policy(":read", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn empty_function_in_colon_id_matches_empty_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "");
    // "file:" splits to ("file", "")
    let policies = vec![allow_policy("file:", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// ═══════════════════════════════════════════
// MULTI-POLICY PATTERN INTERACTION
// ════════════════════════════════════════════

#[test]
fn specific_pattern_overrides_wildcard_by_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "delete");
    let policies = vec![
        allow_policy("*", 1),               // Low priority: allow all
        deny_policy("file:delete", 100),     // High priority: deny this specific action
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn wildcard_at_higher_priority_beats_specific() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "delete");
    let policies = vec![
        allow_policy("*", 1000),              // High priority: allow everything
        deny_policy("file:delete", 1),        // Low priority: deny specific
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn first_match_wins_among_equal_priority_different_patterns() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    // Both match, same priority. Deny should win due to tie-breaking.
    let policies = vec![
        allow_policy("file:*", 50),
        deny_policy("*:read", 50),
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // At equal priority, Deny sorts before Allow (deny-overrides)
    assert!(matches!(verdict, Verdict::Deny { .. }));
}