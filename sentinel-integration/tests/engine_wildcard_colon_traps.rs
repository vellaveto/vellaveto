//! Adversarial tests targeting the engine's policy ID parsing.
//! The engine uses `split_once(':')` to separate tool:function patterns.
//! These tests try to break that parsing with unusual colon placements.

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

// ═══════════════════════════════════════
// MULTIPLE COLONS IN POLICY ID
// ═══════════════════════════════════════

/// split_once(":") on "a:b:c" gives ("a", "b:c").
/// So the function pattern is "b:c" — does this match function "b:c" exactly?
#[test]
fn id_with_two_colons_treats_rest_as_function_pattern() {
    let engine = PolicyEngine::new(false);
    // Policy ID "tool:func:extra" → split_once → tool_pat="tool", func_pat="func:extra"
    let policies = vec![allow_policy("tool:func:extra", 10)];

    // Action with function literally "func:extra" should match
    let action = make_action("tool", "func:extra");
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "function 'func:extra' should match func_pat 'func:extra', got {:?}",
        result
    );

    // Action with function "func" should NOT match
    let action2 = make_action("tool", "func");
    let result2 = engine.evaluate_action(&action2, &policies).unwrap();
    assert!(
        matches!(result2, Verdict::Deny { .. }),
        "function 'func' should NOT match func_pat 'func:extra', got {:?}",
        result2
    );
}

/// Leading colon: ":function"  split_once gives ("", "function").
/// Tool pattern is "" — does this match tool ""? Or everything?
#[test]
fn id_with_leading_colon_has_empty_tool_pattern() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy(":read", 10)];

    // Tool "" should match tool_pat "" (exact match)
    let action_empty_tool = make_action("", "read");
    let result = engine.evaluate_action(&action_empty_tool, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "empty tool should match empty tool pattern from ':read', got {:?}",
        result
    );

    // Non-empty tool should NOT match tool_pat ""
    let action_nonempty = make_action("file", "read");
    let result2 = engine.evaluate_action(&action_nonempty, &policies).unwrap();
    assert!(
        matches!(result2, Verdict::Deny { .. }),
        "tool 'file' should NOT match empty tool pattern from ':read', got {:?}",
        result2
    );
}

/// Trailing colon: "tool:" → split_once gives ("tool", "").
/// Function pattern is "" — matches only empty function name.
#[test]
fn id_with_trailing_colon_has_empty_function_pattern() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("file:", 10)];

    // Empty function should match
    let action = make_action("file", "");
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "empty function should match empty function pattern from 'file:', got {:?}",
        result
    );

    // Non-empty function should NOT match
    let action2 = make_action("file", "read");
    let result2 = engine.evaluate_action(&action2, &policies).unwrap();
    assert!(
        matches!(result2, Verdict::Deny { .. }),
        "function 'read' should NOT match empty function pattern from 'file:', got {:?}",
        result2
    );
}

/// Just a colon: ":" → split_once gives ("", "").
/// Both patterns are empty  matches only (tool="", function="").
#[test]
fn id_is_just_colon_matches_only_empty_tool_and_function() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy(":", 10)];

    let action_both_empty = make_action("", "");
    let result = engine.evaluate_action(&action_both_empty, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "both-empty action should match ':', got {:?}",
        result
    );

    let action_nonempty = make_action("bash", "exec");
    let result2 = engine.evaluate_action(&action_nonempty, &policies).unwrap();
    assert!(
        matches!(result2, Verdict::Deny { .. }),
        "non-empty action should NOT match ':', got {:?}",
        result2
    );
}

/// Colon with wildcards: "*:*" should match everything (same as "*").
#[test]
fn star_colon_star_matches_everything() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("*:*", 10)];

    for (tool, func) in &[("a", "b"), ("", ""), ("bash", "execute"), ("x", "")] {
        let action = make_action(tool, func);
        let result = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(result, Verdict::Allow),
            "'*:*' should match ({}, {}), got {:?}",
            tool, func, result
        );
    }
}

/// ID without colon is matched against tool only.
/// Verify that a bare tool name doesn't accidentally match the function.
#[test]
fn bare_id_without_colon_matches_tool_only_not_function() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("execute", 10)];

    // Tool "execute" matches
    let action = make_action("execute", "anything");
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "tool 'execute' should match bare id 'execute', got {:?}",
        result
    );

    // Tool "bash" with function "execute" does NOT match
    let action2 = make_action("bash", "execute");
    let result2 = engine.evaluate_action(&action2, &policies).unwrap();
    assert!(
        matches!(result2, Verdict::Deny { .. }),
        "bare id 'execute' should NOT match tool 'bash' even though function is 'execute', got {:?}",
        result2
    );
}

/// Wildcard suffix in tool pattern with colon: "bash*:exec*"
#[test]
fn wildcard_suffix_in_both_tool_and_function_via_colon() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("bash*:exec*", 10)];

    let action = make_action("bash_v2", "execute_cmd");
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "'bash*:exec*' should match (bash_v2, execute_cmd), got {:?}",
        result
    );

    let action2 = make_action("bash_v2", "read_file");
    let result2 = engine.evaluate_action(&action2, &policies).unwrap();
    assert!(
        matches!(result2, Verdict::Deny { .. }),
        "'bash*:exec*' should NOT match function 'read_file', got {:?}",
        result2
    );
}

/// Prefix wildcard: "*sh:*cute"
#[test]
fn prefix_wildcard_in_both_tool_and_function_via_colon() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("*sh:*cute", 10)];

    let action = make_action("bash", "execute");
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "'*sh:*cute' should match (bash, execute), got {:?}",
        result
    );

    let action2 = make_action("python", "execute");
    let result2 = engine.evaluate_action(&action2, &policies).unwrap();
    assert!(
        matches!(result2, Verdict::Deny { .. }),
        "'*sh' should NOT match tool 'python', got {:?}",
        result2
    );
}