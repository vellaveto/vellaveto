//! Tests for empty-string edge cases in policy ID patterns and action fields.
//! The engine uses split_once(':') and match_pattern() — empty strings
//! create subtle edge cases in pattern matching.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

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

// ═══════════════════════════════════════
// EMPTY POLICY ID
// ═══════════════════════════════════════

/// Empty policy ID: not "*", no colon. match_pattern("", tool) does exact match.
/// An action with empty tool would match; non-empty tool would not.
#[test]
fn empty_policy_id_matches_empty_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "anything");

    let policies = vec![allow_policy("", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Empty ID should match empty tool"
    );
}

#[test]
fn empty_policy_id_does_not_match_nonempty_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");

    let policies = vec![allow_policy("", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // No match → default deny
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Empty ID should not match non-empty tool, falling through to default deny"
    );
}

// ══════════════════════════════════════
// EMPTY COLON-SEPARATED PARTS
// ═══════════════════════════════════════

/// Policy ID ":" splits into ("", ""). Matches action with empty tool AND empty function.
#[test]
fn colon_only_id_matches_empty_tool_and_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "");

    let policies = vec![allow_policy(":", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "':' should match empty tool and empty function"
    );
}

/// Policy ID ":" should NOT match non-empty tool.
#[test]
fn colon_only_id_does_not_match_nonempty_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "");

    let policies = vec![allow_policy(":", 10)];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "':' means empty:empty, should not match 'bash:\"\"'"
    );
}

/// Policy ID ":func" — empty tool pattern, "func" function pattern.
/// split_once(":") gives ("", "func").
/// match_pattern("", action.tool) is exact match — only empty tool matches.
#[test]
fn empty_tool_pattern_with_function() {
    let engine = PolicyEngine::new(false);

    // Action with empty tool
    let action_empty = make_action("", "func");
    let policies = vec![allow_policy(":func", 10)];
    let v = engine.evaluate_action(&action_empty, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "':func' should match empty tool + 'func' function"
    );

    // Action with non-empty tool
    let action_bash = make_action("bash", "func");
    let v = engine.evaluate_action(&action_bash, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "':func' should NOT match non-empty tool"
    );
}

/// Policy ID "tool:" — "tool" pattern, empty function pattern.
/// split_once(":") gives ("tool", "").
/// match_pattern("", action.function) is exact match — only empty function matches.
#[test]
fn tool_pattern_with_empty_function() {
    let engine = PolicyEngine::new(false);

    let action_match = make_action("tool", "");
    let policies = vec![allow_policy("tool:", 10)];
    let v = engine.evaluate_action(&action_match, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "'tool:' should match 'tool' tool + empty function"
    );

    let action_no_match = make_action("tool", "exec");
    let v = engine.evaluate_action(&action_no_match, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "'tool:' should NOT match non-empty function"
    );
}

// ══════════════════════════════════════
// WILDCARD WITH EMPTY PARTS
// ═══════════════════════════════════════

/// Policy ID "*:" — wildcard tool, empty function.
/// Matches any tool but only empty function.
#[test]
fn wildcard_tool_empty_function() {
    let engine = PolicyEngine::new(false);

    let action_empty_func = make_action("bash", "");
    let policies = vec![allow_policy("*:", 10)];
    let v = engine
        .evaluate_action(&action_empty_func, &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "'*:' should match any tool + empty function"
    );

    let action_nonempty_func = make_action("bash", "exec");
    let v = engine
        .evaluate_action(&action_nonempty_func, &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "'*:' should NOT match non-empty function"
    );
}

/// Policy ID ":*" — empty tool, wildcard function.
/// Matches only empty tool but any function.
#[test]
fn empty_tool_wildcard_function() {
    let engine = PolicyEngine::new(false);

    let action_empty_tool = make_action("", "anything");
    let policies = vec![allow_policy(":*", 10)];
    let v = engine
        .evaluate_action(&action_empty_tool, &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "':*' should match empty tool + any function"
    );

    let action_nonempty_tool = make_action("bash", "anything");
    let v = engine
        .evaluate_action(&action_nonempty_tool, &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "':*' should NOT match non-empty tool"
    );
}

// ═══════════════════════════════════════
// WILDCARD PREFIX/SUFFIX WITH EMPTY
// ═══════════════════════════════════════

/// Pattern "*" (standalone wildcard) is handled as special case, always matches.
/// But what about pattern "*" as a tool part in "tool:*"?
/// split_once gives ("tool", "*"), and match_pattern("*", func) → true always.
/// This is the standard behavior. Testing with empty function:
#[test]
fn suffix_wildcard_matches_empty_string() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "");

    // "tool:*" should match tool="tool", function="" because "*" matches all
    let policies = vec![allow_policy("tool:*", 10)];
    let v = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "'tool:*' should match even when function is empty"
    );
}

/// Pattern "prefix*" with empty value: match_pattern("prefix*", "")
/// strip_suffix("*") gives "prefix", then "".starts_with("prefix") → false.
#[test]
fn prefix_wildcard_does_not_match_empty() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "func");

    // "bash*" as tool pattern: match_pattern("bash*", "") → "".starts_with("bash") → false
    let policies = vec![allow_policy("bash*:func", 10)];
    let v = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "'bash*' should not match empty tool"
    );
}

/// Pattern "*suffix" with value that IS the suffix.
/// strip_prefix("*") gives "suffix", then "suffix".ends_with("suffix")  true.
#[test]
fn suffix_match_works_when_value_equals_suffix() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "func");

    let policies = vec![allow_policy("*bash:*func", 10)];
    let v = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "'*bash' should match 'bash' since 'bash'.ends_with('bash')"
    );
}
