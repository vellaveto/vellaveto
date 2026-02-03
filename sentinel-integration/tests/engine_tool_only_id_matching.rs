//! Tests for policy IDs without a colon separator.
//! When a policy ID has no colon, it is matched against action.tool only
//! (action.function is irrelevant).
//! Source: matches_action — the else branch of split_once(':')

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn allow(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("allow-{}", id),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny-{}", id),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════
// EXACT TOOL NAME MATCH (NO COLON)
// ═════════════════════════════

/// Policy ID "bash" (no colon) matches any action with tool=="bash",
/// regardless of function name.
#[test]
fn tool_only_id_matches_any_function() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow("bash", 10)];

    // Different functions, same tool  all should match
    for func in &["execute", "run", "eval", "", "anything"] {
        let result = engine
            .evaluate_action(&action("bash", func), &policies)
            .unwrap();
        assert_eq!(
            result,
            Verdict::Allow,
            "Tool-only ID 'bash' should match function '{}'",
            func
        );
    }
}

/// Policy ID "bash" does NOT match tool "zsh".
#[test]
fn tool_only_id_rejects_different_tool() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow("bash", 10)];
    let result = engine
        .evaluate_action(&action("zsh", "execute"), &policies)
        .unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Tool 'zsh' should not match ID 'bash'"
    );
}

// ═══════════════════════════
// TOOL-ONLY SUFFIX WILDCARD
// ═══════════════════════════

/// Policy ID "*sh" (suffix wildcard, no colon) matches tools ending in "sh".
#[test]
fn tool_only_suffix_wildcard_matches() {
    let engine = PolicyEngine::new(false);
    let policies = vec![deny("*sh", 10)];

    // "bash" ends with "sh"
    let result = engine
        .evaluate_action(&action("bash", "x"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));

    // "zsh" ends with "sh"
    let result = engine
        .evaluate_action(&action("zsh", "y"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));

    // "python" does not end with "sh"
    let result = engine
        .evaluate_action(&action("python", "z"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { reason } if reason.contains("No matching")));
}

// ════════════════════════════
// TOOL-ONLY PREFIX WILDCARD
// ════════════════════════════

/// Policy ID "file*" (prefix wildcard, no colon) matches tools starting with "file".
#[test]
fn tool_only_prefix_wildcard_matches() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow("file*", 10)];

    let result = engine
        .evaluate_action(&action("file_system", "read"), &policies)
        .unwrap();
    assert_eq!(result, Verdict::Allow);

    let result = engine
        .evaluate_action(&action("filesystem", "read"), &policies)
        .unwrap();
    assert_eq!(result, Verdict::Allow);

    let result = engine
        .evaluate_action(&action("file", "read"), &policies)
        .unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Exact prefix match should also work"
    );

    // "afile" starts with "a", not "file"
    let result = engine
        .evaluate_action(&action("afile", "read"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ════════════════════════════
// TOOL-ONLY WITH PRIORITY INTERACTION
// ════════════════════════════

/// Two tool-only policies: allow "bash" at priority 10, deny "bash" at priority 20.
/// Deny wins because higher priority.
#[test]
fn tool_only_deny_higher_priority_wins() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow("bash", 10), deny("bash", 20)];
    let result = engine
        .evaluate_action(&action("bash", "exec"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

/// Two tool-only policies at same priority: deny overrides allow.
#[test]
fn tool_only_same_priority_deny_wins() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow("bash", 10), deny("bash", 10)];
    let result = engine
        .evaluate_action(&action("bash", "exec"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ═══════════════════════════
// TOOL-ONLY VS COLON-SEPARATED POLICIES
// ════════════════════════════

/// A colon-separated policy "bash:execute" at higher priority should beat
/// a tool-only policy "bash" at lower priority.
#[test]
fn colon_policy_higher_priority_beats_tool_only() {
    let engine = PolicyEngine::new(false);
    let policies = vec![
        deny("bash", 10),          // tool-only, matches bash:*
        allow("bash:execute", 20), // colon-separated, matches bash:execute
    ];
    let result = engine
        .evaluate_action(&action("bash", "execute"), &policies)
        .unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Higher-priority colon policy should win"
    );
}

/// A tool-only policy at higher priority beats a colon-separated policy at lower.
#[test]
fn tool_only_higher_priority_beats_colon_policy() {
    let engine = PolicyEngine::new(false);
    let policies = vec![
        deny("bash", 20),          // tool-only at priority 20
        allow("bash:execute", 10), // colon at priority 10
    ];
    let result = engine
        .evaluate_action(&action("bash", "execute"), &policies)
        .unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Higher-priority tool-only should win"
    );
}
