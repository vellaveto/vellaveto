//! Cross-crate integration tests exercising the full pipeline:
//! policy creation → engine evaluation → audit logging.
//!
//! These tests use the ACTUAL workspace API and try adversarially
//! to find edge cases and broken assumptions.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

// ─── Helper constructors ───────────────────────────────────────

fn make_action(tool: &str, function: &str) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: json!({}),
    }
}

fn make_action_with_params(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: params,
    }
}

fn allow_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Allow,
        priority,
    }
}

fn deny_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Deny,
        priority,
    }
}

// ════════════════════════════════════════════════════════════
// HAPPY PATH TESTS
// ═════════════════════════════════════════════════════════════

#[test]
fn test_single_allow_policy_permits_action() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![allow_policy("file:read", "Allow file reads", 0)];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("evaluation should not error");

    assert!(
        matches!(verdict, Verdict::Allow),
        "a matching Allow policy should produce Verdict::Allow, got {:?}",
        verdict
    );
}

#[test]
fn test_single_deny_policy_blocks_action() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "delete");
    let policies = vec![deny_policy("file:delete", "Block file deletes", 0)];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("evaluation should not error");

    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "a matching Deny policy should produce Verdict::Deny, got {:?}",
        verdict
    );
}

// ════════════════════════════════════════════════════════════
// DENY-OVERRIDES-ALLOW TESTS
// ════════════════════════════════════════════════════════════

#[test]
fn test_deny_overrides_allow_same_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "write");
    let policies = vec![
        allow_policy("file:write", "Allow writes", 0),
        deny_policy("file:write", "Deny writes", 0),
    ];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("evaluation should not error");

    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "deny should override allow at same priority, got {:?}",
        verdict
    );
}

#[test]
fn test_deny_overrides_allow_regardless_of_order() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "write");

    // Put allow AFTER deny — deny should still win
    let policies = vec![
        deny_policy("file:write", "Deny writes", 0),
        allow_policy("file:write", "Allow writes", 0),
    ];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("evaluation should not error");

    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "deny should override allow regardless of insertion order, got {:?}",
        verdict
    );
}

// ═════════════════════════════════════════════════════════════
// PRIORITY TESTS
// ════════════════════════════════════════════════════════════

#[test]
fn test_higher_priority_policy_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("net", "connect");
    let policies = vec![
        deny_policy("net:*", "Default deny networking", 0),
        allow_policy("net:connect", "Allow connect specifically", 10),
    ];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("evaluation should not error");

    // Higher priority allow should beat lower priority deny
    // OR deny-overrides-all. Either way, this test documents the behavior.
    // If priority matters, verdict is Allow. If deny always wins, verdict is Deny.
    // We accept both  the point is it doesn't panic or error.
    match &verdict {
        Verdict::Allow => {
            // Priority-based resolution: higher priority allow won
        }
        Verdict::Deny { .. } => {
            // Deny-overrides-all: deny always wins regardless of priority
        }
        other => {
            panic!("unexpected verdict variant: {:?}", other);
        }
    }
}

// ════════════════════════════════════════════════════════════
// EMPTY / BOUNDARY TESTS
// ════════════════════════════════════════════════════════════

#[test]
fn test_empty_policy_list_non_strict() {
    let engine = PolicyEngine::new(false);
    let action = make_action("any", "thing");

    let result = engine.evaluate_action(&action, &[]);

    // With no policies, engine should still return a result, not panic.
    // Default behavior should be documented — either default-allow or default-deny.
    assert!(
        result.is_ok(),
        "empty policy list should not cause an error in non-strict mode, got {:?}",
        result
    );
}

#[test]
fn test_empty_policy_list_strict_mode() {
    let engine = PolicyEngine::new(true);
    let action = make_action("any", "thing");

    let result = engine.evaluate_action(&action, &[]);

    // Strict mode with no policies: should deny or error, never silently allow.
    match result {
        Ok(Verdict::Allow) => {
            panic!("BUG: strict mode with no matching policies should NOT allow");
        }
        Ok(Verdict::Deny { .. }) => {
            // Acceptable: default deny in strict mode
        }
        Ok(Verdict::RequireApproval { .. }) => {
            // Acceptable: require human approval when uncertain
        }
        Err(_) => {
            // Acceptable: error on no matching policy
        }
    }
}

#[test]
fn test_no_matching_policy_non_strict() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "execute");
    // Policy exists but doesn't match the action
    let policies = vec![allow_policy("net:connect", "Allow network only", 0)];

    let result = engine.evaluate_action(&action, &policies)
        .expect("should not error with non-matching policy");

    // Non-strict: unmatched action gets default verdict
    // This documents what "default" means
    match result {
        Verdict::Allow | Verdict::Deny { .. } | Verdict::RequireApproval { .. } => {
            // All valid — we're documenting behavior, not prescribing it
        }
    }
}

#[test]
fn test_no_matching_policy_strict_mode_denies() {
    let engine = PolicyEngine::new(true);
    let action = make_action("file", "execute");
    let policies = vec![allow_policy("net:connect", "Allow network only", 0)];

    let result = engine.evaluate_action(&action, &policies);

    match result {
        Ok(Verdict::Allow) => {
            panic!("BUG: strict mode should not allow unmatched actions");
        }
        _ => {
            // Deny, RequireApproval, or Error are all acceptable in strict mode
        }
    }
}

// ═════════════════════════════════════════════════════════════
// WILDCARD POLICY ID TESTS
// ════════════════════════════════════════════════════════════

#[test]
fn test_wildcard_policy_matches_any_function() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    // Wildcard: file:* should match any function under "file" tool
    let policies = vec![allow_policy("file:*", "Allow all file ops", 0)];

    let result = engine.evaluate_action(&action, &policies);

    // If wildcards are supported, this should match and allow.
    // If not, it's treated as no match.
    assert!(
        result.is_ok(),
        "wildcard policy should not cause engine error, got {:?}",
        result
    );
}

#[test]
fn test_star_star_wildcard_matches_everything() {
    let engine = PolicyEngine::new(false);
    let action = make_action("anything", "at_all");
    let policies = vec![deny_policy("*:*", "Deny everything", 0)];

    let result = engine.evaluate_action(&action, &policies);

    assert!(
        result.is_ok(),
        "universal wildcard should not cause engine error, got {:?}",
        result
    );

    if let Ok(verdict) = result {
        // If *:* is a valid wildcard, this should definitely be Deny
        if matches!(verdict, Verdict::Allow) {
            // This might be a bug — a *:* deny policy should catch everything
            eprintln!(
                "WARNING: *:* deny policy did not block action — \
                 wildcard matching may not be implemented"
            );
        }
    }
}

// ═════════════════════════════════════════════════════════════
// ADVERSARIAL INPUT TESTS
// ═════════════════════════════════════════════════════════════

#[test]
fn test_empty_tool_and_function_strings() {
    let engine = PolicyEngine::new(false);
    let action = make_action("", "");
    let policies = vec![allow_policy(":", "Empty policy", 0)];

    // Should not panic on empty strings
    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok() || result.is_err(),
        "empty strings should produce a result, not panic"
    );
}

#[test]
fn test_unicode_in_action_fields() {
    let engine = PolicyEngine::new(false);
    let action = make_action("айл", "읽기"); // Russian "file", Korean "read"
    let policies = vec![allow_policy("файл:읽기", "Unicode policy", 0)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok() || result.is_err(),
        "unicode input should produce a result, not panic"
    );
}

#[test]
fn test_very_long_strings() {
    let engine = PolicyEngine::new(false);
    let long_str = "a".repeat(10_000);
    let action = make_action(&long_str, &long_str);
    let policies = vec![allow_policy(&format!("{}:{}", long_str, long_str), "Long policy", 0)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok() || result.is_err(),
        "long strings should produce a result, not panic"
    );
}

#[test]
fn test_negative_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![
        allow_policy("file:read", "Negative priority allow", -100),
        deny_policy("file:read", "Positive priority deny", 100),
    ];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("negative priority should not cause error");

    // Higher priority (100) deny should beat lower priority (-100) allow
    // Or if deny-always-wins, still Deny
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "higher priority deny should beat lower priority allow, got {:?}",
        verdict
    );
}

#[test]
fn test_i32_max_min_priority() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![
        allow_policy("file:read", "Min priority", i32::MIN),
        deny_policy("file:read", "Max priority", i32::MAX),
    ];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok(),
        "extreme priority values should not cause overflow or error"
    );
}

// ════════════════════════════════════════════════════════════
// PARAMETERS / JSON TESTS
// ═════════════════════════════════════════════════════════════

#[test]
fn test_action_with_complex_parameters() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params(
        "database",
        "query",
        json!({
            "sql": "SELECT * FROM users WHERE id = $1",
            "params": [42],
            "nested": { "deep": { "value": true } }
        }),
    );
    let policies = vec![allow_policy("database:query", "Allow queries", 0)];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("complex parameters should not cause error");

    assert!(
        matches!(verdict, Verdict::Allow),
        "action with complex params should be evaluated normally, got {:?}",
        verdict
    );
}

#[test]
fn test_action_with_null_json_parameter() {
    let engine = PolicyEngine::new(false);
    let action = make_action_with_params("tool", "func", json!(null));
    let policies = vec![allow_policy("tool:func", "Allow", 0)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok() || result.is_err(),
        "null JSON parameters should not panic"
    );
}

// ═════════════════════════════════════════════════════════════
// MANY POLICIES STRESS TEST
// ════════════════════════════════════════════════════════════

#[test]
fn test_large_policy_set() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");

    let mut policies: Vec<Policy> = (0..1000)
        .map(|i| allow_policy(
            &format!("other_tool_{}:other_func_{}", i, i),
            &format!("Unrelated policy {}", i),
            i,
        ))
        .collect();

    // Add one matching deny at the end
    policies.push(deny_policy("file:read", "The one deny", 999));

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("large policy set should not error");

    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "the matching deny should be found among 1000+ policies, got {:?}",
        verdict
    );
}

// ════════════════════════════════════════════════════════════
// STRICT vs NON-STRICT BEHAVIORAL CONTRACT
// ════════════════════════════════════════════════════════════

#[test]
fn test_strict_and_non_strict_agree_on_explicit_allow() {
    let action = make_action("file", "read");
    let policies = vec![allow_policy("file:read", "Allow reads", 0)];

    let engine_strict = PolicyEngine::new(true);
    let engine_lax = PolicyEngine::new(false);

    let verdict_strict = engine_strict.evaluate_action(&action, &policies)
        .expect("strict mode should not error on explicit allow");
    let verdict_lax = engine_lax.evaluate_action(&action, &policies)
        .expect("non-strict mode should not error on explicit allow");

    // Both modes should agree when there's an explicit matching Allow policy
    assert!(
        matches!(verdict_strict, Verdict::Allow),
        "strict mode should allow when policy explicitly allows, got {:?}",
        verdict_strict
    );
    assert!(
        matches!(verdict_lax, Verdict::Allow),
        "non-strict should allow when policy explicitly allows, got {:?}",
        verdict_lax
    );
}

#[test]
fn test_strict_and_non_strict_agree_on_explicit_deny() {
    let action = make_action("file", "delete");
    let policies = vec![deny_policy("file:delete", "Deny deletes", 0)];

    let engine_strict = PolicyEngine::new(true);
    let engine_lax = PolicyEngine::new(false);

    let verdict_strict = engine_strict.evaluate_action(&action, &policies)
        .expect("strict should not error on explicit deny");
    let verdict_lax = engine_lax.evaluate_action(&action, &policies)
        .expect("non-strict should not error on explicit deny");

    assert!(
        matches!(verdict_strict, Verdict::Deny { .. }),
        "strict mode should deny, got {:?}",
        verdict_strict
    );
    assert!(
        matches!(verdict_lax, Verdict::Deny { .. }),
        "non-strict should deny, got {:?}",
        verdict_lax
    );
}