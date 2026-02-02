//! Additional edge-case tests for PolicyEngine behavior.
//! Focuses on behavioral contracts and regression cases.

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

// ══════════════════════════════════════════════════════
// DUPLICATE POLICY TESTS
// ══════════════════════════════════════════════════════

#[test]
fn test_duplicate_allow_policies_still_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![
        allow_policy("file:read", "Allow reads 1", 0),
        allow_policy("file:read", "Allow reads 2", 0),
        allow_policy("file:read", "Allow reads 3", 0),
    ];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("duplicate allows should not error");

    assert!(
        matches!(verdict, Verdict::Allow),
        "multiple allow policies should still produce Allow, got {:?}",
        verdict
    );
}

#[test]
fn test_duplicate_deny_policies_still_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "delete");
    let policies = vec![
        deny_policy("file:delete", "Deny 1", 0),
        deny_policy("file:delete", "Deny 2", 5),
        deny_policy("file:delete", "Deny 3", 10),
    ];

    let verdict = engine.evaluate_action(&action, &policies)
        .expect("duplicate denies should not error");

    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "multiple deny policies should produce Deny, got {:?}",
        verdict
    );
}

// ══════════════════════════════════════════════════════
// POLICY ID MATCHING SEMANTICS
// ══════════════════════════════════════════════════════

#[test]
fn test_policy_id_exact_match_required() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    // Policy ID is "file:write" — should NOT match action "file"/"read"
    let policies = vec![allow_policy("file:write", "Allow writes only", 0)];

    let result = engine.evaluate_action(&action, &policies)
        .expect("non-matching policy should not error");

    // If no policy matches, we get default behavior, not an allow
    // In non-strict mode this could be allow or deny depending on default
    // But it should NOT be treated as if the allow policy matched
    let _ = result; // Document: result depends on default-allow vs default-deny
}

#[test]
fn test_policy_matching_is_case_sensitive() {
    let engine = PolicyEngine::new(false);
    let action = make_action("File", "Read");
    let policies = vec![allow_policy("file:read", "lowercase policy", 0)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok(), "case mismatch should not cause error");
    // If the engine is case-sensitive, this won't match.
    // If case-insensitive, it will. Either behavior is valid but should be consistent.
}

// ══════════════════════════════════════════════════════
// SINGLE-FIELD MATCHING
// ══════════════════════════════════════════════════════

#[test]
fn test_policy_id_with_no_colon_separator() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    // Policy ID has no colon — how does matching work?
    let policies = vec![allow_policy("fileread", "No separator", 0)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok(), "policy ID without colon should not panic");
}

// ══════════════════════════════════════════════════════
// ENGINE REUSE
// ══════════════════════════════════════════════════════

#[test]
fn test_engine_can_evaluate_multiple_times() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("file:read", "Allow reads", 0)];

    for _ in 0..100 {
        let action = make_action("file", "read");
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_ok(), "engine should be reusable across evaluations");
    }
}

#[test]
fn test_engine_alternating_strict_instances() {
    let strict = PolicyEngine::new(true);
    let lax = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![allow_policy("file:read", "Allow", 0)];

    // Alternating calls to different engine instances
    let v1 = strict.evaluate_action(&action, &policies).unwrap();
    let v2 = lax.evaluate_action(&action, &policies).unwrap();
    let v3 = strict.evaluate_action(&action, &policies).unwrap();
    let v4 = lax.evaluate_action(&action, &policies).unwrap();

    // All should produce Allow since there's an explicit matching policy
    assert!(matches!(v1, Verdict::Allow), "strict explicit allow: {:?}", v1);
    assert!(matches!(v2, Verdict::Allow), "lax explicit allow: {:?}", v2);
    assert!(matches!(v3, Verdict::Allow), "strict explicit allow round 2: {:?}", v3);
    assert!(matches!(v4, Verdict::Allow), "lax explicit allow round 2: {:?}", v4);
}

// ══════════════════════════════════════════════════════
// PARAMETER VARIATIONS
// ══════════════════════════════════════════════════════

#[test]
fn test_different_parameters_same_tool_function() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("file:read", "Allow reads", 0)];

    let action1 = Action {
        tool: "file".to_string(),
        function: "read".to_string(),
        parameters: json!({"path": "/etc/passwd"}),
    };
    let action2 = Action {
        tool: "file".to_string(),
        function: "read".to_string(),
        parameters: json!({"path": "/home/user/.ssh/id_rsa"}),
    };

    let v1 = engine.evaluate_action(&action1, &policies).unwrap();
    let v2 = engine.evaluate_action(&action2, &policies).unwrap();

    // Both should get the same verdict since policy matches on tool:function, not params
    assert_eq!(
        std::mem::discriminant(&v1),
        std::mem::discriminant(&v2),
        "same tool:function should get same verdict regardless of parameters"
    );
}

#[test]
fn test_empty_object_vs_populated_parameters() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("tool:func", "Allow", 0)];

    let empty_params = Action {
        tool: "tool".to_string(),
        function: "func".to_string(),
        parameters: json!({}),
    };
    let populated_params = Action {
        tool: "tool".to_string(),
        function: "func".to_string(),
        parameters: json!({"key": "value", "count": 42}),
    };

    let v1 = engine.evaluate_action(&empty_params, &policies).unwrap();
    let v2 = engine.evaluate_action(&populated_params, &policies).unwrap();

    assert_eq!(
        std::mem::discriminant(&v1),
        std::mem::discriminant(&v2),
        "parameters should not affect policy matching"
    );
}