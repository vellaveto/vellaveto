//! Adversarial tests that try to BREAK the policy engine's condition evaluation.
//! Focuses on malformed JSON, deeply nested conditions, forbidden parameter matching,
//! and edge cases in the conditional policy pipeline.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn conditional_policy(id: &str, priority: i32, conditions: serde_json::Value) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("cond-{}", id),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
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

// ════════════════════════════════════════════
// MALFORMED JSON IN CONDITIONS
// ════════════════════════════════════════════

#[test]
fn conditions_with_null_value_does_not_crash() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy("*", 10, json!(null))];

    // null conditions: no forbidden/required/require_approval keys → falls through to Allow
    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok(),
        "null conditions should not crash: {:?}",
        result
    );
}

#[test]
fn conditions_with_string_value_does_not_crash() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy("*", 10, json!("not an object"))];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok(),
        "string conditions should not crash: {:?}",
        result
    );
}

#[test]
fn conditions_with_array_value_does_not_crash() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy("*", 10, json!([1, 2, 3]))];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok(),
        "array conditions should not crash: {:?}",
        result
    );
}

#[test]
fn conditions_with_integer_value_does_not_crash() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy("*", 10, json!(42))];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok(),
        "integer conditions should not crash: {:?}",
        result
    );
}

#[test]
fn conditions_with_boolean_value_does_not_crash() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy("*", 10, json!(true))];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok(),
        "boolean conditions should not crash: {:?}",
        result
    );
}

#[test]
fn conditions_with_empty_object_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy("*", 10, json!({}))];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(result, Verdict::Allow, "empty conditions should allow");
}

// ═══════════════════════════════════════════
// DEPTH BOMB: CONDITIONS NESTED >10 LEVELS
// ═══════════════════════════════════════════

/// Build a JSON value nested to the given depth.
fn nested_json(depth: usize) -> serde_json::Value {
    let mut val = json!("leaf");
    for _ in 0..depth {
        val = json!({"d": val});
    }
    val
}

#[test]
fn condition_depth_10_is_accepted() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let conditions = nested_json(10);
    let policies = vec![conditional_policy("*", 10, conditions)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok(), "depth 10 should be accepted: {:?}", result);
}

#[test]
fn condition_depth_11_is_rejected() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let conditions = nested_json(11);
    let policies = vec![conditional_policy("*", 10, conditions)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_err(),
        "depth 11 should be rejected as InvalidCondition"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("nesting depth"),
        "Error should mention nesting depth: {}",
        err_msg
    );
}

#[test]
fn condition_depth_20_is_rejected() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let conditions = nested_json(20);
    let policies = vec![conditional_policy("*", 10, conditions)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err(), "depth 20 should be rejected");
}

#[test]
fn condition_depth_100_is_rejected() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let conditions = nested_json(100);
    let policies = vec![conditional_policy("*", 10, conditions)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err(), "depth 100 must be rejected");
}

/// Array nesting counts as depth too
#[test]
fn condition_depth_via_arrays_11_is_rejected() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    let mut val = json!("leaf");
    for _ in 0..11 {
        val = json!([val]);
    }
    let policies = vec![conditional_policy("*", 10, val)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err(), "depth 11 via arrays should be rejected");
}

/// Mixed object/array nesting
#[test]
fn condition_depth_mixed_object_array_11_is_rejected() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    let mut val = json!("leaf");
    for i in 0..11 {
        if i % 2 == 0 {
            val = json!({"d": val});
        } else {
            val = json!([val]);
        }
    }
    let policies = vec![conditional_policy("*", 10, val)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_err(),
        "depth 11 via mixed nesting should be rejected"
    );
}

// ═══════════════════════════════════════════
// CONDITION SIZE LIMIT (MAX_CONDITIONS_SIZE = 65,536)
// R230-ENG-1: Legacy path now uses canonical MAX_CONDITIONS_SIZE.
// ═══════════════════════════════════════════

#[test]
fn condition_just_under_max_size_is_accepted() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    // Build a flat object with many keys, staying under 65,536 bytes
    let mut obj = serde_json::Map::new();
    // Each key-value pair: "k_XXXX": "v" ~= 12 bytes in JSON
    // 4500 * ~14 = ~63KB (under 65,536)
    for i in 0..4500 {
        obj.insert(format!("k_{:04}", i), json!("v"));
    }
    let conditions = serde_json::Value::Object(obj);
    let size = conditions.to_string().len();
    assert!(
        size < vellaveto_types::MAX_CONDITIONS_SIZE,
        "precondition: size {} should be < {}",
        size,
        vellaveto_types::MAX_CONDITIONS_SIZE,
    );

    let policies = vec![conditional_policy("*", 10, conditions)];
    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok(),
        "conditions under MAX_CONDITIONS_SIZE should be accepted"
    );
}

#[test]
fn condition_over_max_size_is_rejected() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    // Build a flat object that exceeds MAX_CONDITIONS_SIZE (65,536)
    let mut obj = serde_json::Map::new();
    for i in 0..5500 {
        obj.insert(format!("key_{:05}", i), json!("value_padding_data"));
    }
    let conditions = serde_json::Value::Object(obj);
    let size = conditions.to_string().len();
    assert!(
        size > vellaveto_types::MAX_CONDITIONS_SIZE,
        "precondition: size {} should be > {}",
        size,
        vellaveto_types::MAX_CONDITIONS_SIZE,
    );

    let policies = vec![conditional_policy("*", 10, conditions)];
    let result = engine.evaluate_action(&action, &policies);
    assert!(
        result.is_err(),
        "conditions over MAX_CONDITIONS_SIZE should be rejected"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("too large"),
        "Error should mention size: {}",
        err_msg
    );
}

// ═══════════════════════════════════════════
// FORBIDDEN PARAMETERS: MATCHING CASES
// ═══════════════════════════════════════════

#[test]
fn forbidden_parameter_present_causes_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({"force": true, "cmd": "ls"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": ["force"]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match &result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("force"),
                "Reason should name the param: {}",
                reason
            );
            assert!(
                reason.contains("forbidden"),
                "Reason should say forbidden: {}",
                reason
            );
        }
        other => panic!("Expected Deny for forbidden param, got {:?}", other),
    }
}

#[test]
fn forbidden_parameter_absent_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "exec", json!({"cmd": "ls"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": ["force", "delete", "destroy"]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "No forbidden params present → Allow"
    );
}

#[test]
fn multiple_forbidden_params_first_match_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"delete": true, "force": true}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": ["delete", "force"]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match &result {
        Verdict::Deny { reason } => {
            // The engine iterates forbidden_parameters in order; "delete" should trigger first
            assert!(
                reason.contains("delete"),
                "First forbidden param should trigger: {}",
                reason
            );
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

#[test]
fn forbidden_param_with_null_value_still_matches() {
    let engine = PolicyEngine::new(false);
    // The action has the key "secret" but its value is null.
    // `action.parameters.get("secret").is_some()` should still be true.
    let action = make_action("tool", "func", json!({"secret": null}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": ["secret"]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { .. } => {} // correct: key exists even though value is null
        other => panic!(
            "Key 'secret' with null value should still be forbidden, got {:?}",
            other
        ),
    }
}

#[test]
fn forbidden_param_with_empty_string_value_still_matches() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"token": ""}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": ["token"]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Key with empty string value should still be forbidden"
    );
}

// ═══════════════════════════════════════════
// REQUIRED PARAMETERS: MISSING CASES
// ═══════════════════════════════════════════

#[test]
fn required_parameter_missing_causes_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"a": 1}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"required_parameters": ["auth_token"]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match &result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("auth_token"),
                "Should name missing param: {}",
                reason
            );
        }
        other => panic!("Expected Deny for missing required param, got {:?}", other),
    }
}

#[test]
fn required_parameter_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"auth_token": "abc123"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"required_parameters": ["auth_token"]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(result, Verdict::Allow, "Required param present → Allow");
}

#[test]
fn required_parameter_present_as_null_still_satisfies() {
    let engine = PolicyEngine::new(false);
    // `parameters.get("key").is_some()` returns true even if value is null
    let action = make_action("tool", "func", json!({"key": null}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"required_parameters": ["key"]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Null-valued key should satisfy required_parameters"
    );
}

// ═══════════════════════════════════════════
// REQUIRE_APPROVAL INTERACTION WITH FORBIDDEN/REQUIRED
// ═══════════════════════════════════════════

#[test]
fn require_approval_takes_precedence_over_forbidden_params() {
    let engine = PolicyEngine::new(false);
    // Action has a forbidden param AND require_approval is true.
    // The engine checks require_approval FIRST, so it should return RequireApproval.
    let action = make_action("tool", "func", json!({"dangerous": true}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "require_approval": true,
            "forbidden_parameters": ["dangerous"]
        }),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "require_approval should take precedence over forbidden_parameters, got {:?}",
        result
    );
}

#[test]
fn require_approval_false_does_not_trigger() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"require_approval": false}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "require_approval: false should not trigger approval"
    );
}

#[test]
fn require_approval_as_string_fails_closed() {
    // FIND-IMP-013: Non-boolean require_approval fails closed → RequireApproval.
    // `as_bool()` returns None, `unwrap_or(true)` yields true (fail-closed).
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"require_approval": "yes"}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Non-boolean require_approval should fail-closed to RequireApproval, got {:?}",
        result
    );
}

#[test]
fn require_approval_as_integer_fails_closed() {
    // FIND-IMP-013: Non-boolean require_approval fails closed → RequireApproval.
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy("*", 10, json!({"require_approval": 1}))];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Non-boolean require_approval should fail-closed to RequireApproval, got {:?}",
        result
    );
}

// ═══════════════════════════════════════════
// FORBIDDEN_PARAMETERS MALFORMED VALUES
// ═══════════════════════════════════════════

#[test]
fn forbidden_parameters_as_string_instead_of_array_denied_fail_closed() {
    // R231-ENG-3: forbidden_parameters as string (not array) → fail-closed Deny.
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"force": true}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": "force"}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "forbidden_parameters as string should fail-closed (Deny)"
    );
}

#[test]
fn forbidden_parameters_with_non_string_elements_are_skipped() {
    // Array contains integers instead of strings. `param.as_str()` returns None, skip.
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"123": "val"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": [123, true, null]}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Non-string elements in forbidden_parameters should be skipped"
    );
}

#[test]
fn required_parameters_as_object_instead_of_array_denied_fail_closed() {
    // R231-ENG-3: required_parameters as object (not array) → fail-closed Deny.
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"required_parameters": {"key": "value"}}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "required_parameters as object should fail-closed (Deny)"
    );
}

// ═══════════════════════════════════════════
// COMBINED: FORBIDDEN + REQUIRED IN SAME CONDITION
// ═══════════════════════════════════════════

#[test]
fn forbidden_checked_before_required_when_both_present() {
    let engine = PolicyEngine::new(false);
    // Action has forbidden param "bad" AND is missing required param "auth".
    // Engine checks forbidden first (after require_approval), so should deny for "bad".
    let action = make_action("tool", "func", json!({"bad": "x"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "forbidden_parameters": ["bad"],
            "required_parameters": ["auth"]
        }),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match &result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("bad") && reason.contains("forbidden"),
                "Should deny for forbidden param first: {}",
                reason
            );
        }
        other => panic!("Expected Deny for forbidden param, got {:?}", other),
    }
}

#[test]
fn both_forbidden_absent_and_required_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"auth": "token123"}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({
            "forbidden_parameters": ["delete", "destroy"],
            "required_parameters": ["auth"]
        }),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(result, Verdict::Allow);
}

// ══════════════════════════════════════════
// DEEP CONDITION DOES NOT BYPASS MATCHING POLICY
// ═══════════════════════════════════════════

#[test]
fn deep_condition_error_does_not_fall_through_to_lower_priority_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    // High-priority conditional with depth > 10 → should error
    // Low-priority allow as fallback
    let policies = vec![
        conditional_policy("*", 100, nested_json(15)),
        allow_policy("*", 1),
    ];

    let result = engine.evaluate_action(&action, &policies);
    // The engine should error on the first matching policy's conditions,
    // NOT skip it and fall through to the allow.
    assert!(
        result.is_err(),
        "Depth error on highest-priority matching policy should propagate, not fall through"
    );
}

#[test]
fn non_matching_deep_condition_policy_is_skipped() {
    // If the deep condition policy doesn't match the action's tool/function,
    // it should be skipped entirely and the valid policy should apply.
    let engine = PolicyEngine::new(false);
    let action = make_action("safe_tool", "safe_func", json!({}));

    let policies = vec![
        // This one won't match because ID is "dangerous:*" but action is "safe_tool"
        conditional_policy("dangerous:*", 100, nested_json(50)),
        allow_policy("safe_tool:*", 10),
    ];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok(), "Non-matching deep policy should be skipped");
    assert_eq!(result.unwrap(), Verdict::Allow);
}

// ════════════════════════════════════════════
// EMPTY ARRAYS IN CONDITIONS
// ═══════════════════════════════════════════

#[test]
fn empty_forbidden_parameters_array_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"anything": true}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"forbidden_parameters": []}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Empty forbidden array should allow everything"
    );
}

#[test]
fn empty_required_parameters_array_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        10,
        json!({"required_parameters": []}),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(
        result,
        Verdict::Allow,
        "Empty required array should allow everything"
    );
}
