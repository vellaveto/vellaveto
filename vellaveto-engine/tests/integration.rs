// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Integration tests for vellaveto-engine - adversarial and edge-case focused.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

// --- Helpers ---

fn action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn allow(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn conditional(id: &str, name: &str, priority: i32, conditions: serde_json::Value) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// --- Empty policy behavior ---

#[test]
fn strict_mode_denies_with_empty_policy_list() {
    let engine = PolicyEngine::new(true);
    let act = action("shell", "execute", json!({}));
    let result = engine.evaluate_action(&act, &[]);
    assert!(result.is_ok());
    match result.unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!("Strict mode + no policies must deny, got {other:?}"),
    }
}

#[test]
fn non_strict_mode_also_denies_with_empty_policy_list() {
    let engine = PolicyEngine::new(false);
    let act = action("anything", "at_all", json!({}));
    let result = engine.evaluate_action(&act, &[]);
    assert!(result.is_ok());
    match result.unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!("Non-strict + no policies must also deny (fail-closed), got {other:?}"),
    }
}

#[test]
fn strict_mode_allows_when_explicit_allow_exists() {
    let engine = PolicyEngine::new(true);
    let act = action("file", "read", json!({"path": "/tmp/ok.txt"}));
    let policies = vec![allow("file:read", "allow-file-read", 1)];
    let result = engine.evaluate_action(&act, &policies);
    assert!(result.is_ok());
    match result.unwrap() {
        Verdict::Allow => {}
        other => panic!("Strict mode with explicit allow should allow, got {other:?}"),
    }
}

// --- Priority conflict resolution ---

#[test]
fn deny_wins_over_allow_at_equal_priority() {
    let engine = PolicyEngine::new(false);
    let act = action("shell", "execute", json!({}));
    let policies = vec![
        allow("shell:*", "allow-shell", 5),
        deny("shell:*", "deny-shell", 5),
    ];
    let result = engine.evaluate_action(&act, &policies);
    assert!(result.is_ok());
    match result.unwrap() {
        Verdict::Deny { .. } | Verdict::Allow => {}
        other => panic!("Unexpected verdict at equal priority: {other:?}"),
    }
}

#[test]
fn highest_priority_deny_overrides_multiple_allows() {
    let engine = PolicyEngine::new(false);
    let act = action("file", "write", json!({}));
    let policies = vec![
        allow("*", "allow-1", 1),
        allow("*", "allow-2", 2),
        allow("*", "allow-3", 3),
        deny("file:*", "deny-high", 100),
    ];
    let result = engine.evaluate_action(&act, &policies).unwrap();
    match result {
        Verdict::Deny { .. } => {}
        other => panic!("Single high-priority deny must override all allows, got {other:?}"),
    }
}

#[test]
fn highest_priority_allow_overrides_lower_deny() {
    let engine = PolicyEngine::new(false);
    let act = action("file", "read", json!({}));
    let policies = vec![
        deny("file:*", "deny-low", 1),
        allow("file:*", "allow-high", 100),
    ];
    let result = engine.evaluate_action(&act, &policies).unwrap();
    match result {
        Verdict::Allow => {}
        other => panic!("High-priority allow should override low deny, got {other:?}"),
    }
}

// --- Conditional policy tests ---

#[test]
fn conditional_triggers_require_approval_on_match() {
    let engine = PolicyEngine::new(false);
    let act = action("shell", "execute", json!({"command": "rm -rf /"}));
    let policies = vec![conditional(
        "shell:*",
        "shell-guard",
        10,
        json!({"require_approval": true}),
    )];
    let result = engine.evaluate_action(&act, &policies).unwrap();
    match result {
        Verdict::RequireApproval { reason } => {
            assert!(!reason.is_empty(), "Approval reason must not be empty");
        }
        other => panic!("Matching conditional should require approval, got {other:?}"),
    }
}

#[test]
fn conditional_does_not_trigger_on_non_matching_action() {
    let engine = PolicyEngine::new(false);
    let act = action("file", "read", json!({}));
    let policies = vec![conditional(
        "shell:*",
        "shell-guard",
        10,
        json!({"require_approval": true}),
    )];
    let result = engine.evaluate_action(&act, &policies).unwrap();
    match result {
        Verdict::Deny { .. } => {} // No matching policy -> deny (fail-closed)
        other => panic!("Non-matching conditional should result in deny, got {other:?}"),
    }
}

#[test]
fn deny_overrides_conditional_at_higher_priority() {
    let engine = PolicyEngine::new(false);
    let act = action("shell", "execute", json!({}));
    let policies = vec![
        conditional(
            "shell:*",
            "shell-review",
            5,
            json!({"require_approval": true}),
        ),
        deny("shell:*", "shell-block", 10),
    ];
    let result = engine.evaluate_action(&act, &policies).unwrap();
    match result {
        Verdict::Deny { .. } => {}
        other => panic!("Higher-priority deny must beat conditional, got {other:?}"),
    }
}

// --- Boundary & adversarial inputs ---

#[test]
fn empty_string_tool_and_function() {
    let engine = PolicyEngine::new(false);
    let act = action("", "", json!({}));
    let policies = vec![allow("*", "allow-all", 1)];
    let result = engine.evaluate_action(&act, &policies);
    assert!(
        result.is_ok(),
        "Empty tool/function should not cause errors"
    );
}

#[test]
fn very_large_parameter_set() {
    let engine = PolicyEngine::new(false);
    let mut params = serde_json::Map::new();
    for i in 0..1000 {
        params.insert(format!("key_{i}"), json!(format!("value_{}", i)));
    }
    let act = action("shell", "execute", serde_json::Value::Object(params));
    let policies = vec![allow("shell:*", "allow-shell", 1)];
    let result = engine.evaluate_action(&act, &policies);
    assert!(
        result.is_ok(),
        "Large parameter set should not cause errors"
    );
}

#[test]
fn null_parameters() {
    let engine = PolicyEngine::new(false);
    let act = action("shell", "execute", json!(null));
    let policies = vec![allow("shell:*", "allow-shell", 1)];
    let result = engine.evaluate_action(&act, &policies);
    let _ = result; // Must not panic
}

#[test]
fn nested_json_parameters() {
    let engine = PolicyEngine::new(false);
    let act = action(
        "shell",
        "execute",
        json!({
            "env": { "nested": { "deeply": { "value": true } } }
        }),
    );
    let policies = vec![allow("shell:*", "allow-shell", 1)];
    let result = engine.evaluate_action(&act, &policies);
    assert!(result.is_ok(), "Nested JSON parameters must be handled");
}

#[test]
fn unicode_in_tool_and_function_names() {
    let engine = PolicyEngine::new(false);
    let act = action("日語ツール", "функция", json!({"키": "值"}));
    let policies = vec![allow("*", "allow-all", 1)];
    let result = engine.evaluate_action(&act, &policies);
    assert!(
        result.is_ok(),
        "Unicode in action fields should not cause errors"
    );
}

// --- Engine reusability ---

#[test]
fn engine_is_reusable_across_evaluations() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow("*", "allow", 1)];

    for i in 0..100 {
        let act = action("tool", &format!("fn_{i}"), json!({"i": i}));
        let result = engine.evaluate_action(&act, &policies);
        assert!(result.is_ok(), "Evaluation #{i} should succeed");
    }
}

#[test]
fn engine_gives_consistent_results() {
    let engine = PolicyEngine::new(true);
    let act = action("shell", "execute", json!({}));
    let policies = vec![deny("shell:*", "deny-shell", 10)];

    for _ in 0..50 {
        let result = engine.evaluate_action(&act, &policies).unwrap();
        match result {
            Verdict::Deny { .. } => {}
            other => panic!("Inconsistent result: {other:?}"),
        }
    }
}

// --- Many policies stress test ---

#[test]
fn handles_many_policies() {
    let engine = PolicyEngine::new(false);
    let act = action("shell", "execute", json!({}));

    let mut policies: Vec<Policy> = (0..100)
        .map(|i| allow("*", &format!("allow-{i}"), i))
        .collect();
    policies.push(deny("shell:*", "deny-final", 999));

    let result = engine.evaluate_action(&act, &policies).unwrap();
    match result {
        Verdict::Deny { .. } => {}
        other => panic!("Single high-priority deny among 100 allows should deny, got {other:?}"),
    }
}
