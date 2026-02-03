//! Integration tests for PolicyEngine evaluation logic.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn sample_action(tool: &str, function: &str) -> Action {
    Action::new(
        tool.to_string(),
        function.to_string(),
        json!({"key": "value"}),
    )
}

fn allow_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

#[test]
fn engine_allows_action_with_allow_policy() {
    let engine = PolicyEngine::new(false);
    let action = sample_action("shell", "execute");
    let policies = vec![allow_policy("shell:*", "allow-shell", 1)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok());
    match result.unwrap() {
        Verdict::Allow => {}
        other => panic!("Expected Allow, got {:?}", other),
    }
}

#[test]
fn engine_denies_action_with_deny_policy() {
    let engine = PolicyEngine::new(false);
    let action = sample_action("shell", "execute");
    let policies = vec![deny_policy("shell:*", "deny-shell", 1)];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok());
    match result.unwrap() {
        Verdict::Deny { reason } => {
            assert!(!reason.is_empty(), "Deny verdict should include a reason");
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

#[test]
fn empty_policies_always_deny() {
    // Both strict and non-strict modes deny when no policies exist (fail-closed)
    for strict in [true, false] {
        let engine = PolicyEngine::new(strict);
        let action = sample_action("network", "fetch");
        let policies: Vec<Policy> = vec![];

        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_ok());
        match result.unwrap() {
            Verdict::Deny { .. } => {}
            other => panic!(
                "Empty policies should deny (strict={}), got {:?}",
                strict, other
            ),
        }
    }
}

#[test]
fn higher_priority_policy_wins() {
    let engine = PolicyEngine::new(false);
    let action = sample_action("file", "write");
    let policies = vec![
        allow_policy("*", "allow-all", 1),
        deny_policy("file:*", "deny-file", 10),
    ];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok());
    // Higher priority deny should override lower priority allow
    match result.unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!("Higher-priority deny should win, got {:?}", other),
    }
}

#[test]
fn evaluate_multiple_actions_sequentially() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("file:*", "allow-read", 1)];

    // Engine should be reusable across multiple evaluations
    for i in 0..10 {
        let action = sample_action("file", &format!("read_{}", i));
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_ok(), "Evaluation {} failed unexpectedly", i);
    }
}

#[test]
fn no_matching_policy_denies() {
    let engine = PolicyEngine::new(false);
    let action = sample_action("network", "connect");
    // Policy only matches "file:*", not "network:connect"
    let policies = vec![allow_policy("file:*", "allow-file", 1)];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { .. } => {}
        other => panic!("Non-matching policy should result in deny, got {:?}", other),
    }
}

#[test]
fn wildcard_matches_all() {
    let engine = PolicyEngine::new(false);
    let action = sample_action("anything", "whatever");
    let policies = vec![allow_policy("*", "allow-all", 1)];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}
