//! Integration tests for conditional policy evaluation.

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn conditional_policy(
    id: &str,
    name: &str,
    priority: i32,
    conditions: serde_json::Value,
) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

#[test]
fn conditional_policy_requires_approval() {
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "shell".to_string(),
        "execute".to_string(),
        json!({"command": "rm -rf /"}),
    );
    let policies = vec![conditional_policy(
        "shell:*",
        "dangerous-commands",
        10,
        json!({
            "require_approval": true
        }),
    )];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok());
    match result.unwrap() {
        Verdict::RequireApproval { reason } => {
            assert!(
                !reason.is_empty(),
                "RequireApproval should include a reason"
            );
        }
        other => panic!(
            "Conditional policy with require_approval should require approval, got {:?}",
            other
        ),
    }
}

#[test]
fn conditional_policy_with_non_matching_action() {
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "file".to_string(),
        "read".to_string(),
        json!({"path": "/tmp/safe.txt"}),
    );
    let policies = vec![conditional_policy(
        "shell:*",
        "shell-guard",
        10,
        json!({
            "require_approval": true
        }),
    )];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok());
    // A conditional policy for "shell:*" shouldn't affect a "file:read" action
    match result.unwrap() {
        Verdict::Deny { .. } => {} // No matching policy -> deny (fail-closed)
        other => panic!(
            "Non-matching conditional should result in deny (no match), got {:?}",
            other
        ),
    }
}

#[test]
fn mixed_policies_conditional_and_deny() {
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "shell".to_string(),
        "execute".to_string(),
        json!({"command": "ls"}),
    );

    let policies = vec![
        conditional_policy(
            "shell:*",
            "shell-review",
            5,
            json!({"require_approval": true}),
        ),
        Policy {
            id: "shell:*".to_string(),
            name: "deny-all-shell".to_string(),
            policy_type: PolicyType::Deny,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
    ];

    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok());
    // Higher-priority Deny should beat lower-priority Conditional
    match result.unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!(
            "Higher-priority Deny should override Conditional, got {:?}",
            other
        ),
    }
}

#[test]
fn conditional_with_forbidden_parameters() {
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "shell".to_string(),
        "execute".to_string(),
        json!({"force": true, "path": "/etc"}),
    );
    let policies = vec![conditional_policy(
        "shell:*",
        "no-force",
        10,
        json!({
            "forbidden_parameters": ["force"]
        }),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("force"),
                "Reason should mention forbidden param"
            );
        }
        other => panic!("Forbidden parameter should trigger deny, got {:?}", other),
    }
}

#[test]
fn conditional_with_required_parameters() {
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "file".to_string(),
        "write".to_string(),
        json!({"content": "hello"}),
    );
    let policies = vec![conditional_policy(
        "file:write",
        "require-reason",
        10,
        json!({
            "required_parameters": ["reason"]
        }),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("reason"),
                "Should mention missing required param"
            );
        }
        other => panic!(
            "Missing required parameter should trigger deny, got {:?}",
            other
        ),
    }
}

#[test]
fn conditional_allows_when_no_conditions_triggered() {
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "file".to_string(),
        "read".to_string(),
        json!({"path": "/tmp/safe.txt"}),
    );
    let policies = vec![conditional_policy(
        "file:*",
        "file-conditions",
        10,
        json!({
            "forbidden_parameters": ["delete", "force"]
        }),
    )];

    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Allow => {}
        other => panic!("No forbidden params present, should allow, got {:?}", other),
    }
}
