//! Integration tests for conditional policy evaluation.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, CallChainEntry, EvaluationContext, Policy, PolicyType, Verdict};

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

// ══════════════════════════════════════════════════════════════════════════════
// OWASP ASI08: Multi-Agent Call Chain Depth Tests
// ══════════════════════════════════════════════════════════════════════════════

fn make_call_chain_entry(agent_id: &str, tool: &str) -> CallChainEntry {
    CallChainEntry {
        agent_id: agent_id.to_string(),
        tool: tool.to_string(),
        function: "execute".to_string(),
        timestamp: "2026-01-01T12:00:00Z".to_string(),
        hmac: None,
        verified: None,
    }
}

#[test]
fn max_chain_depth_zero_allows_direct_calls() {
    // max_depth: 0 means no multi-hop allowed (direct calls only)
    let policies = vec![conditional_policy(
        "*",
        "no-multi-hop",
        100,
        json!({
            "context_conditions": [
                {"type": "max_chain_depth", "max_depth": 0}
            ]
        }),
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = Action::new("read_file", "execute", json!({}));

    // Empty call chain (depth 0) should be allowed
    let ctx = EvaluationContext {
        call_chain: Vec::new(),
        ..Default::default()
    };
    let result = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Empty chain should be allowed"
    );
}

#[test]
fn max_chain_depth_zero_denies_single_hop() {
    // max_depth: 0 means no multi-hop allowed
    let policies = vec![conditional_policy(
        "*",
        "no-multi-hop",
        100,
        json!({
            "context_conditions": [
                {"type": "max_chain_depth", "max_depth": 0}
            ]
        }),
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = Action::new("read_file", "execute", json!({}));

    // Single entry in call chain (depth 1) should be denied
    let ctx = EvaluationContext {
        call_chain: vec![make_call_chain_entry("agent-a", "tool1")],
        ..Default::default()
    };
    let result = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("chain depth"),
                "Deny reason should mention chain depth: {}",
                reason
            );
        }
        other => panic!("Expected Deny for chain depth > 0, got {:?}", other),
    }
}

#[test]
fn max_chain_depth_one_allows_single_hop() {
    // max_depth: 1 means one upstream agent allowed
    let policies = vec![conditional_policy(
        "*",
        "allow-one-hop",
        100,
        json!({
            "context_conditions": [
                {"type": "max_chain_depth", "max_depth": 1}
            ]
        }),
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = Action::new("read_file", "execute", json!({}));

    // Single entry in call chain should be allowed
    let ctx = EvaluationContext {
        call_chain: vec![make_call_chain_entry("agent-a", "tool1")],
        ..Default::default()
    };
    let result = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Single hop should be allowed"
    );
}

#[test]
fn max_chain_depth_one_denies_double_hop() {
    // max_depth: 1 means only one upstream agent allowed
    let policies = vec![conditional_policy(
        "*",
        "allow-one-hop",
        100,
        json!({
            "context_conditions": [
                {"type": "max_chain_depth", "max_depth": 1}
            ]
        }),
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = Action::new("read_file", "execute", json!({}));

    // Two entries in call chain should be denied
    let ctx = EvaluationContext {
        call_chain: vec![
            make_call_chain_entry("agent-a", "tool1"),
            make_call_chain_entry("agent-b", "tool2"),
        ],
        ..Default::default()
    };
    let result = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains("chain depth"),
                "Deny reason should mention chain depth: {}",
                reason
            );
        }
        other => panic!("Expected Deny for chain depth > 1, got {:?}", other),
    }
}

#[test]
fn max_chain_depth_compilation_error_on_missing_max_depth() {
    // max_chain_depth without max_depth field should fail to compile
    let policies = vec![conditional_policy(
        "*",
        "bad-config",
        100,
        json!({
            "context_conditions": [
                {"type": "max_chain_depth"}  // Missing max_depth
            ]
        }),
    )];
    let result = PolicyEngine::with_policies(false, &policies);
    assert!(result.is_err(), "Should fail to compile without max_depth");
    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.reason.contains("max_depth")),
        "Error should mention missing max_depth"
    );
}
