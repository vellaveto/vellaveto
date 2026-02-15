//! Smoke tests for core invariants that must always hold.
//! Every assertion traces to a specific source code line.
//! If any of these fail, the workspace is fundamentally broken.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

// ════════════════════════════
// INVARIANT 1: Empty policies → Deny
// Source: vellaveto-engine/src/lib.rs evaluate_action, first check
// ════════════════════════════

#[test]
fn smoke_empty_policies_returns_deny() {
    let engine = PolicyEngine::new(false);
    let result = engine.evaluate_action(&action("any", "thing"), &[]);
    assert!(result.is_ok());
    match result.unwrap() {
        Verdict::Deny { reason } => assert_eq!(reason, "No policies defined"),
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ═════════════════════════════
// INVARIANT 2: Wildcard "*" matches everything
// Source: matches_action returns true when id == "*"
// ════════════════════════════

#[test]
fn smoke_wildcard_allow_permits() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "allow-all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine
        .evaluate_action(&action("x", "y"), &policies)
        .unwrap();
    assert_eq!(result, Verdict::Allow);
}

#[test]
fn smoke_wildcard_deny_denies() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "deny-all".to_string(),
        policy_type: PolicyType::Deny,
        priority: 1,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine
        .evaluate_action(&action("x", "y"), &policies)
        .unwrap();
    match result {
        Verdict::Deny { reason } => assert!(reason.contains("deny-all")),
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ════════════════════════════
// INVARIANT 3: Higher priority wins
// Source: sorted.sort_by priority descending
// ════════════════════════════

#[test]
fn smoke_higher_priority_wins() {
    let engine = PolicyEngine::new(false);
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "low-allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "high-deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine
        .evaluate_action(&action("a", "b"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ════════════════════════════
// INVARIANT 4: Equal priority  Deny beats Allow
// Source: sort tiebreaker: b_deny.cmp(&a_deny)
// ════════════════════════════

#[test]
fn smoke_equal_priority_deny_wins() {
    let engine = PolicyEngine::new(false);
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = engine
        .evaluate_action(&action("a", "b"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ════════════════════════════
// INVARIANT 5: Exact colon match works
// Source: split_once(':') then match_pattern on both parts
// ════════════════════════════

#[test]
fn smoke_exact_colon_match() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "file:read".to_string(),
        name: "allow-file-read".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine
        .evaluate_action(&action("file", "read"), &policies)
        .unwrap();
    assert_eq!(result, Verdict::Allow);
}

#[test]
fn smoke_exact_colon_no_match_denies() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "file:read".to_string(),
        name: "allow-file-read".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine
        .evaluate_action(&action("file", "write"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

// ═══════════════════════════
// INVARIANT 6: Conditional require_approval
// Source: evaluate_conditions checks require_approval first
// ═══════════════════════════

#[test]
fn smoke_conditional_require_approval() {
    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "need-approval".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"require_approval": true}),
        },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine
        .evaluate_action(&action("a", "b"), &policies)
        .unwrap();
    assert!(matches!(result, Verdict::RequireApproval { .. }));
}

// ════════════════════════════
// INVARIANT 7: Conditional forbidden_parameters
// Source: checks action.parameters.get(param_str).is_some()
// ═══════════════════════════

#[test]
fn smoke_forbidden_param_present_denies() {
    let engine = PolicyEngine::new(false);
    let act = Action::new("t".to_string(), "f".to_string(), json!({"secret": "value"}));
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "no-secrets".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": ["secret"]}),
        },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&act, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

#[test]
fn smoke_forbidden_param_absent_allows() {
    let engine = PolicyEngine::new(false);
    let act = Action::new("t".to_string(), "f".to_string(), json!({"safe": "value"}));
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "no-secrets".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": ["secret"]}),
        },
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&act, &policies).unwrap();
    assert_eq!(result, Verdict::Allow);
}
