//! Proves that policy.name has NO effect on matching or verdict type.
//! The engine uses policy.id for matching and policy.name only in verdict reason strings.
//! If someone accidentally uses name for matching, these tests break.

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

// ═══════════════════════════════
// EMPTY NAME DOES NOT PREVENT MATCHING
// ═══════════════════════════════

#[test]
fn empty_name_policy_still_matches() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec");
    let policies = vec![Policy {
        id: "bash:exec".to_string(),
        name: String::new(),
        policy_type: PolicyType::Deny,
        priority: 10,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }));
}

#[test]
fn whitespace_name_policy_still_matches() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read");
    let policies = vec![Policy {
        id: "file:read".to_string(),
        name: "   \t\n  ".to_string(),
        policy_type: PolicyType::Allow,
        priority: 5,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

#[test]
fn very_long_name_policy_still_matches() {
    let engine = PolicyEngine::new(false);
    let action = make_action("net", "fetch");
    let long_name = "x".repeat(100_000);
    let policies = vec![Policy {
        id: "net:fetch".to_string(),
        name: long_name.clone(),
        policy_type: PolicyType::Deny,
        priority: 50,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            // The reason includes the name
            assert!(reason.contains(&long_name),
                "Deny reason should contain the policy name");
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ════════════════════════════════
// TWO POLICIES: SAME ID, DIFFERENT NAMES, SAME PRIORITY
// ════════════════════════════════

/// With identical IDs and priorities, deny-overrides-allow regardless of name.
#[test]
fn name_does_not_affect_tiebreaking() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func");

    // "AAAA" sorts before "ZZZZ" alphabetically — if names were used for
    // tiebreaking, the Allow with name "AAAA" might win.
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "AAAA".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        },
        Policy {
            id: "*".to_string(),
            name: "ZZZZ".to_string(),
            policy_type: PolicyType::Deny,
            priority: 10,
        },
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Deny { .. }),
        "Deny should win at same priority regardless of name ordering");
}

// ═══════════════════════════════
// CONDITIONAL POLICY: NAME APPEARS IN VERDICT
// ════════════════════════════════

#[test]
fn conditional_require_approval_reason_includes_name() {
    let engine = PolicyEngine::new(false);
    let action = make_action("shell", "run");
    let policies = vec![Policy {
        id: "shell:*".to_string(),
        name: "My Custom Policy Name".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"require_approval": true}),
        },
        priority: 100,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::RequireApproval { reason } => {
            assert!(reason.contains("My Custom Policy Name"),
                "RequireApproval reason should contain policy name, got: {}", reason);
        }
        other => panic!("Expected RequireApproval, got {:?}", other),
    }
}

#[test]
fn conditional_forbidden_param_reason_includes_name() {
    let engine = PolicyEngine::new(false);
    let action = Action {
        tool: "db".to_string(),
        function: "query".to_string(),
        parameters: json!({"drop_table": true}),
    };
    let policies = vec![Policy {
        id: "db:*".to_string(),
        name: "DB Safety Rule".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": ["drop_table"]}),
        },
        priority: 100,
    }];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    match result {
        Verdict::Deny { reason } => {
            assert!(reason.contains("DB Safety Rule"),
                "Deny reason should contain policy name, got: {}", reason);
            assert!(reason.contains("drop_table"),
                "Deny reason should mention the forbidden parameter, got: {}", reason);
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}