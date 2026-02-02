//! Invariant and quasi-property-based tests.
//!
//! Since we cannot add proptest without modifying Cargo.toml,
//! these tests exercise the same concerns:
//! - Serialization roundtrips
//! - Invariants that must hold for all inputs
//! - Boundary conditions
//! - Randomly-structured inputs via manual construction

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

// ════════════════════════════════════════════
// SERIALIZATION ROUNDTRIP INVARIANTS
// ═════════════════════════════════════════════

#[test]
fn action_roundtrip_preserves_equality() {
    let actions = vec![
        Action {
            tool: String::new(),
            function: String::new(),
            parameters: json!(null),
        },
        Action {
            tool: "a".repeat(1000),
            function: "b".repeat(1000),
            parameters: json!({"nested": {"deep": {"value": 42}}}),
        },
        Action {
            tool: "special\tchars".to_string(),
            function: "with spaces".to_string(),
            parameters: json!([1, 2, 3, "four", null, true]),
        },
        Action {
            tool: "unicode_🔥".to_string(),
            function: "日本語".to_string(),
            parameters: json!({"emoji": "🎉", "chinese": "中文"}),
        },
    ];

    for action in &actions {
        let serialized = serde_json::to_string(action).unwrap();
        let deserialized: Action = serde_json::from_str(&serialized).unwrap();
        assert_eq!(action, &deserialized, "Roundtrip failed for action: {:?}", action);
    }
}

#[test]
fn verdict_roundtrip_preserves_equality() {
    let verdicts = vec![
        Verdict::Allow,
        Verdict::Deny { reason: String::new() },
        Verdict::Deny { reason: "x".repeat(10000) },
        Verdict::Deny { reason: "newline\nand\ttab".to_string() },
        Verdict::RequireApproval { reason: String::new() },
        Verdict::RequireApproval { reason: "unicode: 日本 🔥".to_string() },
    ];

    for verdict in &verdicts {
        let serialized = serde_json::to_string(verdict).unwrap();
        let deserialized: Verdict = serde_json::from_str(&serialized).unwrap();
        assert_eq!(verdict, &deserialized, "Roundtrip failed for verdict: {:?}", verdict);
    }
}

#[test]
fn policy_type_roundtrip_preserves_equality() {
    let types = vec![
        PolicyType::Allow,
        PolicyType::Deny,
        PolicyType::Conditional { conditions: json!(null) },
        PolicyType::Conditional { conditions: json!({}) },
        PolicyType::Conditional { conditions: json!("string") },
        PolicyType::Conditional { conditions: json!(42) },
        PolicyType::Conditional { conditions: json!([1, 2, 3]) },
        PolicyType::Conditional {
            conditions: json!({
                "forbidden_parameters": ["a", "b"],
                "required_parameters": ["c"],
                "require_approval": false
            }),
        },
    ];

    for pt in &types {
        let serialized = serde_json::to_string(pt).unwrap();
        let deserialized: PolicyType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(pt, &deserialized, "Roundtrip failed for policy type: {:?}", pt);
    }
}

#[test]
fn policy_roundtrip_with_various_priorities() {
    let priorities = vec![i32::MIN, -1000, -1, 0, 1, 1000, i32::MAX];

    for &pri in &priorities {
        let policy = Policy {
            id: "test:roundtrip".to_string(),
            name: format!("priority-{}", pri),
            policy_type: PolicyType::Deny,
            priority: pri,
        };
        let serialized = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.priority, pri);
        assert_eq!(deserialized.id, "test:roundtrip");
    }
}

// ════════════════════════════════════════════
// ENGINE INVARIANTS: FAIL-CLOSED
// ═══════════════════════════════════════════

/// No matter what the action looks like, empty policies always deny.
#[test]
fn empty_policies_always_deny_for_any_action() {
    let engine = PolicyEngine::new(false);
    let actions = vec![
        Action { tool: String::new(), function: String::new(), parameters: json!(null) },
        Action { tool: "*".to_string(), function: "*".to_string(), parameters: json!({}) },
        Action { tool: "a".repeat(10000), function: "b".to_string(), parameters: json!({"x": 1}) },
    ];

    for action in &actions {
        let verdict = engine.evaluate_action(action, &[]).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Empty policies should deny for action: {:?}",
            action
        );
    }
}

/// Wildcard allow always allows, regardless of action content.
#[test]
fn wildcard_allow_always_allows() {
    let engine = PolicyEngine::new(false);
    let policy = vec![Policy {
        id: "*".to_string(),
        name: "allow-all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 0,
    }];

    let actions = vec![
        Action { tool: "".to_string(), function: "".to_string(), parameters: json!(null) },
        Action { tool: "bash".to_string(), function: "exec".to_string(), parameters: json!({"cmd": "rm -rf /"}) },
        Action { tool: "🔥".to_string(), function: "💀".to_string(), parameters: json!([]) },
    ];

    for action in &actions {
        let verdict = engine.evaluate_action(action, &policy).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Wildcard allow should allow action: {:?}",
            action
        );
    }
}

/// Wildcard deny always denies, regardless of action content.
#[test]
fn wildcard_deny_always_denies() {
    let engine = PolicyEngine::new(false);
    let policy = vec![Policy {
        id: "*".to_string(),
        name: "deny-all".to_string(),
        policy_type: PolicyType::Deny,
        priority: 0,
    }];

    let actions = vec![
        Action { tool: "safe".to_string(), function: "read".to_string(), parameters: json!({}) },
        Action { tool: "".to_string(), function: "".to_string(), parameters: json!(null) },
    ];

    for action in &actions {
        let verdict = engine.evaluate_action(action, &policy).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Wildcard deny should deny action: {:?}",
            action
        );
    }
}

// ═══════════════════════════════════════════
// INVARIANT: HIGHER PRIORITY ALWAYS WINS
// ═════════════════════════════════════════════

/// For any pair of priorities where p1 > p2, the p1 policy always wins.
#[test]
fn higher_priority_always_wins_over_lower() {
    let engine = PolicyEngine::new(false);
    let action = Action {
        tool: "tool".to_string(),
        function: "func".to_string(),
        parameters: json!({}),
    };

    let priority_pairs: Vec<(i32, i32)> = vec![
        (1, 0),
        (100, 99),
        (0, -1),
        (-1, -100),
        (i32::MAX, i32::MAX - 1),
        (i32::MIN + 1, i32::MIN),
    ];

    for (high, low) in &priority_pairs {
        // High-priority allow vs low-priority deny → allow wins
        let policies = vec![
            Policy {
                id: "*".to_string(),
                name: "high-allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: *high,
            },
            Policy {
                id: "*".to_string(),
                name: "low-deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: *low,
            },
        ];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Priority {} allow should beat priority {} deny",
            high, low
        );

        // High-priority deny vs low-priority allow  deny wins
        let policies = vec![
            Policy {
                id: "*".to_string(),
                name: "high-deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: *high,
            },
            Policy {
                id: "*".to_string(),
                name: "low-allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: *low,
            },
        ];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Priority {} deny should beat priority {} allow",
            high, low
        );
    }
}

// ════════════════════════════════════════════
// INVARIANT: DENY-OVERRIDES-ALLOW AT SAME PRIORITY
// ════════════════════════════════════════════

/// At every priority level, deny should beat allow (deny-overrides tie-breaking).
#[test]
fn deny_overrides_allow_at_every_priority_level() {
    let engine = PolicyEngine::new(false);
    let action = Action {
        tool: "t".to_string(),
        function: "f".to_string(),
        parameters: json!({}),
    };

    let priorities = vec![i32::MIN, -1, 0, 1, 100, i32::MAX];

    for &pri in &priorities {
        let policies = vec![
            Policy {
                id: "*".to_string(),
                name: "allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: pri,
            },
            Policy {
                id: "*".to_string(),
                name: "deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: pri,
            },
        ];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Deny should override allow at priority {}",
            pri
        );
    }
}

// ═══════════════════════════════════════════
// INVARIANT: evaluate_action NEVER PANICS
// ════════════════════════════════════════════

/// No combination of valid types should cause a panic.
#[test]
fn evaluate_never_panics_with_valid_inputs() {
    let engine = PolicyEngine::new(false);

    let actions = vec![
        Action { tool: "".to_string(), function: "".to_string(), parameters: json!(null) },
        Action { tool: "*".to_string(), function: "*".to_string(), parameters: json!({}) },
        Action { tool: ":".to_string(), function: ":".to_string(), parameters: json!("str") },
        Action { tool: "a:b:c".to_string(), function: "d".to_string(), parameters: json!([]) },
    ];

    let policy_sets: Vec<Vec<Policy>> = vec![
        vec![],
        vec![Policy {
            id: "*".to_string(),
            name: "a".to_string(),
            policy_type: PolicyType::Allow,
            priority: 0,
        }],
        vec![Policy {
            id: "*".to_string(),
            name: "c".to_string(),
            policy_type: PolicyType::Conditional { conditions: json!(null) },
            priority: 0,
        }],
    ];

    for action in &actions {
        for policies in &policy_sets {
            // Should not panic — result can be Ok or Err, but no panic
            let _ = engine.evaluate_action(action, policies);
        }
    }
}

// ════════════════════════════════════════════
// MANY-POLICIES STRESS
// ════════════════════════════════════════════

/// 1000 non-matching policies followed by one match. Should still return correct verdict.
#[test]
fn thousand_non_matching_then_one_match() {
    let engine = PolicyEngine::new(false);
    let action = Action {
        tool: "target".to_string(),
        function: "hit".to_string(),
        parameters: json!({}),
    };

    let mut policies: Vec<Policy> = (0..1000)
        .map(|i| Policy {
            id: format!("nomatch_{}:nomatch_{}", i, i),
            name: format!("miss-{}", i),
            policy_type: PolicyType::Allow,
            priority: 10,
        })
        .collect();

    policies.push(Policy {
        id: "target:hit".to_string(),
        name: "the-match".to_string(),
        policy_type: PolicyType::Deny,
        priority: 1,
    });

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // The matching policy at priority 1 should fire (non-matching ones at priority 10 are irrelevant)
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

/// All 1000 policies match (wildcard). Highest priority wins.
#[test]
fn thousand_matching_policies_highest_wins() {
    let engine = PolicyEngine::new(false);
    let action = Action {
        tool: "t".to_string(),
        function: "f".to_string(),
        parameters: json!({}),
    };

    let mut policies: Vec<Policy> = (0..999)
        .map(|i| Policy {
            id: "*".to_string(),
            name: format!("deny-{}", i),
            policy_type: PolicyType::Deny,
            priority: i,
        })
        .collect();

    // One allow at highest priority
    policies.push(Policy {
        id: "*".to_string(),
        name: "top-allow".to_string(),
        policy_type: PolicyType::Allow,
        priority: 999,
    });

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}