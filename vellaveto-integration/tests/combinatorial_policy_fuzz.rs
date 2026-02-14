//! Fuzz-like tests that systematically generate combinations of policies
//! and actions to find crashes, panics, or invariant violations in the engine.
//! No external dependencies required — uses deterministic "pseudo-random" construction.

use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn make_policy(id: &str, name: &str, policy_type: PolicyType, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

/// All policy type variants we want to combine.
fn all_policy_types() -> Vec<PolicyType> {
    vec![
        PolicyType::Allow,
        PolicyType::Deny,
        PolicyType::Conditional {
            conditions: json!({"require_approval": true}),
        },
        PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": ["secret"]}),
        },
        PolicyType::Conditional {
            conditions: json!({"required_parameters": ["token"]}),
        },
        PolicyType::Conditional {
            conditions: json!({}),
        },
    ]
}

/// Various policy ID patterns to combine.
fn all_patterns() -> Vec<&'static str> {
    vec![
        "*",
        "tool:*",
        "*:func",
        "tool:func",
        "other:other",
        "tool",
        "nonexistent",
    ]
}

/// Various priority values including edge cases.
fn all_priorities() -> Vec<i32> {
    vec![i32::MIN, -1000, -1, 0, 1, 100, 1000, i32::MAX]
}

// ════════════════════════════════════
// INVARIANT: evaluate_action never panics
// ════════════════════════════════════

/// For every combination of policy type × pattern × priority,
/// evaluating against a fixed action must not panic.
#[test]
fn engine_never_panics_on_any_policy_combination() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"secret": "val", "token": "t"}));

    for pt in all_policy_types() {
        for &pattern in &all_patterns() {
            for &priority in &all_priorities() {
                let policy = make_policy(pattern, "fuzz-policy", pt.clone(), priority);
                // Must not panic — we don't care about the verdict, just that it completes
                let _result = engine.evaluate_action(&action, &[policy]);
            }
        }
    }
}

/// Same as above but with strict_mode=true.
#[test]
fn strict_engine_never_panics_on_any_policy_combination() {
    let engine = PolicyEngine::new(true);
    let action = make_action("tool", "func", json!({}));

    for pt in all_policy_types() {
        for &pattern in &all_patterns() {
            for &priority in &all_priorities() {
                let policy = make_policy(pattern, "fuzz-strict", pt.clone(), priority);
                let _result = engine.evaluate_action(&action, &[policy]);
            }
        }
    }
}

// ════════════════════════════════════
// INVARIANT: result is always Ok for valid policies
// ════════════════════════════════════

/// All well-formed policies (no deeply nested conditions) should return Ok.
#[test]
fn all_simple_policy_combos_return_ok() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    let simple_types = vec![
        PolicyType::Allow,
        PolicyType::Deny,
        PolicyType::Conditional {
            conditions: json!({"require_approval": false}),
        },
    ];

    for pt in &simple_types {
        for &pattern in &["*", "tool:*", "tool:func"] {
            for &priority in &[i32::MIN, 0, i32::MAX] {
                let policy = make_policy(pattern, "simple", pt.clone(), priority);
                let result = engine.evaluate_action(&action, &[policy]);
                assert!(
                    result.is_ok(),
                    "Expected Ok for pattern={}, priority={}, type={:?}",
                    pattern,
                    priority,
                    pt
                );
            }
        }
    }
}

// ══════════════════════════════════════════════
// MULTI-POLICY COMBINATORIAL: 2-policy interactions
// ════════════════════════════════════════════

/// For every pair of (Allow, Deny) policies with different priorities,
/// the higher priority one should win.
#[test]
fn higher_priority_always_wins_in_pairwise_combos() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    let priorities = vec![-100, -1, 0, 1, 50, 100];

    for &p1 in &priorities {
        for &p2 in &priorities {
            if p1 == p2 {
                continue; // tie-breaking tested elsewhere
            }
            let allow = make_policy("*", "allow", PolicyType::Allow, p1);
            let deny = make_policy("*", "deny", PolicyType::Deny, p2);

            let verdict = engine.evaluate_action(&action, &[allow, deny]).unwrap();

            if p1 > p2 {
                // Allow has higher priority
                assert_eq!(
                    verdict,
                    Verdict::Allow,
                    "Allow(pri={}) should beat Deny(pri={})",
                    p1,
                    p2
                );
            } else {
                // Deny has higher priority
                match &verdict {
                    Verdict::Deny { .. } => {}
                    other => panic!(
                        "Deny(pri={}) should beat Allow(pri={}), got {:?}",
                        p2, p1, other
                    ),
                }
            }
        }
    }
}

// ═════════════════════════════════════════════
// TRIPLE POLICY: Allow + Deny + Conditional
// ════════════════════════════════════════════

/// When three policy types compete, highest priority wins regardless of type.
#[test]
fn three_way_policy_highest_priority_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    // Allow=100 > Deny=50 > Conditional(require_approval)=10
    let policies = vec![
        make_policy("*", "allow", PolicyType::Allow, 100),
        make_policy("*", "deny", PolicyType::Deny, 50),
        make_policy(
            "*",
            "cond",
            PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            10,
        ),
    ];
    assert_eq!(
        engine.evaluate_action(&action, &policies).unwrap(),
        Verdict::Allow
    );

    // Conditional=100 > Deny=50 > Allow=10
    let policies = vec![
        make_policy("*", "allow", PolicyType::Allow, 10),
        make_policy("*", "deny", PolicyType::Deny, 50),
        make_policy(
            "*",
            "cond",
            PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            100,
        ),
    ];
    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::RequireApproval { .. } => {}
        other => panic!("Expected RequireApproval, got {:?}", other),
    }

    // Deny=100 > Conditional=50 > Allow=10
    let policies = vec![
        make_policy("*", "allow", PolicyType::Allow, 10),
        make_policy("*", "deny", PolicyType::Deny, 100),
        make_policy(
            "*",
            "cond",
            PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            50,
        ),
    ];
    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!("Expected Deny, got {:?}", other),
    }
}

// ═════════════════════════════════════════════
// PARAMETER COMBINATORIAL: actions with varied params
// ═════════════════════════════════════════════

/// Test forbidden_parameters against actions with varying parameter sets.
#[test]
fn forbidden_parameters_combinatorial() {
    let engine = PolicyEngine::new(false);

    let forbidden = vec!["a", "b", "c"];
    let policy = make_policy(
        "*",
        "forbid-abc",
        PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": forbidden}),
        },
        100,
    );

    // No forbidden params present → Allow
    let action = make_action("tool", "func", json!({"x": 1, "y": 2}));
    assert_eq!(
        engine
            .evaluate_action(&action, std::slice::from_ref(&policy))
            .unwrap(),
        Verdict::Allow
    );

    // Each forbidden param individually triggers Deny
    for &param in &["a", "b", "c"] {
        let action = make_action("tool", "func", json!({param: "val"}));
        match engine
            .evaluate_action(&action, std::slice::from_ref(&policy))
            .unwrap()
        {
            Verdict::Deny { reason } => {
                assert!(
                    reason.contains(param),
                    "Reason should mention forbidden param '{}'",
                    param
                );
            }
            other => panic!("Expected Deny for param '{}', got {:?}", param, other),
        }
    }

    // All forbidden params present → still Deny (first one found)
    let action = make_action("tool", "func", json!({"a": 1, "b": 2, "c": 3}));
    match engine
        .evaluate_action(&action, std::slice::from_ref(&policy))
        .unwrap()
    {
        Verdict::Deny { .. } => {}
        other => panic!("Expected Deny with all forbidden params, got {:?}", other),
    }
}

/// Test required_parameters against actions with varying parameter sets.
#[test]
fn required_parameters_combinatorial() {
    let engine = PolicyEngine::new(false);

    let policy = make_policy(
        "*",
        "require-ab",
        PolicyType::Conditional {
            conditions: json!({"required_parameters": ["a", "b"]}),
        },
        100,
    );

    // Both present  Allow
    let action = make_action("tool", "func", json!({"a": 1, "b": 2}));
    assert_eq!(
        engine
            .evaluate_action(&action, std::slice::from_ref(&policy))
            .unwrap(),
        Verdict::Allow
    );

    // Only "a" present  Deny (missing "b")
    let action = make_action("tool", "func", json!({"a": 1}));
    match engine
        .evaluate_action(&action, std::slice::from_ref(&policy))
        .unwrap()
    {
        Verdict::Deny { reason } => {
            assert!(reason.contains("b"), "Should mention missing param 'b'");
        }
        other => panic!("Expected Deny for missing 'b', got {:?}", other),
    }

    // Neither present → Deny
    let action = make_action("tool", "func", json!({}));
    match engine
        .evaluate_action(&action, std::slice::from_ref(&policy))
        .unwrap()
    {
        Verdict::Deny { .. } => {}
        other => panic!("Expected Deny with no params, got {:?}", other),
    }
}

// ══════════════════════════════════════════════
// MANY POLICIES: scale test (no panics, correct verdict)
// ═════════════════════════════════════════════

/// 1000 policies with varied types and priorities. The highest-priority
/// matching policy determines the verdict.
#[test]
fn thousand_policies_highest_priority_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    let mut policies: Vec<Policy> = (0..999)
        .map(|i| {
            if i % 2 == 0 {
                make_policy("*", &format!("p{}", i), PolicyType::Allow, i)
            } else {
                make_policy("*", &format!("p{}", i), PolicyType::Deny, i)
            }
        })
        .collect();

    // Add one policy with the absolute highest priority
    policies.push(make_policy("*", "the-king", PolicyType::Allow, 10_000));

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert_eq!(verdict, Verdict::Allow, "Highest priority Allow should win");
}

/// Same as above but highest is Deny.
#[test]
fn thousand_policies_highest_priority_deny_wins() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));

    let mut policies: Vec<Policy> = (0..999)
        .map(|i| make_policy("*", &format!("p{}", i), PolicyType::Allow, i))
        .collect();

    policies.push(make_policy("*", "the-blocker", PolicyType::Deny, 10_000));

    match engine.evaluate_action(&action, &policies).unwrap() {
        Verdict::Deny { .. } => {}
        other => panic!("Expected Deny, got {:?}", other),
    }
}
