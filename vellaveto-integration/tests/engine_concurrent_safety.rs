//! Proves PolicyEngine is safe to share across threads via Arc.
//! The engine has no interior mutability (&self only), so concurrent
//! evaluate_action calls must never interfere with each other.

use serde_json::json;
use std::sync::Arc;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
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

fn deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny-{}", id),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn runtime_mt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to create multi-thread runtime")
}

/// 100 tasks evaluate concurrently on the same engine instance.
/// All must get the same deterministic result.
#[test]
fn concurrent_evaluations_are_deterministic() {
    let rt = runtime_mt();
    rt.block_on(async {
        let engine = Arc::new(PolicyEngine::new(false));
        let policies = Arc::new(vec![
            deny_policy("bash:*", 100),
            allow_policy("file:read", 50),
            allow_policy("*", 1),
        ]);

        let mut handles = Vec::new();
        for i in 0..100 {
            let engine = Arc::clone(&engine);
            let policies = Arc::clone(&policies);
            handles.push(tokio::spawn(async move {
                // Half the tasks evaluate a denied action, half an allowed one
                if i % 2 == 0 {
                    let action = make_action("bash", "execute", json!({"i": i}));
                    let verdict = engine.evaluate_action(&action, &policies).unwrap();
                    assert!(
                        matches!(verdict, Verdict::Deny { .. }),
                        "Task {} expected Deny, got {:?}",
                        i,
                        verdict
                    );
                } else {
                    let action = make_action("file", "read", json!({"i": i}));
                    let verdict = engine.evaluate_action(&action, &policies).unwrap();
                    assert_eq!(
                        verdict,
                        Verdict::Allow,
                        "Task {} expected Allow, got {:?}",
                        i,
                        verdict
                    );
                }
            }));
        }

        for (i, handle) in handles.into_iter().enumerate() {
            handle
                .await
                .unwrap_or_else(|e| panic!("Task {} panicked: {:?}", i, e));
        }
    });
}

/// Concurrent evaluation with conditional policies — more complex code path.
#[test]
fn concurrent_conditional_evaluations() {
    let rt = runtime_mt();
    rt.block_on(async {
        let engine = Arc::new(PolicyEngine::new(false));
        let policies = Arc::new(vec![
            Policy {
                id: "net:*".to_string(),
                name: "Network requires approval".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({"require_approval": true}),
                },
                priority: 50,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*".to_string(),
                name: "Conditional with forbidden params".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({"forbidden_parameters": ["secret", "password"]}),
                },
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
        ]);

        let mut handles = Vec::new();
        for i in 0..50 {
            let engine = Arc::clone(&engine);
            let policies = Arc::clone(&policies);
            handles.push(tokio::spawn(async move {
                match i % 3 {
                    0 => {
                        // Network action -> RequireApproval
                        let action =
                            make_action("net", "fetch", json!({"url": "http://example.com"}));
                        let v = engine.evaluate_action(&action, &policies).unwrap();
                        assert!(
                            matches!(v, Verdict::RequireApproval { .. }),
                            "Expected RequireApproval, got {:?}",
                            v
                        );
                    }
                    1 => {
                        // Non-network with forbidden param -> Deny
                        let action = make_action("db", "query", json!({"secret": "value"}));
                        let v = engine.evaluate_action(&action, &policies).unwrap();
                        assert!(
                            matches!(v, Verdict::Deny { .. }),
                            "Expected Deny, got {:?}",
                            v
                        );
                    }
                    _ => {
                        // Non-network without forbidden param -> Allow (conditions pass)
                        let action = make_action("db", "query", json!({"table": "users"}));
                        let v = engine.evaluate_action(&action, &policies).unwrap();
                        assert_eq!(v, Verdict::Allow, "Expected Allow, got {:?}", v);
                    }
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    });
}

/// Different policy sets evaluated through the same engine concurrently.
/// Proves policies are purely input-driven with no cross-contamination.
#[test]
fn concurrent_different_policy_sets_no_contamination() {
    let rt = runtime_mt();
    rt.block_on(async {
        let engine = Arc::new(PolicyEngine::new(false));
        let action = Arc::new(make_action("tool", "func", json!({})));

        let allow_policies = Arc::new(vec![allow_policy("*", 100)]);
        let deny_policies = Arc::new(vec![deny_policy("*", 100)]);

        let mut handles = Vec::new();
        for i in 0..100 {
            let engine = Arc::clone(&engine);
            let action = Arc::clone(&action);
            let allow_policies = Arc::clone(&allow_policies);
            let deny_policies = Arc::clone(&deny_policies);

            handles.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    let v = engine.evaluate_action(&action, &allow_policies).unwrap();
                    assert_eq!(
                        v,
                        Verdict::Allow,
                        "Even task {} got {:?} instead of Allow",
                        i,
                        v
                    );
                } else {
                    let v = engine.evaluate_action(&action, &deny_policies).unwrap();
                    assert!(
                        matches!(v, Verdict::Deny { .. }),
                        "Odd task {} got {:?} instead of Deny",
                        i,
                        v
                    );
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    });
}
