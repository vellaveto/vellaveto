//! End-to-end policy pipeline benchmarks for vellaveto-engine.
//!
//! Measures the full compile-then-evaluate pipeline that production deployments
//! execute: policy compilation (regex, glob, tool matchers) followed by action
//! evaluation with varying policy counts and evaluation contexts.
//!
//! Run with: `cargo bench -p vellaveto-engine --bench e2e_pipeline`

use std::collections::HashMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{
    Action, AgentIdentity, CallChainEntry, EvaluationContext, NetworkRules, PathRules, Policy,
    PolicyType,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn make_allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Allow {}", id),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn make_deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Deny {}", id),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn make_conditional_glob_policy(id: &str, param: &str, pattern: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Conditional {}", id),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": param,
                    "op": "glob",
                    "pattern": pattern,
                    "on_match": "deny"
                }]
            }),
        },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn make_conditional_regex_policy(id: &str, param: &str, pattern: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Regex {}", id),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": param,
                    "op": "regex",
                    "pattern": pattern,
                    "on_match": "deny"
                }]
            }),
        },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

/// Generate N realistic mixed policies with path rules, network rules,
/// glob conditions, and regex conditions — representative of a production
/// deployment.
fn generate_e2e_policies(n: usize) -> Vec<Policy> {
    let mut policies = Vec::with_capacity(n);
    for i in 0..n {
        let priority = (n - i) as i32;
        match i % 6 {
            0 => {
                // Allow with path rules
                policies.push(Policy {
                    id: format!("file_{}:*", i),
                    name: format!("File allow {}", i),
                    policy_type: PolicyType::Allow,
                    priority,
                    path_rules: Some(PathRules {
                        allowed: vec![format!("/workspace/dir_{}/**", i)],
                        blocked: vec!["/workspace/**/secret/**".to_string()],
                    }),
                    network_rules: None,
                });
            }
            1 => {
                // Deny policy
                policies.push(make_deny_policy(&format!("blocked_{}:*", i), priority));
            }
            2 => {
                // Allow with network rules
                policies.push(Policy {
                    id: format!("http_{}:*", i),
                    name: format!("HTTP allow {}", i),
                    policy_type: PolicyType::Allow,
                    priority,
                    path_rules: None,
                    network_rules: Some(NetworkRules {
                        allowed_domains: vec![
                            format!("api-{}.example.com", i),
                            "*.internal.corp".to_string(),
                        ],
                        blocked_domains: vec!["*.evil.com".to_string()],
                        ip_rules: None,
                    }),
                });
            }
            3 => {
                // Conditional glob
                policies.push(make_conditional_glob_policy(
                    &format!("glob_{}:*", i),
                    "path",
                    &format!("/restricted/dir_{}/**", i),
                    priority,
                ));
            }
            4 => {
                // Conditional regex
                policies.push(make_conditional_regex_policy(
                    &format!("regex_{}:*", i),
                    "command",
                    &format!("^(rm|delete|drop).*item_{}", i),
                    priority,
                ));
            }
            _ => {
                // Context-aware policy with forbidden_previous_action
                policies.push(Policy {
                    id: format!("ctx_{}:*", i),
                    name: format!("Context policy {}", i),
                    policy_type: PolicyType::Conditional {
                        conditions: json!({
                            "context_conditions": [
                                {"type": "forbidden_previous_action", "forbidden_tool": format!("sensitive_tool_{}", i)}
                            ],
                            "on_no_match": "continue"
                        }),
                    },
                    priority,
                    path_rules: None,
                    network_rules: None,
                });
            }
        }
    }
    // Catch-all allow at lowest priority
    policies.push(make_allow_policy("*", 0));
    policies
}

// ---------------------------------------------------------------------------
// E2E Benchmarks
// ---------------------------------------------------------------------------

fn bench_e2e_compile_and_evaluate_10_policies(c: &mut Criterion) {
    let policies = generate_e2e_policies(10);
    let action = make_action(
        "file",
        "read",
        json!({"path": "/workspace/dir_0/test.txt"}),
    );

    c.bench_function("e2e/compile_and_evaluate_10_policies", |b| {
        b.iter(|| {
            let engine =
                PolicyEngine::with_policies(false, black_box(&policies)).unwrap();
            engine.evaluate_action(black_box(&action), black_box(&[]))
        })
    });
}

fn bench_e2e_compile_and_evaluate_100_policies(c: &mut Criterion) {
    let policies = generate_e2e_policies(100);
    let action = make_action(
        "unknown_tool",
        "unknown_fn",
        json!({"path": "/tmp/safe.txt"}),
    );

    c.bench_function("e2e/compile_and_evaluate_100_policies", |b| {
        b.iter(|| {
            let engine =
                PolicyEngine::with_policies(false, black_box(&policies)).unwrap();
            engine.evaluate_action(black_box(&action), black_box(&[]))
        })
    });
}

fn bench_e2e_evaluate_with_context_full_session_state(c: &mut Criterion) {
    let policies = generate_e2e_policies(50);
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Build a fully-populated EvaluationContext representing a realistic session
    let mut call_counts = HashMap::new();
    for i in 0..20 {
        call_counts.insert(format!("tool_{}", i), (i + 1) as u64);
    }

    let mut claims = HashMap::new();
    claims.insert("team".to_string(), json!("security-ops"));
    claims.insert("environment".to_string(), json!("production"));
    claims.insert("role".to_string(), json!("senior-agent"));

    let call_chain: Vec<CallChainEntry> = (0..3)
        .map(|i| CallChainEntry {
            agent_id: format!("agent-{}", i),
            tool: format!("tool_{}", i),
            function: format!("function_{}", i),
            timestamp: "2026-02-16T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        })
        .collect();

    let ctx = EvaluationContext {
        timestamp: Some("2026-02-16T12:00:00Z".to_string()),
        agent_id: Some("prod-agent-42".to_string()),
        agent_identity: Some(AgentIdentity {
            issuer: Some("https://auth.example.com".to_string()),
            subject: Some("agent-42".to_string()),
            audience: vec!["vellaveto".to_string()],
            claims,
        }),
        call_counts,
        previous_actions: (0..50).map(|i| format!("tool_{}", i % 20)).collect(),
        call_chain,
        tenant_id: Some("acme-corp".to_string()),
        verification_tier: None,
        capability_token: None,
        session_state: Some("active".to_string()),
    };

    let action = make_action(
        "http_request",
        "execute",
        json!({
            "url": "https://api.example.com/data",
            "method": "POST",
            "body": {"query": "SELECT * FROM reports"}
        }),
    );

    c.bench_function("e2e/evaluate_with_full_session_context", |b| {
        b.iter(|| {
            engine.evaluate_action_with_context(
                black_box(&action),
                black_box(&[]),
                Some(black_box(&ctx)),
            )
        })
    });
}

// ---------------------------------------------------------------------------
// Group and main
// ---------------------------------------------------------------------------

criterion_group!(
    e2e_benches,
    bench_e2e_compile_and_evaluate_10_policies,
    bench_e2e_compile_and_evaluate_100_policies,
    bench_e2e_evaluate_with_context_full_session_state,
);

criterion_main!(e2e_benches);
