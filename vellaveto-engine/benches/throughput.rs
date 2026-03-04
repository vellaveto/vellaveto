// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Phase 55 — Performance & Scale Validation benchmarks for vellaveto-engine.
//!
//! Measures sustained throughput and validates the 100K evaluations/second target.
//!
//! Run with: `cargo bench -p vellaveto-engine --bench throughput`
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(deprecated)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, NetworkRules, PathRules, Policy, PolicyType};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn make_allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Allow {id}"),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn make_deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Deny {id}"),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn make_conditional_glob_policy(id: &str, param: &str, pattern: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Conditional {id}"),
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
        name: format!("Regex {id}"),
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
fn generate_throughput_policies(n: usize) -> Vec<Policy> {
    let mut policies = Vec::with_capacity(n + 1);
    for i in 0..n {
        let priority = (n - i) as i32;
        match i % 6 {
            0 => {
                // Allow with path rules
                policies.push(Policy {
                    id: format!("file_{i}:*"),
                    name: format!("File allow {i}"),
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
                policies.push(make_deny_policy(&format!("blocked_{i}:*"), priority));
            }
            2 => {
                // Allow with network rules
                policies.push(Policy {
                    id: format!("http_{i}:*"),
                    name: format!("HTTP allow {i}"),
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
                    &format!("glob_{i}:*"),
                    "path",
                    &format!("/restricted/dir_{i}/**"),
                    priority,
                ));
            }
            4 => {
                // Conditional regex
                policies.push(make_conditional_regex_policy(
                    &format!("regex_{i}:*"),
                    "command",
                    &format!("^(rm|delete|drop).*item_{i}"),
                    priority,
                ));
            }
            _ => {
                // Context-aware policy with forbidden_previous_action
                policies.push(Policy {
                    id: format!("ctx_{i}:*"),
                    name: format!("Context policy {i}"),
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

/// Generate N distinct actions with different tool/function names and
/// varying parameters, simulating diverse workloads.
fn generate_diverse_actions(n: usize) -> Vec<Action> {
    let mut actions = Vec::with_capacity(n);
    for i in 0..n {
        let action = match i % 5 {
            0 => make_action(
                &format!("file_tool_{i}"),
                "read",
                json!({"path": format!("/workspace/dir_{}/file_{}.txt", i % 20, i)}),
            ),
            1 => make_action(
                &format!("http_tool_{i}"),
                "request",
                json!({
                    "url": format!("https://api-{}.example.com/data", i % 10),
                    "method": "GET"
                }),
            ),
            2 => make_action(
                &format!("db_tool_{i}"),
                "query",
                json!({"query": format!("SELECT * FROM table_{} LIMIT 100", i % 15)}),
            ),
            3 => make_action(
                &format!("shell_tool_{i}"),
                "execute",
                json!({"command": format!("ls -la /workspace/dir_{}", i % 10)}),
            ),
            _ => make_action(
                &format!("custom_tool_{i}"),
                &format!("action_{}", i % 8),
                json!({"param_a": i, "param_b": format!("value_{}", i)}),
            ),
        };
        actions.push(action);
    }
    actions
}

// ---------------------------------------------------------------------------
// Group 1: sustained_throughput
// ---------------------------------------------------------------------------

fn sustained_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("sustained_throughput");

    // --- single_allow_policy: 1 policy, allow-all, peak throughput ---
    {
        let policies = vec![make_allow_policy("*", 100)];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = make_action("any_tool", "any_fn", json!({"key": "value"}));

        group.throughput(Throughput::Elements(1));
        group.bench_function("single_allow_policy", |b| {
            b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
        });
    }

    // --- ten_mixed_policies: 10 policies, mix of Allow/Deny/Conditional ---
    {
        let policies = generate_throughput_policies(10);
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = make_action(
            "file_tool",
            "read",
            json!({"path": "/workspace/dir_0/test.txt"}),
        );

        group.throughput(Throughput::Elements(1));
        group.bench_function("ten_mixed_policies", |b| {
            b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
        });
    }

    // --- hundred_mixed_policies: 100 realistic mixed policies ---
    {
        let policies = generate_throughput_policies(100);
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = make_action(
            "http_request",
            "execute",
            json!({"url": "https://api.example.com/data", "method": "POST"}),
        );

        group.throughput(Throughput::Elements(1));
        group.bench_function("hundred_mixed_policies", |b| {
            b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
        });
    }

    // --- thousand_policies_worst_case: 1000 policies, action matches none (fail-closed scan) ---
    {
        let policies = generate_throughput_policies(1000);
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        // Use an action that matches no specific tool pattern, forcing full scan
        let action = make_action(
            "nonexistent_tool_xyz",
            "nonexistent_fn",
            json!({"irrelevant": true}),
        );

        group.throughput(Throughput::Elements(1));
        group.bench_function("thousand_policies_worst_case", |b| {
            b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 2: concurrent_throughput
// ---------------------------------------------------------------------------

fn concurrent_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_throughput");

    let policies = generate_throughput_policies(50);
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = make_action(
        "file_tool",
        "read",
        json!({"path": "/workspace/dir_0/test.txt"}),
    );

    const ITERS_PER_THREAD: u64 = 10_000;

    for thread_count in [4u64, 8, 16] {
        let total_elements = thread_count * ITERS_PER_THREAD;
        group.throughput(Throughput::Elements(total_elements));
        group.bench_with_input(
            BenchmarkId::new("parallel_eval", format!("{thread_count}_threads")),
            &thread_count,
            |b, &n_threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..n_threads)
                            .map(|_| {
                                s.spawn(|| {
                                    for _ in 0..ITERS_PER_THREAD {
                                        let _ =
                                            black_box(engine.evaluate_action(
                                                black_box(&action),
                                                black_box(&[]),
                                            ));
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 3: multi_tenant_overhead
// ---------------------------------------------------------------------------

fn multi_tenant_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_tenant_overhead");

    let all_policies = generate_throughput_policies(100);
    let action = make_action(
        "http_request",
        "execute",
        json!({"url": "https://api.example.com/data"}),
    );

    // --- no_tenant_filter: evaluate against all 100 policies ---
    {
        let engine = PolicyEngine::with_policies(false, &all_policies).unwrap();
        group.throughput(Throughput::Elements(1));
        group.bench_function("no_tenant_filter", |b| {
            b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
        });
    }

    // --- tenant_filter_10pct: pre-filter to ~10 policies ---
    {
        let subset: Vec<Policy> = all_policies
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 10 == 0)
            .map(|(_, p)| p.clone())
            .collect();
        let engine = PolicyEngine::with_policies(false, &subset).unwrap();
        group.throughput(Throughput::Elements(1));
        group.bench_function("tenant_filter_10pct", |b| {
            b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
        });
    }

    // --- tenant_filter_1pct: pre-filter to ~1 policy ---
    {
        let subset: Vec<Policy> = all_policies
            .iter()
            .take(1)
            .cloned()
            .chain(std::iter::once(make_allow_policy("*", 0)))
            .collect();
        let engine = PolicyEngine::with_policies(false, &subset).unwrap();
        group.throughput(Throughput::Elements(1));
        group.bench_function("tenant_filter_1pct", |b| {
            b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 4: batch_evaluation
// ---------------------------------------------------------------------------

fn batch_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_evaluation");

    let policies = generate_throughput_policies(50);
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    for batch_size in [10u64, 100, 1000] {
        let actions = generate_diverse_actions(batch_size as usize);

        group.throughput(Throughput::Elements(batch_size));
        group.bench_with_input(
            BenchmarkId::new("batch", batch_size),
            &actions,
            |b, actions| {
                b.iter(|| {
                    for action in actions {
                        let _ =
                            black_box(engine.evaluate_action(black_box(action), black_box(&[])));
                    }
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 5: cache_hit_throughput
// ---------------------------------------------------------------------------

fn cache_hit_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hit_throughput");

    let policies = generate_throughput_policies(50);
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // --- same_action_100_repeats ---
    {
        let action = make_action(
            "file_tool",
            "read",
            json!({"path": "/workspace/dir_0/test.txt"}),
        );
        let repeats: u64 = 100;
        group.throughput(Throughput::Elements(repeats));
        group.bench_function("same_action_100_repeats", |b| {
            b.iter(|| {
                for _ in 0..repeats {
                    let _ = black_box(engine.evaluate_action(black_box(&action), black_box(&[])));
                }
            })
        });
    }

    // --- same_action_1000_repeats ---
    {
        let action = make_action(
            "file_tool",
            "read",
            json!({"path": "/workspace/dir_0/test.txt"}),
        );
        let repeats: u64 = 1000;
        group.throughput(Throughput::Elements(repeats));
        group.bench_function("same_action_1000_repeats", |b| {
            b.iter(|| {
                for _ in 0..repeats {
                    let _ = black_box(engine.evaluate_action(black_box(&action), black_box(&[])));
                }
            })
        });
    }

    // --- alternating_2_actions ---
    {
        let action_a = make_action(
            "file_tool",
            "read",
            json!({"path": "/workspace/dir_0/test.txt"}),
        );
        let action_b = make_action(
            "http_tool",
            "request",
            json!({"url": "https://api.example.com/data"}),
        );
        let total: u64 = 1000;
        group.throughput(Throughput::Elements(total));
        group.bench_function("alternating_2_actions", |b| {
            b.iter(|| {
                for i in 0..total {
                    let action = if i % 2 == 0 { &action_a } else { &action_b };
                    let _ = black_box(engine.evaluate_action(black_box(action), black_box(&[])));
                }
            })
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Group and main
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    sustained_throughput,
    concurrent_throughput,
    multi_tenant_overhead,
    batch_evaluation,
    cache_hit_throughput,
);
criterion_main!(benches);
