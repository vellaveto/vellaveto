//! Benchmark-style example measuring engine evaluation throughput.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example engine_benchmark

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType};
use serde_json::json;
use std::time::Instant;

fn make_policies(count: usize) -> Vec<Policy> {
    let mut policies = Vec::with_capacity(count);
    for i in 0..count {
        policies.push(Policy {
            id: format!("tool_{}:func_{}", i % 50, i % 20),
            name: format!("Policy {}", i),
            policy_type: match i % 3 {
                0 => PolicyType::Allow,
                1 => PolicyType::Deny,
                _ => PolicyType::Conditional {
                    conditions: json!({
                        "forbidden_parameters": ["dangerous"],
                        "require_approval": false
                    }),
                },
            },
            priority: (i as i32) * 2,
            path_rules: None,
            network_rules: None,
        });
    }
    policies
}

fn make_actions(count: usize) -> Vec<Action> {
    (0..count)
        .map(|i| {
            Action::new(
                format!("tool_{}", i % 50),
                format!("func_{}", i % 20),
                json!({"key": format!("value_{}", i)}),
            )
        })
        .collect()
}

fn bench_evaluation(engine: &PolicyEngine, actions: &[Action], policies: &[Policy], label: &str) {
    let start = Instant::now();
    let mut allow_count = 0u64;
    let mut deny_count = 0u64;
    let mut approval_count = 0u64;

    for action in actions {
        match engine.evaluate_action(action, policies) {
            Ok(sentinel_types::Verdict::Allow) => allow_count += 1,
            Ok(sentinel_types::Verdict::Deny { .. }) => deny_count += 1,
            Ok(sentinel_types::Verdict::RequireApproval { .. }) => approval_count += 1,
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    let elapsed = start.elapsed();
    let ops_per_sec = actions.len() as f64 / elapsed.as_secs_f64();

    println!("--- {} ---", label);
    println!("  Actions evaluated: {}", actions.len());
    println!("  Policies in set:   {}", policies.len());
    println!("  Elapsed:           {:.2?}", elapsed);
    println!("  Throughput:        {:.0} evals/sec", ops_per_sec);
    println!(
        "  Results:           allow={}, deny={}, approval={}",
        allow_count, deny_count, approval_count
    );
    println!();
}

fn main() {
    let engine = PolicyEngine::new(false);
    let strict_engine = PolicyEngine::new(true);

    println!("=== Sentinel Engine Benchmark ===\n");

    // Small policy set (10 policies, 1000 actions)
    let small_policies = make_policies(10);
    let actions_1k = make_actions(1_000);
    bench_evaluation(
        &engine,
        &actions_1k,
        &small_policies,
        "10 policies × 1K actions",
    );

    // Medium policy set (100 policies, 10000 actions)
    let medium_policies = make_policies(100);
    let actions_10k = make_actions(10_000);
    bench_evaluation(
        &engine,
        &actions_10k,
        &medium_policies,
        "100 policies × 10K actions",
    );

    // Large policy set (1000 policies, 10000 actions)
    let large_policies = make_policies(1_000);
    bench_evaluation(
        &engine,
        &actions_10k,
        &large_policies,
        "1000 policies × 10K actions",
    );

    // Strict mode comparison
    bench_evaluation(
        &strict_engine,
        &actions_10k,
        &medium_policies,
        "100 policies × 10K actions (strict)",
    );

    // Worst case: many conditional policies with complex conditions
    let conditional_policies: Vec<Policy> = (0..200)
        .map(|i| Policy {
            id: "*".to_string(),
            name: format!("Conditional {}", i),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "forbidden_parameters": ["param_a", "param_b", "param_c"],
                    "required_parameters": ["auth"],
                    "require_approval": false
                }),
            },
            priority: i,
            path_rules: None,
            network_rules: None,
        })
        .collect();
    let actions_with_params: Vec<Action> = (0..5_000)
        .map(|i| {
            Action::new(
                "api".to_string(),
                "call".to_string(),
                json!({"auth": "token", "data": format!("payload_{}", i)}),
            )
        })
        .collect();
    bench_evaluation(
        &engine,
        &actions_with_params,
        &conditional_policies,
        "200 conditional policies × 5K actions",
    );

    println!("=== Benchmark Complete ===");
}
