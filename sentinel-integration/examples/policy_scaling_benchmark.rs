//! Benchmark: How does evaluation time scale with number of policies?
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example policy_scaling_benchmark

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType};
use serde_json::json;
use std::time::Instant;

fn make_policies(count: usize) -> Vec<Policy> {
    (0..count)
        .map(|i| Policy {
            id: format!("tool_{}:func_{}", i, i),
            name: format!("Policy {}", i),
            policy_type: if i % 2 == 0 {
                PolicyType::Allow
            } else {
                PolicyType::Deny
            },
            priority: i as i32,
        })
        .collect()
}

fn bench_evaluation(engine: &PolicyEngine, action: &Action, policies: &[Policy], iterations: usize) -> std::time::Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine.evaluate_action(action, policies);
    }
    start.elapsed()
}

fn main() {
    let engine = PolicyEngine::new(false);
    let iterations = 10_000;

    // Action that won't match any specific policy (forces full scan)
    let miss_action = Action {
        tool: "nonexistent_tool".to_string(),
        function: "nonexistent_func".to_string(),
        parameters: json!({}),
    };

    // Action that matches the first policy after sort (best case)
    let hit_action = Action {
        tool: "tool_0".to_string(),
        function: "func_0".to_string(),
        parameters: json!({}),
    };

    println!("Policy Scaling Benchmark");
    println!("========================");
    println!("Iterations per measurement: {}", iterations);
    println!();

    println!("{:<15} {:>15} {:>15} {:>15} {:>15}",
        "# Policies", "Miss Total", "Miss/iter", "Hit Total", "Hit/iter");
    println!("{}", "-".repeat(75));

    for &count in &[1, 10, 50, 100, 500, 1000, 5000] {
        let policies = make_policies(count);

        let miss_dur = bench_evaluation(&engine, &miss_action, &policies, iterations);
        let hit_dur = bench_evaluation(&engine, &hit_action, &policies, iterations);

        println!("{:<15} {:>15.2?} {:>15.2?} {:>15.2?} {:>15.2?}",
            count,
            miss_dur,
            miss_dur / iterations as u32,
            hit_dur,
            hit_dur / iterations as u32,
        );
    }

    println!();
    println!("=== Conditional Policy Scaling ===");
    println!();

    let conditional_policies: Vec<Policy> = (0..1000)
        .map(|i| Policy {
            id: format!("tool_{}:func_{}", i, i),
            name: format!("Conditional {}", i),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "forbidden_parameters": ["secret", "password", "token"],
                    "required_parameters": ["auth"],
                }),
            },
            priority: i as i32,
        })
        .collect();

    let cond_action = Action {
        tool: "tool_999".to_string(),
        function: "func_999".to_string(),
        parameters: json!({"auth": "valid", "data": "payload"}),
    };

    let dur = bench_evaluation(&engine, &cond_action, &conditional_policies, iterations);
    println!("1000 conditional policies, {} iterations: {:?} ({:?}/iter)",
        iterations, dur, dur / iterations as u32);
}