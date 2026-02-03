//! Benchmark: How does conditional policy evaluation scale?
//! Measures throughput with varying numbers of condition keys.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example conditional_scaling_benchmark

use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType};
use serde_json::json;
use std::time::Instant;

fn make_conditional_policy(num_forbidden: usize, num_required: usize) -> Policy {
    let forbidden: Vec<String> = (0..num_forbidden)
        .map(|i| format!("forbidden_{}", i))
        .collect();
    let required: Vec<String> = (0..num_required)
        .map(|i| format!("required_{}", i))
        .collect();

    Policy {
        id: "*".to_string(),
        name: "conditional-bench".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "forbidden_parameters": forbidden,
                "required_parameters": required,
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

fn make_action_with_params(num_params: usize) -> Action {
    let mut params = serde_json::Map::new();
    for i in 0..num_params {
        params.insert(
            format!("required_{}", i),
            serde_json::Value::String(format!("val_{}", i)),
        );
    }
    Action::new(
        "tool".to_string(),
        "func".to_string(),
        serde_json::Value::Object(params),
    )
}

fn main() {
    let engine = PolicyEngine::new(false);
    let iterations = 50_000;

    println!("Conditional Policy Scaling Benchmark");
    println!("====================================");
    println!();

    // Vary forbidden parameter count
    println!(
        "Forbidden parameter count scaling ({} iterations each):",
        iterations
    );
    println!("{:<15} {:>12} {:>12}", "Forbidden", "Total", "Per-eval");
    println!("{}", "-".repeat(39));

    for &count in &[0, 5, 10, 50, 100] {
        let policy = make_conditional_policy(count, 0);
        let action = make_action_with_params(0);
        let policies = vec![policy];

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = engine.evaluate_action(&action, &policies);
        }
        let elapsed = start.elapsed();

        println!(
            "{:<15} {:>12.2?} {:>12.0?}",
            count,
            elapsed,
            elapsed / iterations as u32
        );
    }

    println!();

    // Vary required parameter count (all present in action)
    println!(
        "Required parameter count scaling ({} iterations each):",
        iterations
    );
    println!("{:<15} {:>12} {:>12}", "Required", "Total", "Per-eval");
    println!("{}", "-".repeat(39));

    for &count in &[0, 5, 10, 50, 100] {
        let policy = make_conditional_policy(0, count);
        let action = make_action_with_params(count);
        let policies = vec![policy];

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = engine.evaluate_action(&action, &policies);
        }
        let elapsed = start.elapsed();

        println!(
            "{:<15} {:>12.2?} {:>12.0?}",
            count,
            elapsed,
            elapsed / iterations as u32
        );
    }

    println!();

    // Combined: both forbidden and required
    println!(
        "Combined forbidden+required scaling ({} iterations each):",
        iterations
    );
    println!(
        "{:<10} {:<10} {:>12} {:>12}",
        "Forbidden", "Required", "Total", "Per-eval"
    );
    println!("{}", "-".repeat(44));

    for &(f, r) in &[(5, 5), (10, 10), (25, 25), (50, 50)] {
        let policy = make_conditional_policy(f, r);
        let action = make_action_with_params(r);
        let policies = vec![policy];

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = engine.evaluate_action(&action, &policies);
        }
        let elapsed = start.elapsed();

        println!(
            "{:<10} {:<10} {:>12.2?} {:>12.0?}",
            f,
            r,
            elapsed,
            elapsed / iterations as u32
        );
    }
}
