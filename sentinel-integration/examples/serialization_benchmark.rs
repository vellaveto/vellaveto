//! Benchmark: Measures serialization/deserialization throughput for core types.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example serialization_benchmark

use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;
use std::time::Instant;

fn bench_serialize<T: serde::Serialize>(label: &str, value: &T, iterations: usize) {
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = serde_json::to_string(value).unwrap();
    }
    let elapsed = start.elapsed();
    println!(
        "  {:<30} {:>10.2?} total, {:>8.0?}/op",
        label,
        elapsed,
        elapsed / iterations as u32,
    );
}

fn bench_deserialize<T: serde::de::DeserializeOwned>(
    label: &str,
    json_str: &str,
    iterations: usize,
) {
    let start = Instant::now();
    for _ in 0..iterations {
        let _: T = serde_json::from_str(json_str).unwrap();
    }
    let elapsed = start.elapsed();
    println!(
        "  {:<30} {:>10.2?} total, {:>8.0?}/op",
        label,
        elapsed,
        elapsed / iterations as u32,
    );
}

fn main() {
    let iterations = 100_000;

    println!("Serialization/Deserialization Benchmark");
    println!("=======================================");
    println!("({} iterations per measurement)", iterations);
    println!();

    // --- Action ---
    let small_action = Action {
        tool: "file".to_string(),
        function: "read".to_string(),
        parameters: json!({"path": "/tmp/x"}),
    };
    let large_action = Action {
        tool: "complex_tool".to_string(),
        function: "process_batch".to_string(),
        parameters: json!({
            "files": (0..100).map(|i| format!("/path/{}", i)).collect::<Vec<_>>(),
            "config": {"depth": 5, "recursive": true, "filters": ["*.rs", "*.toml"]},
        }),
    };

    println!("Action serialize:");
    bench_serialize("Small action", &small_action, iterations);
    bench_serialize("Large action (100 files)", &large_action, iterations);

    println!("Action deserialize:");
    let small_json = serde_json::to_string(&small_action).unwrap();
    let large_json = serde_json::to_string(&large_action).unwrap();
    bench_deserialize::<Action>("Small action", &small_json, iterations);
    bench_deserialize::<Action>("Large action (100 files)", &large_json, iterations);

    println!();

    // --- Verdict ---
    let allow = Verdict::Allow;
    let deny = Verdict::Deny {
        reason: "Blocked by policy 'strict-security-v2'".to_string(),
    };
    let approval = Verdict::RequireApproval {
        reason: "Manual review required for elevated operations".to_string(),
    };

    println!("Verdict serialize:");
    bench_serialize("Allow", &allow, iterations);
    bench_serialize("Deny (with reason)", &deny, iterations);
    bench_serialize("RequireApproval", &approval, iterations);

    println!("Verdict deserialize:");
    let allow_json = serde_json::to_string(&allow).unwrap();
    let deny_json = serde_json::to_string(&deny).unwrap();
    let approval_json = serde_json::to_string(&approval).unwrap();
    bench_deserialize::<Verdict>("Allow", &allow_json, iterations);
    bench_deserialize::<Verdict>("Deny (with reason)", &deny_json, iterations);
    bench_deserialize::<Verdict>("RequireApproval", &approval_json, iterations);

    println!();

    // --- Policy ---
    let simple_policy = Policy {
        id: "bash:*".to_string(),
        name: "Block bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
    };
    let conditional_policy = Policy {
        id: "*".to_string(),
        name: "Complex conditional".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "forbidden_parameters": ["rm", "delete", "format", "destroy"],
                "required_parameters": ["confirmation", "reason"],
                "require_approval": false,
            }),
        },
        priority: 500,
    };

    println!("Policy serialize:");
    bench_serialize("Simple (Deny)", &simple_policy, iterations);
    bench_serialize("Conditional", &conditional_policy, iterations);

    println!("Policy deserialize:");
    let simple_json = serde_json::to_string(&simple_policy).unwrap();
    let conditional_json = serde_json::to_string(&conditional_policy).unwrap();
    bench_deserialize::<Policy>("Simple (Deny)", &simple_json, iterations);
    bench_deserialize::<Policy>("Conditional", &conditional_json, iterations);
}
