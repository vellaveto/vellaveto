//! Criterion benchmarks for sentinel-engine policy evaluation.
//!
//! Validates that evaluation latency stays under 5ms for realistic workloads.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: params,
    }
}

fn make_allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Allow {}", id),
        policy_type: PolicyType::Allow,
        priority,
    }
}

fn make_deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Deny {}", id),
        policy_type: PolicyType::Deny,
        priority,
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
    }
}

/// Generate N mixed policies (allow + deny + conditional) with varied patterns.
fn generate_mixed_policies(n: usize) -> Vec<Policy> {
    let mut policies = Vec::with_capacity(n);
    for i in 0..n {
        let priority = (n - i) as i32;
        match i % 4 {
            0 => policies.push(make_allow_policy(&format!("tool_{}:*", i), priority)),
            1 => policies.push(make_deny_policy(&format!("blocked_{}:*", i), priority)),
            2 => policies.push(make_conditional_glob_policy(
                &format!("glob_{}:*", i),
                "path",
                &format!("/restricted/dir_{}/**", i),
                priority,
            )),
            _ => policies.push(make_conditional_regex_policy(
                &format!("regex_{}:*", i),
                "command",
                &format!("^(rm|delete|drop).*item_{}", i),
                priority,
            )),
        }
    }
    // Add a catch-all allow at the bottom
    policies.push(make_allow_policy("*", 0));
    policies
}

// ---------------------------------------------------------------------------
// Benchmarks: Policy Evaluation
// ---------------------------------------------------------------------------

fn bench_single_policy_exact_match(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);
    let policies = vec![make_allow_policy("file:read", 100)];
    let action = make_action("file", "read", json!({"path": "/tmp/test.txt"}));

    c.bench_function("eval/single_policy_exact", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });
}

fn bench_single_policy_wildcard(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);
    let policies = vec![make_allow_policy("*", 100)];
    let action = make_action("file", "read", json!({"path": "/tmp/test.txt"}));

    c.bench_function("eval/single_policy_wildcard", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });
}

fn bench_single_policy_no_match(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);
    let policies = vec![make_deny_policy("bash:*", 100)];
    let action = make_action("file", "read", json!({"path": "/tmp/test.txt"}));

    c.bench_function("eval/single_policy_no_match", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });
}

fn bench_100_policies(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);
    let mut policies = generate_mixed_policies(100);
    PolicyEngine::sort_policies(&mut policies);
    let action = make_action("unknown_tool", "unknown_fn", json!({"path": "/tmp/safe"}));

    c.bench_function("eval/100_policies_fallthrough", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });
}

fn bench_100_policies_early_match(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);
    let mut policies = generate_mixed_policies(100);
    PolicyEngine::sort_policies(&mut policies);
    // Match the highest-priority policy (tool_0:*)
    let action = make_action("tool_0", "anything", json!({}));

    c.bench_function("eval/100_policies_early_match", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });
}

fn bench_1000_policies(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);
    let mut policies = generate_mixed_policies(1000);
    PolicyEngine::sort_policies(&mut policies);
    let action = make_action("unknown_tool", "unknown_fn", json!({"path": "/tmp/safe"}));

    c.bench_function("eval/1000_policies_fallthrough", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });
}

fn bench_policy_count_scaling(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);
    let action = make_action("unknown_tool", "unknown_fn", json!({"path": "/tmp/safe"}));

    let mut group = c.benchmark_group("eval/scaling");
    for count in [10, 50, 100, 250, 500, 1000] {
        let mut policies = generate_mixed_policies(count);
        PolicyEngine::sort_policies(&mut policies);
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &policies,
            |b, policies| {
                b.iter(|| engine.evaluate_action(black_box(&action), black_box(policies)))
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: normalize_path
// ---------------------------------------------------------------------------

fn bench_normalize_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalize_path");

    group.bench_function("clean", |b| {
        b.iter(|| PolicyEngine::normalize_path(black_box("/usr/local/bin/program")))
    });

    group.bench_function("traversal", |b| {
        b.iter(|| PolicyEngine::normalize_path(black_box("/home/user/../../etc/passwd")))
    });

    group.bench_function("encoded_simple", |b| {
        b.iter(|| PolicyEngine::normalize_path(black_box("/etc/%70asswd")))
    });

    group.bench_function("encoded_traversal", |b| {
        b.iter(|| PolicyEngine::normalize_path(black_box("/%2E%2E/%2E%2E/etc/passwd")))
    });

    group.bench_function("double_encoded", |b| {
        b.iter(|| PolicyEngine::normalize_path(black_box("/etc/%2570asswd")))
    });

    group.bench_function("null_byte", |b| {
        b.iter(|| PolicyEngine::normalize_path(black_box("/etc/passwd\0.txt")))
    });

    group.bench_function("long_path", |b| {
        let path = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z".to_string();
        b.iter(|| PolicyEngine::normalize_path(black_box(&path)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: extract_domain
// ---------------------------------------------------------------------------

fn bench_extract_domain(c: &mut Criterion) {
    let mut group = c.benchmark_group("extract_domain");

    group.bench_function("simple", |b| {
        b.iter(|| PolicyEngine::extract_domain(black_box("https://example.com/path")))
    });

    group.bench_function("with_port", |b| {
        b.iter(|| PolicyEngine::extract_domain(black_box("https://example.com:8443/api")))
    });

    group.bench_function("with_userinfo", |b| {
        b.iter(|| PolicyEngine::extract_domain(black_box("https://user:pass@example.com/api")))
    });

    group.bench_function("ipv6", |b| {
        b.iter(|| PolicyEngine::extract_domain(black_box("https://[::1]:8080/api")))
    });

    group.bench_function("encoded", |b| {
        b.iter(|| PolicyEngine::extract_domain(black_box("https://evil%2ecom/exfil")))
    });

    group.bench_function("no_scheme", |b| {
        b.iter(|| PolicyEngine::extract_domain(black_box("example.com:443/path?query=1")))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Regex constraint matching
// ---------------------------------------------------------------------------

fn bench_regex_constraint(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);

    let mut group = c.benchmark_group("constraint/regex");

    // Simple regex pattern
    let simple_policies = vec![make_conditional_regex_policy(
        "*",
        "command",
        "^rm\\s+-rf",
        100,
    )];
    let dangerous_action = make_action("bash", "execute", json!({"command": "rm -rf /tmp/test"}));
    let safe_action = make_action("bash", "execute", json!({"command": "ls -la /tmp"}));

    group.bench_function("simple_match", |b| {
        b.iter(|| engine.evaluate_action(black_box(&dangerous_action), black_box(&simple_policies)))
    });

    group.bench_function("simple_no_match", |b| {
        b.iter(|| engine.evaluate_action(black_box(&safe_action), black_box(&simple_policies)))
    });

    // Complex regex pattern
    let complex_policies = vec![make_conditional_regex_policy(
        "*",
        "command",
        r"^(rm|delete|drop|truncate|alter)\s+(-[a-zA-Z]+\s+)*(.*\b(\/etc|\/var|\/usr|\/root)\b.*)",
        100,
    )];

    group.bench_function("complex_match", |b| {
        let action = make_action(
            "bash",
            "execute",
            json!({"command": "rm -rf /etc/important"}),
        );
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&complex_policies)))
    });

    group.bench_function("complex_no_match", |b| {
        let action = make_action("bash", "execute", json!({"command": "echo hello world"}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&complex_policies)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Glob constraint matching
// ---------------------------------------------------------------------------

fn bench_glob_constraint(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);

    let mut group = c.benchmark_group("constraint/glob");

    let policies = vec![make_conditional_glob_policy("*", "path", "/etc/**", 100)];

    group.bench_function("match", |b| {
        let action = make_action("file", "read", json!({"path": "/etc/passwd"}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });

    group.bench_function("no_match", |b| {
        let action = make_action("file", "read", json!({"path": "/tmp/safe.txt"}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });

    // Glob with encoded path (triggers normalize_path)
    group.bench_function("encoded_path_match", |b| {
        let action = make_action("file", "read", json!({"path": "/%65tc/passwd"}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Wildcard recursive scanning (param: "*")
// ---------------------------------------------------------------------------

fn bench_wildcard_scan(c: &mut Criterion) {
    let engine = PolicyEngine::new(false);

    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Deep scan".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "*",
                    "op": "glob",
                    "pattern": "/etc/**",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
    }];

    let mut group = c.benchmark_group("constraint/wildcard_scan");

    // Small params (5 string values)
    group.bench_function("small_params", |b| {
        let action = make_action(
            "tool",
            "fn",
            json!({
                "a": "/tmp/safe1",
                "b": "/tmp/safe2",
                "c": "/home/user/file",
                "d": "plain text",
                "e": "/var/log/app.log"
            }),
        );
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });

    // Medium params (nested, ~20 string values)
    group.bench_function("medium_params", |b| {
        let action = make_action(
            "tool",
            "fn",
            json!({
                "config": {
                    "input": "/tmp/in",
                    "output": "/tmp/out",
                    "log": "/var/log/app.log",
                    "backup": "/home/user/backup"
                },
                "items": [
                    "/tmp/a", "/tmp/b", "/tmp/c", "/tmp/d",
                    "/tmp/e", "/tmp/f", "/tmp/g", "/tmp/h"
                ],
                "metadata": {
                    "author": "user",
                    "version": "1.0",
                    "tags": ["safe", "test", "benchmark"],
                    "paths": {
                        "src": "/home/user/src",
                        "dist": "/home/user/dist"
                    }
                }
            }),
        );
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&policies)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group and main
// ---------------------------------------------------------------------------

criterion_group!(
    eval_benches,
    bench_single_policy_exact_match,
    bench_single_policy_wildcard,
    bench_single_policy_no_match,
    bench_100_policies,
    bench_100_policies_early_match,
    bench_1000_policies,
    bench_policy_count_scaling,
);

criterion_group!(path_benches, bench_normalize_path, bench_extract_domain,);

criterion_group!(
    constraint_benches,
    bench_regex_constraint,
    bench_glob_constraint,
    bench_wildcard_scan,
);

criterion_main!(eval_benches, path_benches, constraint_benches);
