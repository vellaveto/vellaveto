//! Criterion benchmarks for sentinel-engine policy evaluation.
//!
//! Validates that evaluation latency stays under 5ms for realistic workloads.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, NetworkRules, PathRules, Policy, PolicyType};
use serde_json::json;

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
        b.iter(|| {
            let _ = PolicyEngine::normalize_path(black_box("/etc/passwd\0.txt"));
        })
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
        path_rules: None,
        network_rules: None,
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
// Benchmarks: COMPILED evaluation path (production hot path)
// ---------------------------------------------------------------------------
// The compiled path uses PolicyEngine::with_policies() which pre-compiles
// regex, glob, and tool matchers at load time. This is the actual path used
// in production — zero Mutex, zero runtime compilation.

fn bench_compiled_single_policy(c: &mut Criterion) {
    let policies = vec![make_allow_policy("file:read", 100)];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = make_action("file", "read", json!({"path": "/tmp/test.txt"}));

    c.bench_function("compiled/single_policy_exact", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });
}

fn bench_compiled_wildcard(c: &mut Criterion) {
    let policies = vec![make_allow_policy("*", 100)];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = make_action("file", "read", json!({"path": "/tmp/test.txt"}));

    c.bench_function("compiled/single_policy_wildcard", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });
}

fn bench_compiled_100_policies(c: &mut Criterion) {
    let mut policies = generate_mixed_policies(100);
    PolicyEngine::sort_policies(&mut policies);
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = make_action("unknown_tool", "unknown_fn", json!({"path": "/tmp/safe"}));

    c.bench_function("compiled/100_policies_fallthrough", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });
}

fn bench_compiled_100_early_match(c: &mut Criterion) {
    let mut policies = generate_mixed_policies(100);
    PolicyEngine::sort_policies(&mut policies);
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = make_action("tool_0", "anything", json!({}));

    c.bench_function("compiled/100_policies_early_match", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });
}

fn bench_compiled_1000_policies(c: &mut Criterion) {
    let mut policies = generate_mixed_policies(1000);
    PolicyEngine::sort_policies(&mut policies);
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = make_action("unknown_tool", "unknown_fn", json!({"path": "/tmp/safe"}));

    c.bench_function("compiled/1000_policies_fallthrough", |b| {
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });
}

fn bench_compiled_scaling(c: &mut Criterion) {
    let action = make_action("unknown_tool", "unknown_fn", json!({"path": "/tmp/safe"}));

    let mut group = c.benchmark_group("compiled/scaling");
    for count in [10, 50, 100, 250, 500, 1000] {
        let mut policies = generate_mixed_policies(count);
        PolicyEngine::sort_policies(&mut policies);
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(count), &engine, |b, engine| {
            b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
        });
    }
    group.finish();
}

fn bench_compiled_conditional_glob(c: &mut Criterion) {
    let policies = vec![
        make_conditional_glob_policy("*:*:cred-block", "path", "/home/*/.aws/**", 300),
        make_allow_policy("*", 1),
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("compiled/conditional_glob");

    group.bench_function("deny_match", |b| {
        let action = make_action(
            "file",
            "read",
            json!({"path": "/home/user/.aws/credentials"}),
        );
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("allow_no_match", |b| {
        let action = make_action("file", "read", json!({"path": "/tmp/safe.txt"}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.finish();
}

fn bench_compiled_conditional_regex(c: &mut Criterion) {
    let policies = vec![
        make_conditional_regex_policy(
            "*:*:dangerous",
            "command",
            r"(?i)(rm\s+-rf|dd\s+if=|mkfs)",
            300,
        ),
        make_allow_policy("*", 1),
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("compiled/conditional_regex");

    group.bench_function("deny_match", |b| {
        let action = make_action("bash", "execute", json!({"command": "rm -rf /important"}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("allow_no_match", |b| {
        let action = make_action("bash", "execute", json!({"command": "ls -la /tmp"}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.finish();
}

fn bench_compiled_on_no_match_chain(c: &mut Criterion) {
    // Benchmark the on_no_match="continue" policy chain (demo scenario)
    let policies = vec![
        Policy {
            id: "*:*:credential-block".to_string(),
            name: "Block credential access".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "glob",
                        "pattern": "/home/*/.aws/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*:domain-block".to_string(),
            name: "Block evil domains".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "domain_match",
                        "pattern": "*.evil.com",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 280,
            path_rules: None,
            network_rules: None,
        },
        make_allow_policy("*", 1),
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("compiled/on_no_match_chain");

    group.bench_function("credential_deny", |b| {
        let action = make_action(
            "file",
            "read",
            json!({"path": "/home/user/.aws/credentials"}),
        );
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("domain_deny", |b| {
        let action = make_action(
            "http",
            "get",
            json!({"url": "https://exfil.evil.com/steal"}),
        );
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("safe_allow", |b| {
        let action = make_action("file", "read", json!({"path": "/tmp/safe.txt"}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Path rules (PathRules struct on compiled policies)
// ---------------------------------------------------------------------------

fn bench_path_rules_blocked(c: &mut Criterion) {
    let policies = vec![Policy {
        id: "file:*:path-block".to_string(),
        name: "Block sensitive paths".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: Some(PathRules {
            allowed: vec![],
            blocked: vec![
                "/home/*/.aws/**".to_string(),
                "/home/*/.ssh/**".to_string(),
                "/etc/shadow".to_string(),
                "/etc/passwd".to_string(),
                "/root/**".to_string(),
            ],
        }),
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("path_rules");

    group.bench_function("blocked_match", |b| {
        let mut action = make_action("file", "read", json!({}));
        action.target_paths = vec!["/home/user/.aws/credentials".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("not_blocked", |b| {
        let mut action = make_action("file", "read", json!({}));
        action.target_paths = vec!["/tmp/safe.txt".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("traversal_blocked", |b| {
        let mut action = make_action("file", "read", json!({}));
        action.target_paths = vec!["/tmp/../home/user/.aws/credentials".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("no_target_paths", |b| {
        let action = make_action("file", "read", json!({}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.finish();
}

fn bench_path_rules_allowed(c: &mut Criterion) {
    let policies = vec![Policy {
        id: "file:*:path-allow".to_string(),
        name: "Allow only safe dirs".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: Some(PathRules {
            allowed: vec![
                "/tmp/**".to_string(),
                "/home/user/workspace/**".to_string(),
                "/var/log/**".to_string(),
            ],
            blocked: vec![],
        }),
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("path_rules_allowlist");

    group.bench_function("in_allowed_set", |b| {
        let mut action = make_action("file", "read", json!({}));
        action.target_paths = vec!["/tmp/test.txt".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("not_in_allowed_set", |b| {
        let mut action = make_action("file", "read", json!({}));
        action.target_paths = vec!["/etc/config.ini".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Network rules (NetworkRules struct on compiled policies)
// ---------------------------------------------------------------------------

fn bench_network_rules_blocked(c: &mut Criterion) {
    let policies = vec![Policy {
        id: "http:*:net-block".to_string(),
        name: "Block exfil domains".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![
                "*.ngrok.io".to_string(),
                "*.requestbin.com".to_string(),
                "*.pipedream.net".to_string(),
                "*.evil.com".to_string(),
                "*.pastebin.com".to_string(),
            ],
            ip_rules: None,
        }),
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("network_rules");

    group.bench_function("blocked_match", |b| {
        let mut action = make_action("http", "get", json!({}));
        action.target_domains = vec!["exfil.evil.com".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("not_blocked", |b| {
        let mut action = make_action("http", "get", json!({}));
        action.target_domains = vec!["api.example.com".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("no_target_domains", |b| {
        let action = make_action("http", "get", json!({}));
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.finish();
}

fn bench_network_rules_allowed(c: &mut Criterion) {
    let policies = vec![Policy {
        id: "http:*:net-allow".to_string(),
        name: "Domain allowlist".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![
                "api.example.com".to_string(),
                "*.internal.corp".to_string(),
                "cdn.trusted.net".to_string(),
            ],
            blocked_domains: vec![],
            ip_rules: None,
        }),
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("network_rules_allowlist");

    group.bench_function("in_allowed_set", |b| {
        let mut action = make_action("http", "get", json!({}));
        action.target_domains = vec!["api.example.com".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("wildcard_allowed", |b| {
        let mut action = make_action("http", "get", json!({}));
        action.target_domains = vec!["svc.internal.corp".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.bench_function("not_in_allowed_set", |b| {
        let mut action = make_action("http", "get", json!({}));
        action.target_domains = vec!["attacker.com".to_string()];
        b.iter(|| engine.evaluate_action(black_box(&action), black_box(&[])))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: match_domain_pattern (direct)
// ---------------------------------------------------------------------------

fn bench_match_domain_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("match_domain_pattern");

    group.bench_function("exact_match", |b| {
        b.iter(|| {
            PolicyEngine::match_domain_pattern(black_box("example.com"), black_box("example.com"))
        })
    });

    group.bench_function("wildcard_match", |b| {
        b.iter(|| {
            PolicyEngine::match_domain_pattern(
                black_box("api.example.com"),
                black_box("*.example.com"),
            )
        })
    });

    group.bench_function("wildcard_no_match", |b| {
        b.iter(|| {
            PolicyEngine::match_domain_pattern(
                black_box("notexample.com"),
                black_box("*.example.com"),
            )
        })
    });

    group.bench_function("deep_subdomain", |b| {
        b.iter(|| {
            PolicyEngine::match_domain_pattern(
                black_box("a.b.c.d.example.com"),
                black_box("*.example.com"),
            )
        })
    });

    group.bench_function("case_insensitive", |b| {
        b.iter(|| {
            PolicyEngine::match_domain_pattern(
                black_box("API.EXAMPLE.COM"),
                black_box("*.example.com"),
            )
        })
    });

    group.bench_function("no_match", |b| {
        b.iter(|| {
            PolicyEngine::match_domain_pattern(
                black_box("totally-different.org"),
                black_box("*.example.com"),
            )
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: with_policies() compilation cost
// ---------------------------------------------------------------------------

fn bench_compile_policies(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile_policies");

    group.bench_function("10_policies", |b| {
        let policies = generate_mixed_policies(10);
        b.iter(|| PolicyEngine::with_policies(false, black_box(&policies)))
    });

    group.bench_function("50_policies", |b| {
        let policies = generate_mixed_policies(50);
        b.iter(|| PolicyEngine::with_policies(false, black_box(&policies)))
    });

    group.bench_function("100_policies", |b| {
        let policies = generate_mixed_policies(100);
        b.iter(|| PolicyEngine::with_policies(false, black_box(&policies)))
    });

    group.bench_function("500_policies", |b| {
        let policies = generate_mixed_policies(500);
        b.iter(|| PolicyEngine::with_policies(false, black_box(&policies)))
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

criterion_group!(
    path_benches,
    bench_normalize_path,
    bench_extract_domain,
    bench_match_domain_pattern,
);

criterion_group!(
    constraint_benches,
    bench_regex_constraint,
    bench_glob_constraint,
    bench_wildcard_scan,
);

criterion_group!(
    compiled_benches,
    bench_compiled_single_policy,
    bench_compiled_wildcard,
    bench_compiled_100_policies,
    bench_compiled_100_early_match,
    bench_compiled_1000_policies,
    bench_compiled_scaling,
    bench_compiled_conditional_glob,
    bench_compiled_conditional_regex,
    bench_compiled_on_no_match_chain,
);

criterion_group!(
    rules_benches,
    bench_path_rules_blocked,
    bench_path_rules_allowed,
    bench_network_rules_blocked,
    bench_network_rules_allowed,
);

criterion_group!(compile_benches, bench_compile_policies,);

// ---------------------------------------------------------------------------
// Benchmarks: Context-aware evaluation (session state)
// ---------------------------------------------------------------------------

fn bench_context_forbidden_previous_action(c: &mut Criterion) {
    use sentinel_types::EvaluationContext;

    let policies = vec![
        Policy {
            id: "http_request:*".to_string(),
            name: "Block exfil after read".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "context_conditions": [
                        {"type": "forbidden_previous_action", "forbidden_tool": "read_file"}
                    ],
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        make_allow_policy("*", 1),
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("context/forbidden_previous");

    group.bench_function("deny_with_match", |b| {
        let action = make_action(
            "http_request",
            "execute",
            json!({"url": "https://evil.com"}),
        );
        let ctx = EvaluationContext {
            previous_actions: vec!["read_file".to_string(), "list_files".to_string()],
            ..Default::default()
        };
        b.iter(|| {
            engine.evaluate_action_with_context(
                black_box(&action),
                black_box(&[]),
                Some(black_box(&ctx)),
            )
        })
    });

    group.bench_function("allow_no_match", |b| {
        let action = make_action(
            "http_request",
            "execute",
            json!({"url": "https://safe.com"}),
        );
        let ctx = EvaluationContext {
            previous_actions: vec!["list_files".to_string()],
            ..Default::default()
        };
        b.iter(|| {
            engine.evaluate_action_with_context(
                black_box(&action),
                black_box(&[]),
                Some(black_box(&ctx)),
            )
        })
    });

    group.bench_function("large_history_100", |b| {
        let action = make_action("http_request", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: (0..100).map(|i| format!("tool_{}", i)).collect(),
            ..Default::default()
        };
        b.iter(|| {
            engine.evaluate_action_with_context(
                black_box(&action),
                black_box(&[]),
                Some(black_box(&ctx)),
            )
        })
    });

    group.finish();
}

fn bench_context_max_calls_in_window(c: &mut Criterion) {
    use sentinel_types::EvaluationContext;

    let policies = vec![
        Policy {
            id: "read_file:*".to_string(),
            name: "Rate limit reads".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "context_conditions": [
                        {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 10, "window": 20}
                    ],
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        make_allow_policy("*", 1),
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let mut group = c.benchmark_group("context/max_calls_window");

    group.bench_function("under_limit", |b| {
        let action = make_action("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec!["read_file".to_string(); 5],
            ..Default::default()
        };
        b.iter(|| {
            engine.evaluate_action_with_context(
                black_box(&action),
                black_box(&[]),
                Some(black_box(&ctx)),
            )
        })
    });

    group.bench_function("at_limit_deny", |b| {
        let action = make_action("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec!["read_file".to_string(); 15],
            ..Default::default()
        };
        b.iter(|| {
            engine.evaluate_action_with_context(
                black_box(&action),
                black_box(&[]),
                Some(black_box(&ctx)),
            )
        })
    });

    group.bench_function("large_history_window", |b| {
        let action = make_action("read_file", "execute", json!({}));
        let mut history: Vec<String> = (0..100).map(|i| format!("tool_{}", i)).collect();
        history.extend(vec!["read_file".to_string(); 5]);
        let ctx = EvaluationContext {
            previous_actions: history,
            ..Default::default()
        };
        b.iter(|| {
            engine.evaluate_action_with_context(
                black_box(&action),
                black_box(&[]),
                Some(black_box(&ctx)),
            )
        })
    });

    group.finish();
}

criterion_group!(
    context_benches,
    bench_context_forbidden_previous_action,
    bench_context_max_calls_in_window,
);

// ---------------------------------------------------------------------------
// Benchmarks: Behavioral anomaly detection (P4.1)
// ---------------------------------------------------------------------------

fn bench_behavioral_record_session(c: &mut Criterion) {
    use sentinel_engine::behavioral::{BehavioralConfig, BehavioralTracker};
    use std::collections::HashMap;

    let config = BehavioralConfig::default();
    let mut tracker = BehavioralTracker::new(config).unwrap();

    let mut call_counts: HashMap<String, u64> = HashMap::new();
    for i in 0..20 {
        call_counts.insert(format!("tool_{}", i), (i + 1) as u64);
    }

    c.bench_function("behavioral/record_session_20_tools", |b| {
        b.iter(|| {
            tracker.record_session(black_box("agent-bench"), black_box(&call_counts));
        })
    });
}

fn bench_behavioral_check_session(c: &mut Criterion) {
    use sentinel_engine::behavioral::{BehavioralConfig, BehavioralTracker};
    use std::collections::HashMap;

    let config = BehavioralConfig {
        min_sessions: 3,
        threshold: 10.0,
        alpha: 0.2,
        ..Default::default()
    };
    let mut tracker = BehavioralTracker::new(config).unwrap();

    // Establish baseline with 10 sessions
    let mut baseline: HashMap<String, u64> = HashMap::new();
    for i in 0..20 {
        baseline.insert(format!("tool_{}", i), 5);
    }
    for _ in 0..10 {
        tracker.record_session("agent-bench", &baseline);
    }

    // Check with slightly varied counts
    let mut check_counts: HashMap<String, u64> = HashMap::new();
    for i in 0..20 {
        check_counts.insert(format!("tool_{}", i), 7);
    }

    c.bench_function("behavioral/check_session_20_tools", |b| {
        b.iter(|| {
            black_box(tracker.check_session(black_box("agent-bench"), black_box(&check_counts)));
        })
    });
}

fn bench_behavioral_check_anomalous(c: &mut Criterion) {
    use sentinel_engine::behavioral::{BehavioralConfig, BehavioralTracker};
    use std::collections::HashMap;

    let config = BehavioralConfig {
        min_sessions: 3,
        threshold: 10.0,
        alpha: 0.2,
        ..Default::default()
    };
    let mut tracker = BehavioralTracker::new(config).unwrap();

    let mut baseline: HashMap<String, u64> = HashMap::new();
    for i in 0..20 {
        baseline.insert(format!("tool_{}", i), 5);
    }
    for _ in 0..10 {
        tracker.record_session("agent-bench", &baseline);
    }

    // Anomalous: all tools at 500x baseline
    let mut anomalous: HashMap<String, u64> = HashMap::new();
    for i in 0..20 {
        anomalous.insert(format!("tool_{}", i), 500);
    }

    c.bench_function("behavioral/check_session_20_tools_anomalous", |b| {
        b.iter(|| {
            black_box(tracker.check_session(black_box("agent-bench"), black_box(&anomalous)));
        })
    });
}

criterion_group!(
    behavioral_benches,
    bench_behavioral_record_session,
    bench_behavioral_check_session,
    bench_behavioral_check_anomalous,
);

criterion_main!(
    eval_benches,
    path_benches,
    constraint_benches,
    compiled_benches,
    rules_benches,
    compile_benches,
    context_benches,
    behavioral_benches
);
