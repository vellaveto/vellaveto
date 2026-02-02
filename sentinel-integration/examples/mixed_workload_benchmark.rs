//! Benchmark: Mixed workload measuring engine evaluation + audit logging together.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example mixed_workload_benchmark

use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, PolicyType};
use serde_json::json;
use std::time::Instant;

fn make_policies() -> Vec<Policy> {
    vec![
        Policy {
            id: "file:read".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        },
        Policy {
            id: "file:delete".to_string(),
            name: "Block file deletes".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
        },
        Policy {
            id: "shell:*".to_string(),
            name: "Shell requires approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 50,
        },
        Policy {
            id: "net:*".to_string(),
            name: "Network conditional".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "forbidden_parameters": ["exfiltrate", "upload_credentials"],
                    "required_parameters": ["auth_token"],
                }),
            },
            priority: 80,
        },
    ]
}

fn make_actions() -> Vec<Action> {
    vec![
        Action {
            tool: "file".to_string(),
            function: "read".to_string(),
            parameters: json!({"path": "/etc/config"}),
        },
        Action {
            tool: "file".to_string(),
            function: "delete".to_string(),
            parameters: json!({"path": "/tmp/data"}),
        },
        Action {
            tool: "shell".to_string(),
            function: "exec".to_string(),
            parameters: json!({"cmd": "ls"}),
        },
        Action {
            tool: "net".to_string(),
            function: "post".to_string(),
            parameters: json!({"auth_token": "abc"}),
        },
        Action {
            tool: "net".to_string(),
            function: "post".to_string(),
            parameters: json!({"exfiltrate": true}),
        },
        Action {
            tool: "unknown".to_string(),
            function: "mystery".to_string(),
            parameters: json!({}),
        },
    ]
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        println!("Mixed Workload Benchmark (Engine + Audit)");
        println!("==========================================");
        println!();

        let engine = PolicyEngine::new(false);
        let policies = make_policies();
        let actions = make_actions();
        let iterations = 1000;

        // Phase 1: Engine-only throughput
        let start = Instant::now();
        for _ in 0..iterations {
            for action in &actions {
                let _ = engine.evaluate_action(action, &policies);
            }
        }
        let engine_elapsed = start.elapsed();
        let engine_ops = iterations * actions.len();
        println!(
            "Engine only:  {} evals in {:?} ({:.0} evals/sec)",
            engine_ops,
            engine_elapsed,
            engine_ops as f64 / engine_elapsed.as_secs_f64()
        );

        // Phase 2: Engine + Audit together
        let tmp = tempfile::TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("bench.log"));

        let start = Instant::now();
        for _ in 0..iterations {
            for action in &actions {
                let verdict = engine.evaluate_action(action, &policies).unwrap();
                logger.log_entry(action, &verdict, json!({})).await.unwrap();
            }
        }
        let combined_elapsed = start.elapsed();
        let combined_ops = iterations * actions.len();
        println!(
            "Engine+Audit: {} evals in {:?} ({:.0} evals/sec)",
            combined_ops,
            combined_elapsed,
            combined_ops as f64 / combined_elapsed.as_secs_f64()
        );

        // Phase 3: Report generation
        let start = Instant::now();
        let report = logger.generate_report().await.unwrap();
        let report_elapsed = start.elapsed();
        println!(
            "Report gen:   {} entries in {:?}",
            report.total_entries, report_elapsed
        );

        println!();
        println!("Report summary:");
        println!("  Total:    {}", report.total_entries);
        println!("  Allow:    {}", report.allow_count);
        println!("  Deny:     {}", report.deny_count);
        println!("  Approval: {}", report.require_approval_count);

        // Sanity check
        assert_eq!(
            report.total_entries,
            report.allow_count + report.deny_count + report.require_approval_count
        );
    });
}
