// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Benchmark: Mixed workload measuring engine evaluation + audit logging together.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p vellaveto-integration --example mixed_workload_benchmark

use serde_json::json;
use std::time::Instant;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType};

fn make_policies() -> Vec<Policy> {
    vec![
        Policy {
            id: "file:read".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "file:delete".to_string(),
            name: "Block file deletes".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "shell:*".to_string(),
            name: "Shell requires approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
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
            path_rules: None,
            network_rules: None,
        },
    ]
}

fn make_actions() -> Vec<Action> {
    vec![
        Action::new(
            "file".to_string(),
            "read".to_string(),
            json!({"path": "/etc/config"}),
        ),
        Action::new(
            "file".to_string(),
            "delete".to_string(),
            json!({"path": "/tmp/data"}),
        ),
        Action::new(
            "shell".to_string(),
            "exec".to_string(),
            json!({"cmd": "ls"}),
        ),
        Action::new(
            "net".to_string(),
            "post".to_string(),
            json!({"auth_token": "abc"}),
        ),
        Action::new(
            "net".to_string(),
            "post".to_string(),
            json!({"exfiltrate": true}),
        ),
        Action::new("unknown".to_string(), "mystery".to_string(), json!({})),
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
