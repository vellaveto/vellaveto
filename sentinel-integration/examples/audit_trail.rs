//! Example: evaluate actions and produce an audit report.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example audit_trail

use sentinel_engine::PolicyEngine;
use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Policy, PolicyType};
use serde_json::json;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        let engine = PolicyEngine::new(false);

        let policies = vec![
            Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 0,
            },
            Policy {
                id: "file:delete".to_string(),
                name: "Block file deletes".to_string(),
                policy_type: PolicyType::Deny,
                priority: 10,
            },
        ];

        let tmp = tempfile::TempDir::new().expect("failed to create temp dir");
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let actions = vec![
            ("file", "read"),
            ("file", "delete"),
            ("file", "read"),
            ("file", "delete"),
        ];

        println!("Evaluating {} actions...\n", actions.len());

        for (tool, function) in &actions {
            let action = Action {
                tool: tool.to_string(),
                function: function.to_string(),
                parameters: json!({}),
            };

            let verdict = engine.evaluate_action(&action, &policies)
                .expect("evaluation failed");

            println!("  {}:{} -> {:?}", tool, function, verdict);
            logger.log_entry(&action, &verdict, json!({})).await.expect("log failed");
        }

        let entries = logger.load_entries().await.expect("load failed");
        println!("\nAudit log: {} entries", entries.len());

        let report = logger.generate_report().await.expect("report failed");
        println!("\n--- Report ---");
        println!("  Total: {}", report.total_entries);
        println!("  Allowed: {}", report.allow_count);
        println!("  Denied: {}", report.deny_count);
        println!("  Require Approval: {}", report.require_approval_count);
    });
}
