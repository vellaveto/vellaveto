// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Stress and concurrency tests for the audit pipeline.
//! Exercises concurrent writes, large volumes, and report consistency.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn allow_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Allow {id}"),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("Deny {id}"),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ════════════════════════════════════════════════
// REPORT CONSISTENCY: counts must sum to total
// ═════════════════════════════════════════════════

#[test]
fn report_counts_sum_to_total_entries() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let engine = PolicyEngine::new(false);

        let policies = vec![allow_policy("safe:*", 10), deny_policy("danger:*", 100)];

        // Log a mix of verdicts
        let actions_and_tools = vec![
            ("safe", "read"),
            ("danger", "delete"),
            ("safe", "write"),
            ("danger", "format"),
            ("safe", "list"),
        ];

        for (tool, func) in &actions_and_tools {
            let action = make_action(tool, func);
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            logger
                .log_entry(&action, &verdict, json!({}))
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();

        // INVARIANT: counts must sum to total
        assert_eq!(
            report.total_entries,
            report.allow_count + report.deny_count + report.require_approval_count,
            "Report counts ({} allow + {} deny + {} approval = {}) must sum to total_entries ({})",
            report.allow_count,
            report.deny_count,
            report.require_approval_count,
            report.allow_count + report.deny_count + report.require_approval_count,
            report.total_entries,
        );

        // We expect 3 allows and 2 denies
        assert_eq!(report.allow_count, 3);
        assert_eq!(report.deny_count, 2);
        assert_eq!(report.require_approval_count, 0);
        assert_eq!(report.total_entries, 5);
    });
}

// ═════════════════════════════════════════════════
// BULK LOGGING: write many entries, verify none lost
// ═════════════════════════════════════════════════

#[test]
fn bulk_logging_preserves_all_entries() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("tool", "func");

        let count = 200;
        for i in 0..count {
            let metadata = json!({"index": i});
            logger
                .log_entry(&action, &Verdict::Allow, metadata)
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(
            entries.len(),
            count,
            "Expected {} entries but got {}; some entries were lost",
            count,
            entries.len()
        );

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, count);
        assert_eq!(report.allow_count, count);
    });
}

// ═════════════════════════════════════════════════
// EMPTY LOG: report on a fresh logger with no entries
// ═════════════════════════════════════════════════

#[test]
fn empty_log_generates_zero_report() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert!(report.entries.is_empty());
    });
}

// ═════════════════════════════════════════════════
// SEQUENTIAL WRITES: two loggers sharing a file path
// ═════════════════════════════════════════════════

#[test]
fn two_loggers_same_file_appends_correctly() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("shared_audit.log");

        let logger1 = AuditLogger::new(log_path.clone());
        let logger2 = AuditLogger::new(log_path.clone());

        let action1 = make_action("tool_a", "func_a");
        let action2 = make_action("tool_b", "func_b");

        logger1
            .log_entry(&action1, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger2
            .log_entry(
                &action2,
                &Verdict::Deny {
                    reason: "test".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        // Both loggers read from the same file, should see both entries
        let entries = logger1.load_entries().await.unwrap();
        assert_eq!(
            entries.len(),
            2,
            "Both entries should be present in shared log"
        );
        assert_eq!(entries[0].action.tool, "tool_a");
        assert_eq!(entries[1].action.tool, "tool_b");
    });
}

// ═════════════════════════════════════════════════
// METADATA PRESERVATION: verify metadata roundtrips
// ════════════════════════════════════════════════

#[test]
fn metadata_preserved_through_log_cycle() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("tool", "func");

        let complex_metadata = json!({
            "user": "alice",
            "session_id": "abc-123",
            "tags": ["security", "audit"],
            "nested": {
                "depth": 2,
                "flag": true
            }
        });

        logger
            .log_entry(&action, &Verdict::Allow, complex_metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, complex_metadata);
    });
}

// ═════════════════════════════════════════════════
// VERDICT VARIANTS: log all three verdict types, verify report
// ════════════════════════════════════════════════

#[test]
fn all_verdict_types_counted_correctly_in_report() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("tool", "func");

        // Log 3 Allow, 2 Deny, 4 RequireApproval
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        for _ in 0..2 {
            logger
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: "blocked".to_string(),
                    },
                    json!({}),
                )
                .await
                .unwrap();
        }
        for _ in 0..4 {
            logger
                .log_entry(
                    &action,
                    &Verdict::RequireApproval {
                        reason: "review".to_string(),
                    },
                    json!({}),
                )
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 9);
        assert_eq!(report.allow_count, 3);
        assert_eq!(report.deny_count, 2);
        assert_eq!(report.require_approval_count, 4);
    });
}

// ═════════════════════════════════════════════════
// LARGE METADATA: ensure we can log sizable metadata
// ═════════════════════════════════════════════════

#[test]
fn large_metadata_value_logged_and_loaded() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("tool", "func");

        // Build a large but valid metadata payload
        let large_array: Vec<serde_json::Value> = (0..500)
            .map(|i| json!({"index": i, "data": "x".repeat(100)}))
            .collect();
        let metadata = json!({"items": large_array});

        logger
            .log_entry(&action, &Verdict::Allow, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        let items = entries[0].metadata["items"].as_array().unwrap();
        assert_eq!(items.len(), 500);
    });
}
