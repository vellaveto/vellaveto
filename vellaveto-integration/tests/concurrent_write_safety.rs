// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that try to BREAK audit logging under concurrent writes.
//! The AuditLogger has no internal mutex — each log_entry call
//! opens the file in append mode independently. This test verifies
//! whether concurrent tokio tasks produce a valid JSONL file.

use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use vellaveto_audit::{AuditEntry, AuditLogger};
use vellaveto_types::{Action, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action(id: usize) -> Action {
    Action::new(
        format!("tool_{id}"),
        format!("func_{id}"),
        json!({"id": id}),
    )
}

// ═══════════════════════════════════════
// CONCURRENT WRITES: JSONL LINE INTEGRITY
// ══════════════════════════════════════

/// Spawn N tasks that all write to the same audit log simultaneously.
/// Then verify every line in the file is independently valid JSON.
#[test]
fn concurrent_writes_produce_valid_jsonl() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("concurrent.log");
        let logger = Arc::new(AuditLogger::new(log_path.clone()));

        let num_tasks = 10;
        let writes_per_task = 20;

        let mut handles = Vec::new();
        for task_id in 0..num_tasks {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for i in 0..writes_per_task {
                    let action = make_action(task_id * 1000 + i);
                    logger
                        .log_entry(&action, &Verdict::Allow, json!({"task": task_id}))
                        .await
                        .unwrap();
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // Read raw file and verify each line is valid JSON
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let mut valid_count = 0;
        for (i, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed: Result<AuditEntry, _> = serde_json::from_str(line);
            assert!(
                parsed.is_ok(),
                "Line {} is not valid AuditEntry JSON: {}",
                i,
                &line[..line.len().min(200)]
            );
            valid_count += 1;
        }

        let expected = num_tasks * writes_per_task;
        assert_eq!(
            valid_count, expected,
            "Expected {expected} entries, found {valid_count}"
        );
    });
}

// ═══════════════════════════════════════
// CONCURRENT WRITES: ENTRY COUNT VIA API
// ══════════════════════════════════════

#[test]
fn concurrent_writes_all_entries_loadable() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("concurrent2.log")));

        let num_tasks = 8;
        let writes_per_task = 25;

        let mut handles = Vec::new();
        for task_id in 0..num_tasks {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for i in 0..writes_per_task {
                    let action = make_action(task_id * 100 + i);
                    let verdict = if i % 2 == 0 {
                        Verdict::Allow
                    } else {
                        Verdict::Deny {
                            reason: format!("deny_{i}"),
                        }
                    };
                    logger
                        .log_entry(&action, &verdict, json!({}))
                        .await
                        .unwrap();
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), num_tasks * writes_per_task);
    });
}

// ═══════════════════════════════════════
// CONCURRENT REPORT GENERATION
// ══════════════════════════════════════

#[test]
fn report_counts_are_consistent_after_concurrent_writes() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("concurrent3.log")));

        // Write exactly: 30 Allow, 30 Deny, 30 RequireApproval
        let mut handles = Vec::new();
        for task_id in 0..3 {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for i in 0..30 {
                    let action = make_action(task_id * 100 + i);
                    let verdict = match task_id {
                        0 => Verdict::Allow,
                        1 => Verdict::Deny {
                            reason: format!("d{i}"),
                        },
                        _ => Verdict::RequireApproval {
                            reason: format!("a{i}"),
                        },
                    };
                    logger
                        .log_entry(&action, &verdict, json!({}))
                        .await
                        .unwrap();
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 90);
        assert_eq!(report.allow_count, 30);
        assert_eq!(report.deny_count, 30);
        assert_eq!(report.require_approval_count, 30);
    });
}
