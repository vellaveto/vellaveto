//! Attempts to break audit logging with concurrent writes from many tasks.
//! The AuditLogger has no internal locking — each log_entry opens the file
//! independently in append mode. This test verifies JSONL integrity.

use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

fn runtime_mt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to create multi-thread runtime")
}

fn runtime_st() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create single-thread runtime")
}

fn make_action(id: usize) -> Action {
    Action::new(
        format!("concurrent_tool_{}", id),
        format!("func_{}", id),
        json!({"task_id": id}),
    )
}

// ══════════════════════════════════════
// CONCURRENT MULTI-TASK WRITES
// ══════════════════════════════════════

/// 50 tasks each write 10 entries concurrently on a multi-threaded runtime.
/// Every line in the resulting file must be valid JSON.
#[test]
fn fifty_tasks_produce_valid_jsonl_lines() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("concurrent.log");
        let logger = Arc::new(AuditLogger::new(log_path.clone()));

        let num_tasks = 50;
        let entries_per_task = 10;

        let mut handles = Vec::new();
        for task_id in 0..num_tasks {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for i in 0..entries_per_task {
                    let action = make_action(task_id * 1000 + i);
                    let verdict = if i % 2 == 0 {
                        Verdict::Allow
                    } else {
                        Verdict::Deny {
                            reason: format!("task {} entry {}", task_id, i),
                        }
                    };
                    logger
                        .log_entry(&action, &verdict, json!({"task": task_id, "entry": i}))
                        .await
                        .expect("log_entry failed");
                }
            }));
        }

        for handle in handles {
            handle.await.expect("task panicked");
        }

        // Verify every line is valid JSON
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

        assert_eq!(
            lines.len(),
            num_tasks * entries_per_task,
            "Expected {} lines, got {}",
            num_tasks * entries_per_task,
            lines.len()
        );

        let mut parse_failures = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if serde_json::from_str::<serde_json::Value>(line).is_err() {
                parse_failures.push((i, line.to_string()));
            }
        }

        assert!(
            parse_failures.is_empty(),
            "Found {} lines that are not valid JSON. First failure at line {}: {:?}",
            parse_failures.len(),
            parse_failures.first().map(|(i, _)| *i).unwrap_or(0),
            parse_failures
                .first()
                .map(|(_, l)| l.as_str())
                .unwrap_or("")
        );
    });
}

/// Verify load_entries returns the correct count after concurrent writes.
#[test]
fn load_entries_count_matches_concurrent_writes() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("count.log")));

        let num_tasks = 20;
        let entries_per_task = 25;
        let expected_total = num_tasks * entries_per_task;

        let mut handles = Vec::new();
        for task_id in 0..num_tasks {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for i in 0..entries_per_task {
                    let action = make_action(task_id * 100 + i);
                    logger
                        .log_entry(&action, &Verdict::Allow, json!({}))
                        .await
                        .unwrap();
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(
            entries.len(),
            expected_total,
            "load_entries should return exactly {} entries",
            expected_total
        );
    });
}

/// Report generation after concurrent writes must have consistent counts.
#[test]
fn report_counts_consistent_after_concurrent_writes() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("report.log")));

        let mut handles = Vec::new();
        let allow_count = 30;
        let deny_count = 20;
        let approval_count = 10;

        // Spawn allow tasks
        for i in 0..allow_count {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                let action = make_action(i);
                logger
                    .log_entry(&action, &Verdict::Allow, json!({}))
                    .await
                    .unwrap();
            }));
        }

        // Spawn deny tasks
        for i in 0..deny_count {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                let action = make_action(1000 + i);
                logger
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: format!("deny-{}", i),
                        },
                        json!({}),
                    )
                    .await
                    .unwrap();
            }));
        }

        // Spawn approval tasks
        for i in 0..approval_count {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                let action = make_action(2000 + i);
                logger
                    .log_entry(
                        &action,
                        &Verdict::RequireApproval {
                            reason: format!("approve-{}", i),
                        },
                        json!({}),
                    )
                    .await
                    .unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(
            report.total_entries,
            allow_count + deny_count + approval_count
        );
        assert_eq!(report.allow_count, allow_count);
        assert_eq!(report.deny_count, deny_count);
        assert_eq!(report.require_approval_count, approval_count);
        assert_eq!(
            report.allow_count + report.deny_count + report.require_approval_count,
            report.total_entries,
            "Verdict counts must sum to total"
        );
    });
}

/// Single-threaded runtime: sequential writes should always produce valid JSONL.
/// This is the baseline sanity check.
#[test]
fn sequential_writes_on_single_thread_are_valid() {
    let rt = runtime_st();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("sequential.log");
        let logger = AuditLogger::new(log_path.clone());

        for i in 0..100 {
            let action = make_action(i);
            logger
                .log_entry(&action, &Verdict::Allow, json!({"seq": i}))
                .await
                .unwrap();
        }

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 100);

        for (i, line) in lines.iter().enumerate() {
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "Line {} is not valid JSON: {}",
                i,
                &line[..line.len().min(100)]
            );
        }
    });
}
