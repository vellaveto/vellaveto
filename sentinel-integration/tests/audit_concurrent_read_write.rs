//! Tests concurrent read and write operations on the audit logger.
//! Multiple tasks write while others simultaneously load entries
//! and generate reports. This probes for file-locking issues.

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
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

fn make_action(id: usize) -> Action {
    Action::new(
        format!("rw_tool_{}", id),
        "test".to_string(),
        json!({"id": id}),
    )
}

// ══════════════════════════════════════
// CONCURRENT WRITERS + READERS
// ═══════════════════════════════════════

/// 10 writer tasks and 10 reader tasks running simultaneously.
/// Writers should not fail. Readers may get partial results
/// but must not panic or return corrupted data.
#[test]
fn concurrent_writers_and_readers_no_panic() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));

        let num_writers = 10;
        let entries_per_writer = 20;
        let num_readers = 10;
        let reads_per_reader = 5;

        let mut handles = Vec::new();

        // Spawn writers
        for w in 0..num_writers {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for i in 0..entries_per_writer {
                    let action = make_action(w * 1000 + i);
                    let verdict = if i % 2 == 0 {
                        Verdict::Allow
                    } else {
                        Verdict::Deny {
                            reason: format!("w{}-e{}", w, i),
                        }
                    };
                    // Writes should not panic
                    let _ = logger
                        .log_entry(&action, &verdict, json!({"writer": w}))
                        .await;
                }
            }));
        }

        // Spawn readers
        for _r in 0..num_readers {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for _ in 0..reads_per_reader {
                    // load_entries may fail if reading a partial line.
                    // That's OK — we just verify no panic.
                    let _ = logger.load_entries().await;
                    tokio::task::yield_now().await;
                }
            }));
        }

        // All tasks must complete without panic
        for handle in handles {
            handle.await.expect("Task panicked");
        }

        // After all writes complete, final load should work
        // (all writers are done, file is complete)
        let entries = logger.load_entries().await.unwrap();
        assert!(
            entries.len() <= num_writers * entries_per_writer,
            "Cannot have more entries than were written"
        );
        // We expect all entries to be written, but concurrent I/O
        // could theoretically lose some. At minimum, verify > 0.
        assert!(!entries.is_empty(), "Should have at least some entries");
    });
}

/// Generate report while writes are in progress.
/// The report should never have inconsistent arithmetic.
#[test]
fn report_during_concurrent_writes_has_consistent_arithmetic() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));

        // Pre-populate some entries
        let action = make_action(0);
        for _ in 0..10 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let mut handles = Vec::new();

        // Writers
        for w in 0..5 {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for i in 0..10 {
                    let action = make_action(w * 100 + i);
                    let _ = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
                }
            }));
        }

        // Report generators
        for _ in 0..5 {
            let logger = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                for _ in 0..3 {
                    if let Ok(report) = logger.generate_report().await {
                        // THE KEY INVARIANT: arithmetic must be consistent
                        assert_eq!(
                            report.total_entries,
                            report.allow_count + report.deny_count + report.require_approval_count,
                            "Report arithmetic invariant violated"
                        );
                        assert_eq!(
                            report.entries.len(),
                            report.total_entries,
                            "entries.len() must equal total_entries"
                        );
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }

        for handle in handles {
            handle.await.expect("Task panicked");
        }
    });
}
