//! Tests that multiple AuditLogger instances writing to different files
//! are fully isolated — no shared global state, no cross-contamination.

use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action(tool: &str) -> Action {
    Action::new(tool.to_string(), "test".to_string(), json!({}))
}

// ════════════════════════════════
// TWO LOGGERS, SEPARATE FILES
// ════════════════════════════════

#[test]
fn two_loggers_to_separate_files_are_isolated() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger_a = AuditLogger::new(tmp.path().join("a.log"));
        let logger_b = AuditLogger::new(tmp.path().join("b.log"));

        logger_a
            .log_entry(&make_action("alpha"), &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger_a
            .log_entry(&make_action("alpha2"), &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger_b
            .log_entry(
                &make_action("beta"),
                &Verdict::Deny {
                    reason: "blocked".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let a_entries = logger_a.load_entries().await.unwrap();
        assert_eq!(a_entries.len(), 2);
        assert!(a_entries.iter().all(|e| e.action.tool.starts_with("alpha")));

        let b_entries = logger_b.load_entries().await.unwrap();
        assert_eq!(b_entries.len(), 1);
        assert_eq!(b_entries[0].action.tool, "beta");

        let a_report = logger_a.generate_report().await.unwrap();
        let b_report = logger_b.generate_report().await.unwrap();
        assert_eq!(a_report.total_entries, 2);
        assert_eq!(a_report.allow_count, 2);
        assert_eq!(a_report.deny_count, 0);
        assert_eq!(b_report.total_entries, 1);
        assert_eq!(b_report.allow_count, 0);
        assert_eq!(b_report.deny_count, 1);
    });
}

#[test]
fn logger_with_no_writes_generates_empty_report() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("never_written.log"));

        let entries = logger.load_entries().await.unwrap();
        assert!(entries.is_empty());

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert!(report.entries.is_empty());
    });
}

// ════════════════════════════════
// CONCURRENT WRITES TO DIFFERENT FILES
// ═══════════════════════════════

#[test]
fn concurrent_loggers_to_different_files_no_interference() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let entries_per_logger: usize = 20;

        let mut join_handles = Vec::new();
        for i in 0..5usize {
            let path = tmp.path().join(format!("logger_{}.log", i));
            let logger = Arc::new(AuditLogger::new(path));
            let handle = tokio::spawn(async move {
                for j in 0..20usize {
                    let action = Action::new(
                        format!("tool_{}", i),
                        format!("func_{}", j),
                        json!({"logger": i, "entry": j}),
                    );
                    logger
                        .log_entry(&action, &Verdict::Allow, json!({}))
                        .await
                        .unwrap();
                }
            });
            join_handles.push(handle);
        }

        for handle in join_handles {
            handle.await.unwrap();
        }

        for i in 0..5usize {
            let path = tmp.path().join(format!("logger_{}.log", i));
            let logger = AuditLogger::new(path);
            let entries = logger.load_entries().await.unwrap();
            assert_eq!(
                entries.len(),
                entries_per_logger,
                "Logger {} should have {} entries",
                i,
                entries_per_logger
            );
            for entry in &entries {
                assert_eq!(entry.action.tool, format!("tool_{}", i));
            }
        }
    });
}

// ════════════════════════════════
// FRESH LOGGER AT SAME PATH SEES PREVIOUS WRITES
// ═══════════════════════════════

#[test]
fn fresh_logger_at_same_path_sees_previous_writes() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("shared.log");

        let logger1 = AuditLogger::new(path.clone());
        logger1
            .log_entry(&make_action("first"), &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger1
            .log_entry(&make_action("second"), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let logger2 = AuditLogger::new(path);
        let entries = logger2.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action.tool, "first");
        assert_eq!(entries[1].action.tool, "second");

        logger2
            .log_entry(&make_action("third"), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let all_entries = logger1.load_entries().await.unwrap();
        assert_eq!(all_entries.len(), 3);
    });
}
