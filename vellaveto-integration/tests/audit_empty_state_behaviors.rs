//! Tests for audit logger behavior with empty/fresh state.
//! Every assertion traces to specific source code behavior.

use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

fn action() -> Action {
    Action::new(
        "empty_state_test".to_string(),
        "probe".to_string(),
        json!({}),
    )
}

// ═══════════════════════════════
// LOAD FROM NON-EXISTENT FILE
// ═══════════════════════════════

/// load_entries on a file that doesn't exist returns Ok(vec![]).
/// Source: vellaveto-audit/src/lib.rs load_entries, NotFound branch
#[test]
fn load_entries_nonexistent_file_returns_empty_vec() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        // Don't write anything — file doesn't exist
        let logger = AuditLogger::new(tmp.path().join("nonexistent.log"));
        let entries = logger.load_entries().await.unwrap();
        assert!(entries.is_empty());
    });
}

/// generate_report on non-existent file returns report with all zeros.
/// Source: generate_report calls load_entries which returns empty vec.
#[test]
fn report_on_nonexistent_file_has_zero_counts() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("nonexistent.log"));
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert_eq!(report.entries.len(), 0);
    });
}

// ═══════════════════════════════
// WRITE THEN IMMEDIATE LOAD
// ════════════════════════════════

/// A single write followed by load returns exactly one entry.
#[test]
fn single_write_then_load_returns_one_entry() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        logger
            .log_entry(&action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    });
}

/// After N writes, load returns exactly N entries.
#[test]
fn n_writes_then_load_returns_n_entries() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let n = 25;
        for _ in 0..n {
            logger
                .log_entry(&action(), &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), n);
    });
}

// ═══════════════════════════════
// REPORT ARITHMETIC AFTER WRITES
// ═══════════════════════════════

/// Write known distribution, verify report counts exactly.
#[test]
fn report_counts_match_written_verdicts_exactly() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();

        // 3 Allow, 2 Deny, 1 RequireApproval
        for _ in 0..3 {
            logger
                .log_entry(&a, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        for i in 0..2 {
            logger
                .log_entry(
                    &a,
                    &Verdict::Deny {
                        reason: format!("r{}", i),
                    },
                    json!({}),
                )
                .await
                .unwrap();
        }
        logger
            .log_entry(
                &a,
                &Verdict::RequireApproval {
                    reason: "review".into(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 6);
        assert_eq!(report.allow_count, 3);
        assert_eq!(report.deny_count, 2);
        assert_eq!(report.require_approval_count, 1);
        assert_eq!(report.entries.len(), 6);
        // Invariant
        assert_eq!(
            report.total_entries,
            report.allow_count + report.deny_count + report.require_approval_count
        );
    });
}

// ═══════════════════════════════
// ENTRIES HAVE NON-EMPTY IDS
// ════════════════════════════════

/// Every entry gets a UUID id (non-empty string).
#[test]
fn all_entries_have_nonempty_ids() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        for _ in 0..5 {
            logger
                .log_entry(&action(), &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        let entries = logger.load_entries().await.unwrap();
        for entry in &entries {
            assert!(!entry.id.is_empty(), "Entry ID must not be empty");
        }
    });
}

/// Every entry gets a non-empty timestamp.
#[test]
fn all_entries_have_nonempty_timestamps() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        for _ in 0..5 {
            logger
                .log_entry(&action(), &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        let entries = logger.load_entries().await.unwrap();
        for entry in &entries {
            assert!(!entry.timestamp.is_empty(), "Timestamp must not be empty");
        }
    });
}
