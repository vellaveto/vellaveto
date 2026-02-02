//! Tests AuditLogger::load_entries behavior when the log file contains
//! corrupted or non-JSON lines. Currently the implementation fails hard
//! on the first bad line (serde_json::from_str returns Err, propagated via ?).
//! These tests document that behavior — they will break if resilience is added.

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action() -> Action {
    Action {
        tool: "corruption_test".to_string(),
        function: "probe".to_string(),
        parameters: json!({}),
    }
}

// ═══════════════════════════════════════
// CORRUPTED LOG FILE: LOAD BEHAVIOR
// ══════════════════════════════════════

/// A completely garbage file causes load_entries to fail.
#[test]
fn load_entries_fails_on_garbage_file() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        // Write garbage directly to the file
        tokio::fs::write(&log_path, "this is not json\n")
            .await
            .unwrap();

        let logger = AuditLogger::new(log_path);
        let result = logger.load_entries().await;
        assert!(
            result.is_err(),
            "Garbage file should cause load_entries to fail"
        );
    });
}

/// Valid entries followed by a corrupted line: load_entries fails,
/// and ALL entries (including valid ones before the corruption) are lost.
#[test]
fn corruption_after_valid_entries_loses_all_data() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Log two valid entries
        let action = make_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Verify they load correctly before corruption
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);

        // Append garbage to the file
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .await
            .unwrap();
        file.write_all(b"CORRUPTED LINE\n").await.unwrap();
        file.flush().await.unwrap();

        // Now load_entries should fail — the two valid entries are inaccessible
        let result = logger.load_entries().await;
        assert!(
            result.is_err(),
            "Corrupted line after valid entries should cause load failure"
        );
    });
}

/// generate_report also fails when the underlying log is corrupted,
/// since it delegates to load_entries.
#[test]
fn generate_report_fails_on_corrupted_log() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        logger
            .log_entry(&make_action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Corrupt the file
        tokio::fs::write(&log_path, "not json\n").await.unwrap();

        let result = logger.generate_report().await;
        assert!(
            result.is_err(),
            "Report generation should fail on corrupted log"
        );
    });
}

/// Blank lines in the middle of the file are silently skipped (the code
/// checks `line.trim().is_empty()`). This is NOT corruption handling
/// it's whitespace tolerance.
#[test]
fn blank_lines_between_valid_entries_are_skipped() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Log one valid entry
        logger
            .log_entry(&make_action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Inject blank lines
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .await
            .unwrap();
        file.write_all(b"\n\n\n").await.unwrap();
        file.flush().await.unwrap();

        // Log another valid entry
        logger
            .log_entry(
                &make_action(),
                &Verdict::Deny {
                    reason: "test".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        // Should successfully load both entries, skipping blank lines
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2, "Blank lines should be silently skipped");
    });
}

/// Whitespace-only lines (spaces, tabs) are also skipped by trim().is_empty().
#[test]
fn whitespace_only_lines_are_skipped() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        logger
            .log_entry(&make_action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Inject whitespace-only lines
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .await
            .unwrap();
        file.write_all(b"   \n\t\t\n  \t  \n").await.unwrap();
        file.flush().await.unwrap();

        logger
            .log_entry(&make_action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);
    });
}
