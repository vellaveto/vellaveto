//! Tests AuditLogger::load_entries behavior when the log file contains
//! corrupted or non-JSON lines. The implementation is lenient: corrupt lines
//! are skipped with a warning, and valid entries are still returned.
//! This ensures a single corrupt line cannot make the entire audit log unreadable.

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
    Action::new(
        "corruption_test".to_string(),
        "probe".to_string(),
        json!({}),
    )
}

// ═══════════════════════════════════════
// CORRUPTED LOG FILE: LOAD BEHAVIOR
// ══════════════════════════════════════

/// A completely garbage file returns empty entries (corrupt lines skipped).
#[test]
fn load_entries_skips_garbage_file() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        // Write garbage directly to the file
        tokio::fs::write(&log_path, "this is not json\n")
            .await
            .unwrap();

        let logger = AuditLogger::new(log_path);
        let entries = logger.load_entries().await.unwrap();
        assert!(
            entries.is_empty(),
            "Garbage file should return empty entries (corrupt lines skipped)"
        );
    });
}

/// Valid entries followed by a corrupted line: load_entries skips the
/// corrupt line and still returns the valid entries.
#[test]
fn corruption_after_valid_entries_preserves_valid_data() {
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

        // Valid entries should still be accessible despite the corrupt line
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(
            entries.len(),
            2,
            "Valid entries should be preserved when corrupt lines are skipped"
        );
    });
}

/// generate_report returns empty results when all lines are corrupt,
/// since corrupt lines are skipped by load_entries.
#[test]
fn generate_report_handles_corrupted_log() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        logger
            .log_entry(&make_action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Overwrite with garbage
        tokio::fs::write(&log_path, "not json\n").await.unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(
            report.total_entries, 0,
            "Corrupt log should produce empty report, not failure"
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
