//! Tests that probe audit logger behavior when the underlying file
//! is manipulated between operations: deleted mid-session, truncated,
//! or recreated. These are adversarial filesystem tests.

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
        tool: "midstream_test".to_string(),
        function: "probe".to_string(),
        parameters: json!({}),
    }
}

// ═══════════════════════════════════
// FILE DELETED THEN WRITE CONTINUES
// ════════════════════════════════════

/// Write entries, delete the file, then write more entries.
/// The logger should recreate the file on the next write.
#[test]
fn write_after_file_deletion_recreates_file() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());
        let action = make_action();

        // Write 3 entries
        for _ in 0..3 {
            logger.log_entry(&action, &Verdict::Allow, json!({})).await.unwrap();
        }
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 3);

        // Delete the file
        tokio::fs::remove_file(&log_path).await.unwrap();

        // load_entries should return empty (file not found = Ok(vec![]))
        let entries = logger.load_entries().await.unwrap();
        assert!(entries.is_empty());

        // Write 2 more entries — file should be recreated
        for _ in 0..2 {
            logger.log_entry(&action, &Verdict::Allow, json!({})).await.unwrap();
        }

        // Should only see the 2 new entries
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);
    });
}

// ═══════════════════════════════════
// FILE TRUNCATED THEN WRITE CONTINUES
// ═══════════════════════════════════

/// Write entries, truncate the file to 0 bytes, then write more.
/// The logger uses append mode, so it should write to the now-empty file.
#[test]
fn write_after_truncation_appends_to_empty_file() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());
        let action = make_action();

        // Write 3 entries
        for _ in 0..3 {
            logger.log_entry(&action, &Verdict::Allow, json!({})).await.unwrap();
        }
        assert_eq!(logger.load_entries().await.unwrap().len(), 3);

        // Truncate the file
        tokio::fs::write(&log_path, "").await.unwrap();

        // Write 2 more entries
        for _ in 0..2 {
            logger
                .log_entry(
                    &action,
                    &Verdict::Deny { reason: "post-truncation".to_string() },
                    json!({}),
                )
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);
        // The new entries should be Deny
        for entry in &entries {
            assert!(matches!(entry.verdict, Verdict::Deny { .. }));
        }
    });
}

// ═══════════════════════════════════
// REPORT AFTER FILE DELETION
// ═══════════════════════════════════

/// Write entries, delete file, generate report.
/// Report should show zero entries (file not found → empty vec).
#[test]
fn report_after_file_deletion_shows_zero() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());
        let action = make_action();

        logger.log_entry(&action, &Verdict::Allow, json!({})).await.unwrap();
        assert_eq!(logger.generate_report().await.unwrap().total_entries, 1);

        tokio::fs::remove_file(&log_path).await.unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
    });
}

// ═══════════════════════════════════
// LOAD AFTER FILE REPLACED WITH VALID BUT DIFFERENT CONTENT
// ═══════════════════════════════════

/// Write Allow entries, replace file content with a valid Deny entry,
/// verify load reads the new content.
#[test]
fn load_reads_replaced_file_content() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());
        let action = make_action();

        // Write an Allow entry
        logger.log_entry(&action, &Verdict::Allow, json!({})).await.unwrap();
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].verdict, Verdict::Allow));

        // Replace file with a hand-crafted Deny entry
        let fake_entry = serde_json::json!({
            "id": "fake-id-001",
            "action": {"tool": "replaced", "function": "test", "parameters": {}},
            "verdict": {"Deny": {"reason": "injected"}},
            "timestamp": "2025-01-01T00:00:00+00:00",
            "metadata": {}
        });
        let line = format!("{}\n", serde_json::to_string(&fake_entry).unwrap());
        tokio::fs::write(&log_path, line).await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "fake-id-001");
        assert_eq!(entries[0].action.tool, "replaced");
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));
    });
}