//! Tests that probe audit logger behavior when the underlying file
//! is manipulated between operations: deleted, truncated, or replaced.
//! These are adversarial filesystem tests.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action() -> Action {
    Action::new(
        "disruption_test".to_string(),
        "probe".to_string(),
        json!({}),
    )
}

// ═══════════════════════════════════
// FILE DELETED BETWEEN WRITE AND LOAD
// ═══════════════════════════════════

/// Write entries, delete the file, then try to load.
/// load_entries returns Ok(vec![]) for missing files, so this should succeed.
#[test]
fn load_after_file_deleted_returns_empty() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Write some entries
        let action = make_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Verify entries exist
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);

        // Delete the file
        tokio::fs::remove_file(&log_path).await.unwrap();

        // Load should return empty, not error
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 0, "Missing file should return empty vec");
    });
}

/// Write, delete, write again. The second write should recreate the file.
#[test]
fn write_after_file_deleted_recreates_file() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());
        let action = make_action();

        // Write
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        assert_eq!(logger.load_entries().await.unwrap().len(), 1);

        // Delete
        tokio::fs::remove_file(&log_path).await.unwrap();

        // Write again — should recreate file
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "after delete".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        // Should have only the new entry
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));
    });
}

// ══════════════════════════════════════════
// FILE TRUNCATED BETWEEN WRITE AND LOAD
// ═════════════════════════════════════════

/// Write entries, then truncate the file to zero bytes.
/// load_entries should return empty vec (no lines to parse).
#[test]
fn load_after_file_truncated_returns_empty() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());
        let action = make_action();

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        assert_eq!(logger.load_entries().await.unwrap().len(), 1);

        // Truncate to empty
        tokio::fs::write(&log_path, "").await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 0, "Truncated file should yield no entries");
    });
}

/// Write entries, truncate, write more. Only new entries should exist.
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
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        assert_eq!(logger.load_entries().await.unwrap().len(), 3);

        // Truncate
        tokio::fs::write(&log_path, "").await.unwrap();

        // Write 2 more
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "post-truncate-1".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "post-truncate-2".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2, "Should only have post-truncation entries");
    });
}

// ═══════════════════════════════════════
// REPORT GENERATION AFTER DISRUPTION
// ══════════════════════════════════════

/// Generate report after file deletion. Should show zero entries.
#[test]
fn report_after_file_deleted_shows_zeros() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());
        let action = make_action();

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        tokio::fs::remove_file(&log_path).await.unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
    });
}

/// Generate report after file truncation.
#[test]
fn report_after_file_truncated_shows_zeros() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());
        let action = make_action();

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "x".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        // Truncate
        tokio::fs::write(&log_path, "").await.unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
    });
}
