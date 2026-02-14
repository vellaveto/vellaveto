//! Tests that the audit logger works with unicode directory and file names.
//! Filesystem edge case — tempfile gives us ASCII paths, but real deployments
//! may use unicode paths.

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

fn action() -> Action {
    Action::new(
        "unicode_path_test".to_string(),
        "probe".to_string(),
        json!({}),
    )
}

// ════════════════════════════════
// UNICODE FILE NAME
// ════════════════════════════════

/// Logger writing to a file with unicode characters in the name.
#[test]
fn unicode_filename_write_and_load() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("审计日志.log");
        let logger = AuditLogger::new(log_path);

        logger
            .log_entry(&action(), &Verdict::Allow, json!({"test": "unicode_path"}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "unicode_path_test");
    });
}

/// Logger writing to a deeply nested path with unicode directory names.
#[test]
fn unicode_nested_directory_path() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("日志").join("子录").join("audit.log");
        let logger = AuditLogger::new(log_path);

        // First write should trigger parent directory creation
        logger
            .log_entry(&action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    });
}

/// Logger writing to a file with emoji in the name.
#[test]
fn emoji_filename_write_and_load() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("️_audit.log");
        let logger = AuditLogger::new(log_path);

        logger
            .log_entry(
                &action(),
                &Verdict::Deny {
                    reason: "test".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0].verdict {
            Verdict::Deny { reason } => assert_eq!(reason, "test"),
            other => panic!("Expected Deny, got {:?}", other),
        }
    });
}

// ════════════════════════════════
// REPORT GENERATION WITH UNICODE PATHS
// ═══════════════════════════════

#[test]
fn report_generation_with_unicode_path() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("рапорт.log"));

        logger
            .log_entry(&action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(
                &action(),
                &Verdict::Deny {
                    reason: "blocked".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 0);
    });
}
