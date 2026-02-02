//! Integration tests for the AuditLogger.

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

fn setup_logger() -> (AuditLogger, TempDir) {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path);
    (logger, dir)
}

fn sample_action(tool: &str, function: &str) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: json!({"key": "value"}),
    }
}

#[tokio::test]
async fn log_and_retrieve_entries() {
    let (logger, _dir) = setup_logger();
    let action = sample_action("shell", "execute");

    logger
        .log_entry(&action, &Verdict::Allow, json!({"user": "test"}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert!(!entries.is_empty(), "Should have at least one entry after logging");
}

#[tokio::test]
async fn log_multiple_entries_preserves_order() {
    let (logger, _dir) = setup_logger();

    for i in 0..5 {
        let action = sample_action("tool", &format!("action_{}", i));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"index": i}))
            .await
            .unwrap();
    }

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 5, "Should have exactly 5 entries");
}

#[tokio::test]
async fn generate_report_with_entries() {
    let (logger, _dir) = setup_logger();

    logger
        .log_entry(
            &sample_action("shell", "execute"),
            &Verdict::Deny { reason: "blocked".to_string() },
            json!({}),
        )
        .await
        .unwrap();
    logger
        .log_entry(
            &sample_action("file", "read"),
            &Verdict::Allow,
            json!({}),
        )
        .await
        .unwrap();

    let report = logger.generate_report().await.unwrap();
    assert_eq!(report.total_entries, 2);
    assert_eq!(report.allow_count, 1);
    assert_eq!(report.deny_count, 1);
}

#[tokio::test]
async fn generate_report_empty_log() {
    let (logger, _dir) = setup_logger();
    let report = logger.generate_report().await.unwrap();
    assert_eq!(report.total_entries, 0);
}

#[tokio::test]
async fn logger_handles_concurrent_writes() {
    let (logger, _dir) = setup_logger();
    let logger = std::sync::Arc::new(logger);

    let mut handles = vec![];
    for i in 0..10 {
        let lg = logger.clone();
        handles.push(tokio::spawn(async move {
            let action = Action {
                tool: "tool".to_string(),
                function: format!("concurrent_{}", i),
                parameters: json!({"thread": i}),
            };
            lg.log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }));
    }

    for h in handles {
        h.await.expect("Task panicked");
    }

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 10, "All concurrent writes should be captured");
}
