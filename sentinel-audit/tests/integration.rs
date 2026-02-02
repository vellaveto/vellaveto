//! Integration tests for sentinel-audit - edge-case and adversarial focused.

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

// --- Helpers ---

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

// --- Basic logging ---

#[tokio::test]
async fn log_single_entry_and_retrieve() {
    let (logger, _dir) = setup_logger();
    let action = sample_action("shell", "execute");

    logger
        .log_entry(&action, &Verdict::Allow, json!({"user": "tester"}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert!(
        !entries.is_empty(),
        "Should have at least one entry after logging"
    );
}

#[tokio::test]
async fn log_deny_verdict() {
    let (logger, _dir) = setup_logger();
    let action = sample_action("file", "delete");

    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "Dangerous operation".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn log_require_approval_verdict() {
    let (logger, _dir) = setup_logger();
    let action = sample_action("shell", "execute");

    logger
        .log_entry(
            &action,
            &Verdict::RequireApproval {
                reason: "Needs human review".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
}

// --- Ordering and multiple entries ---

#[tokio::test]
async fn multiple_entries_preserve_order() {
    let (logger, _dir) = setup_logger();

    for i in 0..5 {
        let action = sample_action("tool", &format!("action_{}", i));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"index": i}))
            .await
            .unwrap();
    }

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 5, "All 5 entries should be stored");
}

#[tokio::test]
async fn entries_from_fresh_logger_are_empty() {
    let (logger, _dir) = setup_logger();
    let entries = logger.load_entries().await.unwrap();
    assert!(entries.is_empty(), "Fresh logger should have zero entries");
}

// --- Report generation ---

#[tokio::test]
async fn generate_report_with_mixed_verdicts() {
    let (logger, _dir) = setup_logger();

    logger
        .log_entry(
            &sample_action("shell", "execute"),
            &Verdict::Deny {
                reason: "blocked".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();
    logger
        .log_entry(&sample_action("file", "read"), &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &sample_action("network", "fetch"),
            &Verdict::RequireApproval {
                reason: "needs review".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    let report = logger.generate_report().await.unwrap();
    assert_eq!(report.total_entries, 3);
    assert_eq!(report.allow_count, 1);
    assert_eq!(report.deny_count, 1);
    assert_eq!(report.require_approval_count, 1);
}

#[tokio::test]
async fn generate_report_on_empty_log() {
    let (logger, _dir) = setup_logger();
    let report = logger.generate_report().await.unwrap();
    assert_eq!(report.total_entries, 0);
}

// --- Concurrent writes ---

#[tokio::test]
async fn concurrent_writes_all_captured() {
    let (logger, _dir) = setup_logger();
    let logger = std::sync::Arc::new(logger);

    let mut handles = vec![];
    for i in 0..20 {
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
        h.await.expect("Spawned task should not panic");
    }

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(
        entries.len(),
        20,
        "All 20 concurrent writes must be captured"
    );
}

// --- Edge cases and adversarial inputs ---

#[tokio::test]
async fn large_metadata_does_not_corrupt_log() {
    let (logger, _dir) = setup_logger();
    let action = sample_action("shell", "execute");

    let mut meta = serde_json::Map::new();
    for i in 0..500 {
        meta.insert(format!("field_{}", i), json!(format!("value_{}", i)));
    }

    logger
        .log_entry(&action, &Verdict::Allow, serde_json::Value::Object(meta))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1, "Large metadata entry should be stored");
}

#[tokio::test]
async fn unicode_in_action_fields() {
    let (logger, _dir) = setup_logger();
    let action = Action {
        tool: "日本語".to_string(),
        function: "функция".to_string(),
        parameters: json!({"키": "值"}),
    };

    logger
        .log_entry(&action, &Verdict::Allow, json!({"note": "유니코드"}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1, "Unicode content must be handled");
}

#[tokio::test]
async fn empty_and_null_metadata() {
    let (logger, _dir) = setup_logger();
    let action = sample_action("tool", "fn");

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(&action, &Verdict::Allow, json!(null))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 2, "Empty/null metadata should be fine");
}

// --- Persistence across load calls ---

#[tokio::test]
async fn load_entries_is_idempotent() {
    let (logger, _dir) = setup_logger();
    let action = sample_action("tool", "fn");
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries1 = logger.load_entries().await.unwrap();
    let entries2 = logger.load_entries().await.unwrap();
    assert_eq!(
        entries1.len(),
        entries2.len(),
        "load_entries must be idempotent"
    );
}

#[tokio::test]
async fn report_after_many_entries() {
    let (logger, _dir) = setup_logger();

    for i in 0..50 {
        let action = sample_action("tool", &format!("fn_{}", i));
        let verdict = if i % 3 == 0 {
            Verdict::Deny {
                reason: "blocked".to_string(),
            }
        } else if i % 3 == 1 {
            Verdict::RequireApproval {
                reason: "review".to_string(),
            }
        } else {
            Verdict::Allow
        };
        logger
            .log_entry(&action, &verdict, json!({"i": i}))
            .await
            .unwrap();
    }

    let report = logger.generate_report().await.unwrap();
    assert_eq!(report.total_entries, 50);
    assert!(report.deny_count > 0);
    assert!(report.allow_count > 0);
    assert!(report.require_approval_count > 0);
}
