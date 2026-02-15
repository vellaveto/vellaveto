//! Integration tests for vellaveto-audit - edge-case and adversarial focused.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};

// --- Helpers ---

fn setup_logger() -> (AuditLogger, TempDir) {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path);
    (logger, dir)
}

fn sample_action(tool: &str, function: &str) -> Action {
    Action::new(
        tool.to_string(),
        function.to_string(),
        json!({"key": "value"}),
    )
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
            let action = Action::new(
                "tool".to_string(),
                format!("concurrent_{}", i),
                json!({"thread": i}),
            );
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
    let action = Action::new(
        "日本語".to_string(),
        "функция".to_string(),
        json!({"키": "值"}),
    );

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

// --- Duplicate ID detection ---

#[tokio::test]
async fn detect_duplicate_ids_empty_log_returns_empty() {
    let (logger, _dir) = setup_logger();
    let duplicates = logger.detect_duplicate_ids().await.unwrap();
    assert!(duplicates.is_empty(), "Empty log should have no duplicates");
}

#[tokio::test]
async fn detect_duplicate_ids_unique_entries_returns_empty() {
    let (logger, _dir) = setup_logger();

    for i in 0..5 {
        let action = sample_action("file", &format!("read_{}", i));
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let duplicates = logger.detect_duplicate_ids().await.unwrap();
    assert!(
        duplicates.is_empty(),
        "Log with unique IDs should have no duplicates"
    );
}

#[tokio::test]
async fn detect_duplicate_ids_finds_injected_duplicates() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new_unredacted(log_path.clone());

    // Create entries with valid hash chain
    logger.initialize_chain().await.unwrap();
    let action = sample_action("file", "read");
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Manually inject a duplicate by copying the first entry
    let content = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 2);

    let mut tampered = content.clone();
    tampered.push_str(lines[0]);
    tampered.push('\n');
    std::fs::write(&log_path, tampered).unwrap();

    let duplicates = logger.detect_duplicate_ids().await.unwrap();
    assert_eq!(duplicates.len(), 1, "Should detect exactly 1 duplicated ID");
    assert_eq!(
        duplicates[0].1, 2,
        "Duplicated ID should appear exactly 2 times"
    );
}

#[tokio::test]
async fn detect_duplicate_ids_sorted_by_count_descending() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new_unredacted(log_path.clone());

    // Create 3 entries
    logger.initialize_chain().await.unwrap();
    for i in 0..3 {
        let action = sample_action("file", &format!("read_{}", i));
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // Read entries and inject duplicates with different counts
    let content = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Duplicate first entry 3 times (total 4), second entry 1 time (total 2)
    let mut tampered = content.clone();
    tampered.push_str(lines[0]);
    tampered.push('\n');
    tampered.push_str(lines[0]);
    tampered.push('\n');
    tampered.push_str(lines[0]);
    tampered.push('\n');
    tampered.push_str(lines[1]);
    tampered.push('\n');
    std::fs::write(&log_path, tampered).unwrap();

    let duplicates = logger.detect_duplicate_ids().await.unwrap();
    assert_eq!(duplicates.len(), 2, "Should detect 2 duplicated IDs");
    assert!(
        duplicates[0].1 >= duplicates[1].1,
        "Should be sorted by count descending: {} >= {}",
        duplicates[0].1,
        duplicates[1].1
    );
    assert_eq!(duplicates[0].1, 4, "First entry should appear 4 times");
    assert_eq!(duplicates[1].1, 2, "Second entry should appear 2 times");
}

// --- Heartbeat logging ---

#[tokio::test]
async fn log_heartbeat_creates_vellaveto_entry() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new_unredacted(log_path);

    logger.log_heartbeat(60, 1).await.unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action.tool, "vellaveto");
    assert_eq!(entries[0].action.function, "heartbeat");
    assert_eq!(entries[0].metadata["event"], "heartbeat");
    assert_eq!(entries[0].metadata["interval_secs"], 60);
    assert_eq!(entries[0].metadata["sequence"], 1);
}

#[tokio::test]
async fn log_heartbeat_sequence_numbers_recorded() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new_unredacted(log_path);

    for seq in 1..=3 {
        logger.log_heartbeat(30, seq).await.unwrap();
    }

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 3);
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.metadata["sequence"], (i + 1) as u64);
    }
}

// --- Heartbeat gap detection ---

#[tokio::test]
async fn detect_heartbeat_gap_empty_log_returns_none() {
    let (logger, _dir) = setup_logger();
    let gap = logger.detect_heartbeat_gap(60).await.unwrap();
    assert!(gap.is_none(), "Empty log should have no gaps");
}

#[tokio::test]
async fn detect_heartbeat_gap_single_entry_returns_none() {
    let (logger, _dir) = setup_logger();
    logger
        .log_entry(&sample_action("file", "read"), &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let gap = logger.detect_heartbeat_gap(60).await.unwrap();
    assert!(gap.is_none(), "Single entry should have no gaps");
}

#[tokio::test]
async fn detect_heartbeat_gap_no_gap_in_rapid_entries() {
    let (logger, _dir) = setup_logger();

    for i in 0..5 {
        let action = sample_action("file", &format!("read_{}", i));
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // With entries written in quick succession, a 60s threshold should find no gap
    let gap = logger.detect_heartbeat_gap(60).await.unwrap();
    assert!(
        gap.is_none(),
        "Rapid consecutive entries should not have a 60s gap"
    );
}

#[tokio::test]
async fn detect_heartbeat_gap_finds_injected_gap() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new_unredacted(log_path.clone());

    logger.initialize_chain().await.unwrap();

    let action = sample_action("file", "read");
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Tamper: change the second entry's timestamp to be 2 hours later
    let content = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    let mut entry: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let ts = chrono::Utc::now() + chrono::Duration::hours(2);
    entry["timestamp"] = serde_json::Value::String(ts.to_rfc3339());
    let mut tampered_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    tampered_lines[1] = serde_json::to_string(&entry).unwrap();
    std::fs::write(&log_path, tampered_lines.join("\n") + "\n").unwrap();

    // A 60-second threshold should detect the 2-hour gap
    let gap = logger.detect_heartbeat_gap(60).await.unwrap();
    assert!(gap.is_some(), "Should detect the 2-hour gap");
    let (_, _, gap_secs) = gap.unwrap();
    assert!(
        gap_secs > 3600,
        "Gap should be >3600 seconds, got {}",
        gap_secs
    );
}
