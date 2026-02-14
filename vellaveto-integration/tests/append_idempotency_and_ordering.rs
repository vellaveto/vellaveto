//! Tests that AuditLogger produces distinct entries for identical inputs,
//! and that load order matches append order (FIFO).

use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};
use serde_json::json;
use std::collections::HashSet;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action() -> Action {
    Action::new(
        "idempotency_test".to_string(),
        "probe".to_string(),
        json!({"fixed": "value"}),
    )
}

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

// ═══════════════════════════════════════
// DISTINCT ENTRIES FOR IDENTICAL INPUTS
// ═══════════════════════════════════════

/// Logging the exact same action+verdict+metadata twice produces two entries
/// with different IDs.
#[test]
fn identical_inputs_produce_different_ids() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action();
        let verdict = Verdict::Allow;
        let metadata = json!({"same": "data"});

        logger
            .log_entry(&action, &verdict, metadata.clone())
            .await
            .unwrap();
        logger
            .log_entry(&action, &verdict, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_ne!(
            entries[0].id, entries[1].id,
            "Two entries from identical inputs must have different IDs"
        );
    });
}

/// 50 identical writes all produce unique IDs.
#[test]
fn fifty_identical_writes_all_unique_ids() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action();

        for _ in 0..50 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 50);

        let ids: HashSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids.len(), 50, "All 50 entry IDs must be unique");
    });
}

// ═══════════════════════════════════════
// LOAD ORDER MATCHES WRITE ORDER (FIFO)
// ═══════════════════════════════════════

/// Entries loaded back should preserve the write order (append-only file).
#[test]
fn load_order_matches_write_order() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        let tools = ["alpha", "bravo", "charlie", "delta", "echo"];
        for tool in &tools {
            let action = Action::new(tool.to_string(), "ordered".to_string(), json!({}));
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 5);

        for (i, tool) in tools.iter().enumerate() {
            assert_eq!(
                entries[i].action.tool, *tool,
                "Entry {} should have tool '{}', got '{}'",
                i, tool, entries[i].action.tool
            );
        }
    });
}

/// Mixed verdicts maintain insertion order.
#[test]
fn mixed_verdicts_maintain_order() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action();

        let verdicts = vec![
            Verdict::Allow,
            Verdict::Deny {
                reason: "r1".to_string(),
            },
            Verdict::RequireApproval {
                reason: "r2".to_string(),
            },
            Verdict::Allow,
            Verdict::Deny {
                reason: "r3".to_string(),
            },
        ];

        for v in &verdicts {
            logger.log_entry(&action, v, json!({})).await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 5);

        // Verify verdict order matches
        for (i, (entry, expected)) in entries.iter().zip(verdicts.iter()).enumerate() {
            let entry_is_allow = matches!(entry.verdict, Verdict::Allow);
            let expected_is_allow = matches!(expected, Verdict::Allow);
            let entry_is_deny = matches!(entry.verdict, Verdict::Deny { .. });
            let expected_is_deny = matches!(expected, Verdict::Deny { .. });
            let entry_is_approval = matches!(entry.verdict, Verdict::RequireApproval { .. });
            let expected_is_approval = matches!(expected, Verdict::RequireApproval { .. });

            assert!(
                (entry_is_allow && expected_is_allow)
                    || (entry_is_deny && expected_is_deny)
                    || (entry_is_approval && expected_is_approval),
                "Entry {} verdict type mismatch: got {:?}, expected {:?}",
                i,
                entry.verdict,
                expected
            );
        }
    });
}

/// Timestamps should be non-decreasing (monotonic) for sequential writes.
#[test]
fn sequential_timestamps_are_non_decreasing() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action();

        for _ in 0..20 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 20);

        for i in 1..entries.len() {
            assert!(
                entries[i].timestamp >= entries[i - 1].timestamp,
                "Timestamps should be non-decreasing: entry {} ('{}') < entry {} ('{}')",
                i,
                entries[i].timestamp,
                i - 1,
                entries[i - 1].timestamp
            );
        }
    });
}
