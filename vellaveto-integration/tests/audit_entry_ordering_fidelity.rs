// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that audit log entries preserve insertion order when loaded.
//! Existing tests verify counts and ID uniqueness but never assert
//! that entries[0] corresponds to the first write and entries[N-1]
//! to the last write. This is critical for forensic analysis.

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

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

fn action_with_tool(tool: &str) -> Action {
    Action::new(tool.to_string(), "test".to_string(), json!({}))
}

// ════════════════════════════════
// SEQUENTIAL WRITE ORDER = LOAD ORDER
// ═══════════════════════════════

/// Write 5 entries with distinct tool names, load, and verify order.
#[test]
fn entries_loaded_in_write_order() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let tools = ["alpha", "bravo", "charlie", "delta", "echo"];

        for tool in &tools {
            logger
                .log_entry(&action_with_tool(tool), &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), tools.len());
        for (i, tool) in tools.iter().enumerate() {
            assert_eq!(
                entries[i].action.tool, *tool,
                "Entry {} should have tool '{}', got '{}'",
                i, tool, entries[i].action.tool
            );
        }
    });
}

/// Write entries with different verdicts and verify verdict order matches.
#[test]
fn verdict_order_preserved_through_load() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = action_with_tool("order_test");

        let verdicts = vec![
            Verdict::Allow,
            Verdict::Deny {
                reason: "first deny".to_string(),
            },
            Verdict::RequireApproval {
                reason: "approval needed".to_string(),
            },
            Verdict::Allow,
            Verdict::Deny {
                reason: "second deny".to_string(),
            },
        ];

        for v in &verdicts {
            logger.log_entry(&action, v, json!({})).await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), verdicts.len());

        // Check each verdict matches
        assert_eq!(entries[0].verdict, Verdict::Allow);
        match &entries[1].verdict {
            Verdict::Deny { reason } => assert_eq!(reason, "first deny"),
            other => panic!("Entry 1 should be Deny, got {:?}", other),
        }
        match &entries[2].verdict {
            Verdict::RequireApproval { reason } => assert_eq!(reason, "approval needed"),
            other => panic!("Entry 2 should be RequireApproval, got {:?}", other),
        }
        assert_eq!(entries[3].verdict, Verdict::Allow);
        match &entries[4].verdict {
            Verdict::Deny { reason } => assert_eq!(reason, "second deny"),
            other => panic!("Entry 4 should be Deny, got {:?}", other),
        }
    });
}

/// Write entries with distinct metadata and verify metadata order.
#[test]
fn metadata_order_preserved_through_load() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = action_with_tool("meta_order");

        for i in 0..10 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({"seq": i}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 10);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry.metadata["seq"], i,
                "Entry {} should have seq={}, got {:?}",
                i, i, entry.metadata
            );
        }
    });
}

// ════════════════════════════════
// REPORT ENTRIES MATCH LOAD ORDER
// ════════════════════════════════

/// Report.entries should be in the same order as load_entries.
#[test]
fn report_entries_match_load_order() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        for i in 0..5 {
            logger
                .log_entry(
                    &action_with_tool(&format!("tool_{}", i)),
                    &Verdict::Allow,
                    json!({"index": i}),
                )
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        let report = logger.generate_report().await.unwrap();

        assert_eq!(entries.len(), report.entries.len());
        for (i, (entry, report_entry)) in entries.iter().zip(report.entries.iter()).enumerate() {
            assert_eq!(
                entry.id, report_entry.id,
                "Entry {} ID mismatch between load_entries and report",
                i
            );
            assert_eq!(entry.action.tool, report_entry.action.tool);
        }
    });
}

// ═══════════════════════════════
// TIMESTAMPS ARE CHRONOLOGICALLY ORDERED
// ════════════════════════════════

/// Sequential writes should produce non-decreasing timestamps.
#[test]
fn timestamps_are_non_decreasing() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = action_with_tool("timestamp_test");

        for _ in 0..20 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        for i in 1..entries.len() {
            assert!(
                entries[i].timestamp >= entries[i - 1].timestamp,
                "Timestamp at index {} ('{}') should be >= timestamp at index {} ('{}')",
                i,
                entries[i].timestamp,
                i - 1,
                entries[i - 1].timestamp
            );
        }
    });
}
