// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests the audit logger through a complete sequential lifecycle:
//! create → write entries → load → generate report → verify.
//! Every assertion is derived from the source code.

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

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

// ════════════════════════════
// FRESH LOGGER: NO FILE EXISTS YET
// ════════════════════════════

#[test]
fn fresh_logger_load_returns_empty() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 0);
    });
}

#[test]
fn fresh_logger_report_has_zero_counts() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert_eq!(report.entries.len(), 0);
    });
}

// ════════════════════════════
// SINGLE ENTRY LIFECYCLE
// ════════════════════════════

#[test]
fn single_allow_entry_lifecycle() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("file", "read");

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "file");
        assert_eq!(entries[0].action.function, "read");
        assert_eq!(entries[0].verdict, Verdict::Allow);

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
    });
}

#[test]
fn single_deny_entry_lifecycle() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("shell", "exec");
        let verdict = Verdict::Deny {
            reason: "blocked".to_string(),
        };

        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].verdict, verdict);

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 0);
    });
}

#[test]
fn single_require_approval_entry_lifecycle() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("net", "connect");
        let verdict = Verdict::RequireApproval {
            reason: "needs review".to_string(),
        };

        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].verdict, verdict);

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 1);
    });
}

// ════════════════════════════
// MULTI-ENTRY LIFECYCLE
// ═════════════════════════════

#[test]
fn mixed_verdicts_counted_correctly() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("tool", "func");

        // Log 3 allows, 2 denies, 1 require_approval
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        for i in 0..2 {
            logger
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: format!("reason_{i}"),
                    },
                    json!({}),
                )
                .await
                .unwrap();
        }
        logger
            .log_entry(
                &action,
                &Verdict::RequireApproval {
                    reason: "review".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 6);
        assert_eq!(report.allow_count, 3);
        assert_eq!(report.deny_count, 2);
        assert_eq!(report.require_approval_count, 1);
        assert_eq!(report.entries.len(), 6);
        // Arithmetic invariant
        assert_eq!(
            report.total_entries,
            report.allow_count + report.deny_count + report.require_approval_count
        );
    });
}

// ════════════════════════════
// ENTRY ID UNIQUENESS
// ════════════════════════════

#[test]
fn entry_ids_are_unique_uuids() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("t", "f");

        for _ in 0..10 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        let ids: std::collections::HashSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids.len(), 10, "All 10 entries should have unique IDs");
    });
}

// ════════════════════════════
// METADATA PRESERVATION
// ═══════════════════════════

#[test]
fn metadata_preserved_through_roundtrip() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("t", "f");
        let metadata = json!({"user": "admin", "source": "api", "count": 42});

        logger
            .log_entry(&action, &Verdict::Allow, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries[0].metadata, metadata);
    });
}
