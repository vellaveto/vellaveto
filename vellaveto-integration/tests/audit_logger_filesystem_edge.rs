// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests for AuditLogger filesystem edge cases:
//! - Non-existent parent directories (retry path)
//! - Loading from non-existent files
//! - Empty files
//! - Files with blank lines

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
    Action::new("fs".to_string(), "stat".to_string(), json!({}))
}

// ════════════════════════════════════════
// NON-EXISTENT PARENT DIRECTORY
// ══════════════════════════════════════

/// The logger's retry path should create missing parent directories.
#[test]
fn creates_parent_directories_on_demand() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        // deep/nested/path doesn't exist yet
        let log_path = tmp
            .path()
            .join("deep")
            .join("nested")
            .join("path")
            .join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        let action = make_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Verify the file was created and contains valid data
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "fs");
    });
}

// ════════════════════════════════════════
// LOADING FROM NON-EXISTENT FILE
// ═══════════════════════════════════════

#[test]
fn load_entries_from_nonexistent_file_returns_empty() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("does_not_exist.log"));
        let entries = logger.load_entries().await.unwrap();
        assert!(entries.is_empty());
    });
}

#[test]
fn generate_report_from_nonexistent_file_returns_empty_report() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("missing.log"));
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert!(report.entries.is_empty());
    });
}

// ═══════════════════════════════════════
// JSONL LINE INTEGRITY
// ══════════════════════════════════════

/// Each line in the audit log should be independently valid JSON.
#[test]
fn each_log_line_is_independent_valid_json() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        let action = make_action();
        for _ in 0..5 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        // Read raw file and verify each line is valid JSON
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let mut count = 0;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "Line {} is not valid JSON: {}", count, line);
            count += 1;
        }
        assert_eq!(count, 5);
    });
}

/// The log file should not have an array wrapper or trailing commas.
#[test]
fn log_file_is_not_json_array() {
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
                    reason: "test".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let trimmed = content.trim();
        assert!(
            !trimmed.starts_with('['),
            "Log file should be JSONL, not a JSON array"
        );
        assert!(
            !trimmed.ends_with(']'),
            "Log file should be JSONL, not a JSON array"
        );
    });
}

// ════════════════════════════════════════
// MULTIPLE WRITES THEN LOAD
// ═══════════════════════════════════════

#[test]
fn multiple_writes_across_all_verdict_types() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action();

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "r1".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::RequireApproval {
                    reason: "r2".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 3);

        // Verify verdict types match in order
        assert!(matches!(entries[0].verdict, Verdict::Allow));
        assert!(matches!(entries[1].verdict, Verdict::Deny { .. }));
        assert!(matches!(
            entries[2].verdict,
            Verdict::RequireApproval { .. }
        ));
    });
}
