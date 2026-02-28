// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that audit entry IDs are unique UUIDs and that entry
//! identity properties hold across the pipeline.

use serde_json::json;
use std::collections::HashSet;
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

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

// ═══════════════════════════════════════
// ENTRY ID UNIQUENESS
// ══════════════════════════════════════

#[test]
fn all_entry_ids_are_unique() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("t", "f");

        for _ in 0..50 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 50);

        let ids: HashSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids.len(), 50, "All 50 entry IDs should be unique");
    });
}

#[test]
fn entry_ids_are_valid_uuid_v4_format() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("x", "y");

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let id = &entries[0].id;

        // UUID v4 format: 8-4-4-4-12 hex chars
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5, "UUID should have 5 parts: {}", id);
        assert_eq!(parts[0].len(), 8, "Part 1 should be 8 chars: {}", id);
        assert_eq!(parts[1].len(), 4, "Part 2 should be 4 chars: {}", id);
        assert_eq!(parts[2].len(), 4, "Part 3 should be 4 chars: {}", id);
        assert_eq!(parts[3].len(), 4, "Part 4 should be 4 chars: {}", id);
        assert_eq!(parts[4].len(), 12, "Part 5 should be 12 chars: {}", id);
    });
}

#[test]
fn entries_across_different_verdicts_have_unique_ids() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool", "func");

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "no".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::RequireApproval {
                    reason: "maybe".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let ids: HashSet<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids.len(), 3);
    });
}

// ══════════════════════════════════════
// ENTRY PRESERVES ACTION IDENTITY
// ══════════════════════════════════════

#[test]
fn logged_entry_preserves_action_fields() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action::new(
            "my_tool".to_string(),
            "my_func".to_string(),
            json!({"key": "value", "num": 42}),
        );

        logger
            .log_entry(&action, &Verdict::Allow, json!({"meta": "data"}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries[0].action.tool, "my_tool");
        assert_eq!(entries[0].action.function, "my_func");
        assert_eq!(
            entries[0].action.parameters,
            json!({"key": "value", "num": 42})
        );
        assert_eq!(entries[0].metadata, json!({"meta": "data"}));
    });
}

#[test]
fn logged_entry_preserves_deny_reason() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("t", "f");
        let reason = "Specific denial reason #42".to_string();

        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: reason.clone(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        match &entries[0].verdict {
            Verdict::Deny { reason: r } => assert_eq!(r, &reason),
            other => panic!("Expected Deny, got {:?}", other),
        }
    });
}
