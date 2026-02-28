// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Cross-crate audit integration tests.
//! Exercises AuditLogger with realistic engine outputs.
//!
//! NOTE: Uses manual tokio runtime because we cannot modify
//! vellaveto-audit/Cargo.toml to add tokio/macros feature.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

// ══════════════════════════════════════════════════════
// HAPPY PATH
// ══════════════════════════════════════════════════════

#[test]
fn test_log_and_load_single_entry() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let action = make_action("file", "read");
        let verdict = Verdict::Allow;

        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();
        let entries = logger.load_entries().await.unwrap();

        assert_eq!(
            entries.len(),
            1,
            "should have exactly one entry after one log"
        );
    });
}

#[test]
fn test_log_and_load_multiple_entries() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        for i in 0..10 {
            let action = make_action("tool", &format!("func_{}", i));
            let verdict = if i % 2 == 0 {
                Verdict::Allow
            } else {
                Verdict::Deny {
                    reason: format!("denied action {}", i),
                }
            };
            logger
                .log_entry(&action, &verdict, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 10, "should have 10 entries");
    });
}

// ... (same pattern for ALL remaining tests)
