// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that metadata passed to AuditLogger::log_entry is preserved
//! exactly as-is through the write→load cycle. No existing test
//! actually asserts metadata field values after loading.

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
    Action::new("meta_test".to_string(), "check".to_string(), json!({}))
}

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

// ═════════════════════════════════
// METADATA PRESERVATION
// ════════════════════════════════

#[test]
fn empty_object_metadata_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        logger
            .log_entry(&make_action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, json!({}));
    });
}

#[test]
fn nested_metadata_preserved_exactly() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let metadata = json!({
            "user": "admin",
            "session": {
                "id": "sess_123",
                "ip": "192.168.1.1",
                "tags": ["internal", "elevated"]
            },
            "timestamp_ms": 1_700_000_000_000_i64,
            "flags": [true, false, null]
        });

        logger
            .log_entry(&make_action(), &Verdict::Allow, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        // SECURITY (R22-SUP-1): Default PiiScanner now redacts IPv4 addresses
        let expected = json!({
            "user": "admin",
            "session": {
                "id": "sess_123",
                "ip": "[REDACTED]",
                "tags": ["internal", "elevated"]
            },
            "timestamp_ms": 1_700_000_000_000_i64,
            "flags": [true, false, null]
        });
        assert_eq!(entries[0].metadata, expected);
    });
}

#[test]
fn null_metadata_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        logger
            .log_entry(&make_action(), &Verdict::Allow, json!(null))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, json!(null));
    });
}

#[test]
fn string_metadata_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        logger
            .log_entry(&make_action(), &Verdict::Allow, json!("just a string"))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, json!("just a string"));
    });
}

#[test]
fn array_metadata_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let metadata = json!([1, "two", null, true, 3.15, {"nested": "obj"}]);

        logger
            .log_entry(&make_action(), &Verdict::Allow, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, metadata);
    });
}

#[test]
fn numeric_metadata_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        logger
            .log_entry(&make_action(), &Verdict::Allow, json!(42))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, json!(42));
    });
}

#[test]
fn boolean_metadata_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        logger
            .log_entry(&make_action(), &Verdict::Allow, json!(false))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, json!(false));
    });
}

// ════════════════════════════════
// MULTIPLE ENTRIES WITH DIFFERENT METADATA
// ════════════════════════════════

#[test]
fn different_metadata_per_entry_preserved_in_order() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let metadatas = vec![
            json!({"index": 0}),
            json!({"index": 1, "extra": "data"}),
            json!(null),
            json!("string_meta"),
            json!([1, 2, 3]),
        ];

        for meta in &metadatas {
            logger
                .log_entry(&make_action(), &Verdict::Allow, meta.clone())
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), metadatas.len());
        for (entry, expected) in entries.iter().zip(metadatas.iter()) {
            assert_eq!(&entry.metadata, expected);
        }
    });
}

// ═════════════════════════════════
// VERDICT PRESERVED ALONGSIDE METADATA
// ════════════════════════════════

#[test]
fn deny_verdict_reason_and_metadata_both_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let metadata = json!({"policy_id": "bash_block", "user": "attacker"});
        let verdict = Verdict::Deny {
            reason: "Bash commands blocked".to_string(),
        };

        logger
            .log_entry(&make_action(), &verdict, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, metadata);
        match &entries[0].verdict {
            Verdict::Deny { reason } => {
                assert_eq!(reason, "Bash commands blocked");
            }
            other => panic!("Expected Deny, got {other:?}"),
        }
    });
}

#[test]
fn require_approval_verdict_and_metadata_both_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let metadata = json!({"approver": "security_team"});
        let verdict = Verdict::RequireApproval {
            reason: "Manual review required".to_string(),
        };

        logger
            .log_entry(&make_action(), &verdict, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, metadata);
        match &entries[0].verdict {
            Verdict::RequireApproval { reason } => {
                assert_eq!(reason, "Manual review required");
            }
            other => panic!("Expected RequireApproval, got {other:?}"),
        }
    });
}
