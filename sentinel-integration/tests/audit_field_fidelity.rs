//! Tests that every field of an AuditEntry survives the full
//! write → JSONL → load cycle with exact fidelity.
//! Existing tests verify counts and IDs but rarely check that
//! action fields, verdict details, and metadata are preserved exactly.

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

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

// ═══════════════════════════
// ACTION FIELDS PRESERVED
// ═════════════════════════════

#[test]
fn action_tool_and_function_preserved_through_audit() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "my_special_tool".to_string(),
            function: "do_something_complex".to_string(),
            parameters: json!({"key1": "val1", "key2": 42, "key3": [1, 2, 3]}),
        };
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "my_special_tool");
        assert_eq!(entries[0].action.function, "do_something_complex");
        assert_eq!(
            entries[0].action.parameters,
            json!({"key1": "val1", "key2": 42, "key3": [1, 2, 3]})
        );
    });
}

#[test]
fn deny_reason_preserved_through_audit() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "t".to_string(),
            function: "f".to_string(),
            parameters: json!({}),
        };
        let verdict = Verdict::Deny {
            reason: "specific denial reason with unicode: 日本語".to_string(),
        };
        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0].verdict {
            Verdict::Deny { reason } => {
                assert_eq!(reason, "specific denial reason with unicode: 日本語");
            }
            other => panic!("Expected Deny, got {:?}", other),
        }
    });
}

#[test]
fn require_approval_reason_preserved_through_audit() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "t".to_string(),
            function: "f".to_string(),
            parameters: json!({}),
        };
        let verdict = Verdict::RequireApproval {
            reason: "needs manager sign-off: level >= 3".to_string(),
        };
        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0].verdict {
            Verdict::RequireApproval { reason } => {
                assert_eq!(reason, "needs manager sign-off: level >= 3");
            }
            other => panic!("Expected RequireApproval, got {:?}", other),
        }
    });
}

// ════════════════════════════════
// METADATA PRESERVED EXACTLY
// ════════════════════════════════

#[test]
fn complex_metadata_preserved_through_audit() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "t".to_string(),
            function: "f".to_string(),
            parameters: json!({}),
        };
        let metadata = json!({
            "user": "admin",
            "ip": "192.168.1.1",
            "tags": ["security", "high-risk"],
            "nested": {"level": 2, "flag": true},
            "nullable": null
        });
        logger
            .log_entry(&action, &Verdict::Allow, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, metadata);
    });
}

#[test]
fn empty_object_metadata_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "t".to_string(),
            function: "f".to_string(),
            parameters: json!({}),
        };
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries[0].metadata, json!({}));
    });
}

#[test]
fn null_metadata_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "t".to_string(),
            function: "f".to_string(),
            parameters: json!({}),
        };
        logger
            .log_entry(&action, &Verdict::Allow, json!(null))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries[0].metadata, json!(null));
    });
}

// ════════════════════════════════════
// MULTIPLE ENTRIES PRESERVE ALL FIELDS
// ═════════════════════════════════════

#[test]
fn three_entries_with_different_verdicts_preserve_all_fields() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        let actions_verdicts_meta = vec![
            (
                Action {
                    tool: "file".to_string(),
                    function: "read".to_string(),
                    parameters: json!({"path": "/etc/hosts"}),
                },
                Verdict::Allow,
                json!({"user": "alice"}),
            ),
            (
                Action {
                    tool: "bash".to_string(),
                    function: "exec".to_string(),
                    parameters: json!({"cmd": "ls"}),
                },
                Verdict::Deny {
                    reason: "bash blocked".to_string(),
                },
                json!({"user": "bob", "attempt": 3}),
            ),
            (
                Action {
                    tool: "net".to_string(),
                    function: "connect".to_string(),
                    parameters: json!({"host": "example.com"}),
                },
                Verdict::RequireApproval {
                    reason: "external network".to_string(),
                },
                json!({"policy_version": "2.0"}),
            ),
        ];

        for (action, verdict, meta) in &actions_verdicts_meta {
            logger
                .log_entry(action, verdict, meta.clone())
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 3);

        // Verify each entry
        assert_eq!(entries[0].action.tool, "file");
        assert_eq!(entries[0].action.function, "read");
        assert_eq!(entries[0].action.parameters, json!({"path": "/etc/hosts"}));
        assert!(matches!(entries[0].verdict, Verdict::Allow));
        assert_eq!(entries[0].metadata, json!({"user": "alice"}));

        assert_eq!(entries[1].action.tool, "bash");
        assert_eq!(entries[1].action.function, "exec");
        match &entries[1].verdict {
            Verdict::Deny { reason } => assert_eq!(reason, "bash blocked"),
            other => panic!("Expected Deny, got {:?}", other),
        }
        assert_eq!(entries[1].metadata, json!({"user": "bob", "attempt": 3}));

        assert_eq!(entries[2].action.tool, "net");
        match &entries[2].verdict {
            Verdict::RequireApproval { reason } => assert_eq!(reason, "external network"),
            other => panic!("Expected RequireApproval, got {:?}", other),
        }
    });
}
