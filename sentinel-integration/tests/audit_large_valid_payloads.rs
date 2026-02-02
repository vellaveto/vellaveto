//! Tests that large-but-valid payloads survive the full audit pipeline:
//! write → load → report. Exercises near-boundary sizes without tripping
//! validation limits.

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

// ═══════════════════════════════════
// LARGE PARAMETER VALUES (UNDER 1MB LIMIT)
// ═══════════════════════════════════

/// Parameters with a ~500KB string value. Well under the 1MB limit but
/// exercises that large serialized entries survive JSONL roundtrip.
#[test]
fn large_string_parameter_survives_roundtrip() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let big_value = "x".repeat(500_000);
        let action = Action {
            tool: "large_test".to_string(),
            function: "write".to_string(),
            parameters: json!({"data": big_value}),
        };

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "large_test");
        let loaded_data = entries[0]
            .action
            .parameters
            .get("data")
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(loaded_data.len(), 500_000);
    });
}

/// Multiple large entries accumulate correctly in the report.
#[test]
fn multiple_large_entries_report_consistent() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let big_value = "y".repeat(100_000);

        for i in 0..5 {
            let action = Action {
                tool: format!("large_{}", i),
                function: "test".to_string(),
                parameters: json!({"payload": big_value}),
            };
            let verdict = if i % 2 == 0 {
                Verdict::Allow
            } else {
                Verdict::Deny {
                    reason: "test".to_string(),
                }
            };
            logger
                .log_entry(&action, &verdict, json!({"index": i}))
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 5);
        assert_eq!(report.allow_count, 3); // i=0,2,4
        assert_eq!(report.deny_count, 2); // i=1,3
        assert_eq!(report.require_approval_count, 0);
        assert_eq!(report.entries.len(), 5);
    });
}

/// Nesting depth of exactly 19 (under limit of 20) with wide objects.
#[test]
fn deep_but_valid_nesting_survives_pipeline() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        // Build 19 levels of nesting
        let mut val = json!("leaf");
        for _ in 0..19 {
            val = json!({"nested": val});
        }

        let action = Action {
            tool: "deep_test".to_string(),
            function: "nest".to_string(),
            parameters: val.clone(),
        };

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.parameters, val);
    });
}

/// Large metadata (not just parameters) survives roundtrip.
#[test]
fn large_metadata_survives_roundtrip() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        let action = Action {
            tool: "meta".to_string(),
            function: "test".to_string(),
            parameters: json!({}),
        };

        let big_meta = json!({
            "trace_id": "a".repeat(1000),
            "tags": (0..100).map(|i| format!("tag_{}", i)).collect::<Vec<_>>(),
            "context": {
                "user": "test_user",
                "session": "b".repeat(500),
            }
        });

        logger
            .log_entry(&action, &Verdict::Allow, big_meta.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, big_meta);
    });
}

/// Long tool and function names (no newlines or null bytes) are accepted.
#[test]
fn long_tool_and_function_names_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        let long_tool = "t".repeat(10_000);
        let long_func = "f".repeat(10_000);
        let action = Action {
            tool: long_tool.clone(),
            function: long_func.clone(),
            parameters: json!({}),
        };

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, long_tool);
        assert_eq!(entries[0].action.function, long_func);
    });
}
