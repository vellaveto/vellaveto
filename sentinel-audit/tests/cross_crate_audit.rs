//! Cross-crate audit integration tests.
//! Exercises AuditLogger with realistic engine outputs.
//!
//! NOTE: Uses manual tokio runtime because we cannot modify
//! sentinel-audit/Cargo.toml to add tokio/macros feature.

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

fn make_action(tool: &str, function: &str) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: json!({}),
    }
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
