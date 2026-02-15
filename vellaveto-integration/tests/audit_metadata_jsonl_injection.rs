//! Tests that metadata containing JSONL-injection-like content
//! (embedded newlines, valid JSON strings) is safely serialized.
//! serde_json escapes embedded newlines in strings, so injection
//! should be impossible — but let's prove it.

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

fn action() -> Action {
    Action::new("injection_test".to_string(), "probe".to_string(), json!({}))
}

// ════════════════════════════════
// METADATA WITH EMBEDDED NEWLINES IN STRING VALUES
// ═══════════════════════════════

/// Metadata containing a string with \n should be escaped by serde_json.
/// The log file should still have exactly one JSONL line per entry.
#[test]
fn metadata_with_newline_in_string_produces_single_jsonl_line() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, tmp) = setup_logger();
        let metadata = json!({"note": "line1\nline2\nline3"});
        logger
            .log_entry(&action(), &Verdict::Allow, metadata.clone())
            .await
            .unwrap();

        // Read raw file — should be exactly one line (plus trailing newline)
        let raw = tokio::fs::read_to_string(tmp.path().join("audit.log"))
            .await
            .unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "Metadata with embedded \\n should produce exactly 1 JSONL line, got {}",
            lines.len()
        );

        // Load through the API — metadata should be preserved exactly
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata["note"], "line1\nline2\nline3");
    });
}

/// Metadata containing what looks like a valid JSON object in a string value.
#[test]
fn metadata_with_json_like_string_value_is_safe() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let metadata = json!({"payload": "{\"injected\": true}\n{\"extra\": \"line\"}"});
        logger
            .log_entry(&action(), &Verdict::Allow, metadata.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        // The metadata should be the exact string, not parsed as JSON
        assert_eq!(
            entries[0].metadata["payload"],
            "{\"injected\": true}\n{\"extra\": \"line\"}"
        );
    });
}

// ═══════════════════════════════
// METADATA WITH DEEPLY NESTED CONTENT
// ════════════════════════════════

/// Metadata with 10 levels of nesting (well under audit's 20-level limit
/// on action parameters — metadata itself is not depth-checked).
#[test]
fn deeply_nested_metadata_survives_roundtrip() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let deep =
            json!({"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": "leaf"}}}}}}}}}});
        logger
            .log_entry(&action(), &Verdict::Allow, deep.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, deep);
    });
}

// ════════════════════════════════
// MULTIPLE ENTRIES WITH TRICKY METADATA
// ═══════════════════════════════

/// Write 3 entries with different tricky metadata, verify all survive.
#[test]
fn multiple_tricky_metadata_entries_all_survive() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = &action();

        let meta1 = json!({"key": "value\twith\ttabs"});
        let meta2 = json!({"key": "value\"with\"quotes"});
        let meta3 = json!({"key": "value\\with\\backslashes"});

        logger
            .log_entry(a, &Verdict::Allow, meta1.clone())
            .await
            .unwrap();
        logger
            .log_entry(a, &Verdict::Allow, meta2.clone())
            .await
            .unwrap();
        logger
            .log_entry(a, &Verdict::Allow, meta3.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].metadata, meta1);
        assert_eq!(entries[1].metadata, meta2);
        assert_eq!(entries[2].metadata, meta3);
    });
}

// ═══════════════════════════════
// METADATA WITH UNICODE AND EMOJI
// ════════════════════════════════

#[test]
fn metadata_with_unicode_and_emoji_survives() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let meta = json!({
            "emoji": "🛡️💀",
            "chinese": "中文测试",
            "arabic": "اختبار",
            "mixed": "hello 世界 🌍"
        });
        logger
            .log_entry(&action(), &Verdict::Allow, meta.clone())
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, meta);
    });
}
