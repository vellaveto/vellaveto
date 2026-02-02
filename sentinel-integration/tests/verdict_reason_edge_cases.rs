//! Tests Verdict serialization and audit logging with unusual reason strings.
//! Reasons can contain anything — empty strings, unicode, JSON-like content,
//! very long strings. The audit pipeline must preserve them exactly.

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

fn action() -> Action {
    Action {
        tool: "reason_test".to_string(),
        function: "check".to_string(),
        parameters: json!({}),
    }
}

// ═══════════════════════════════════
// SERIALIZATION ROUNDTRIPS
// ═══════════════════════════════════

#[test]
fn deny_empty_reason_roundtrips() {
    let v = Verdict::Deny { reason: String::new() };
    let json_str = serde_json::to_string(&v).unwrap();
    let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, deserialized);
}

#[test]
fn deny_unicode_reason_roundtrips() {
    let v = Verdict::Deny { reason: "否: アクセス止 🚫".to_string() };
    let json_str = serde_json::to_string(&v).unwrap();
    let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, deserialized);
}

#[test]
fn deny_json_like_reason_roundtrips() {
    let v = Verdict::Deny { reason: r#"{"injected": "json", "key": [1,2,3]}"#.to_string() };
    let json_str = serde_json::to_string(&v).unwrap();
    let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, deserialized);
}

#[test]
fn deny_newline_reason_roundtrips() {
    let v = Verdict::Deny { reason: "line1\nline2\nline3".to_string() };
    let json_str = serde_json::to_string(&v).unwrap();
    let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, deserialized);
}

#[test]
fn require_approval_long_reason_roundtrips() {
    let long_reason = "a]".repeat(50_000);
    let v = Verdict::RequireApproval { reason: long_reason.clone() };
    let json_str = serde_json::to_string(&v).unwrap();
    let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
    assert_eq!(v, deserialized);
}

// ═══════════════════════════════════
// AUDIT PIPELINE PRESERVATION
// ═══════════════════════════════════

#[test]
fn deny_reason_preserved_through_audit() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let reasons = vec![
            String::new(),
            "simple reason".to_string(),
            "unicode: 日本語 🔥 émojis".to_string(),
            "quotes: \"hello\" and 'world'".to_string(),
            "backslash: \\path\\to\\file".to_string(),
            "tabs\tand\nnewlines".to_string(),
        ];

        let a = action();
        for reason in &reasons {
            let v = Verdict::Deny { reason: reason.clone() };
            logger.log_entry(&a, &v, json!({})).await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), reasons.len());

        for (i, entry) in entries.iter().enumerate() {
            match &entry.verdict {
                Verdict::Deny { reason } => {
                    assert_eq!(reason, &reasons[i], "Reason mismatch at index {}", i);
                }
                other => panic!("Expected Deny at index {}, got {:?}", i, other),
            }
        }
    });
}

#[test]
fn require_approval_reason_preserved_through_audit() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();

        let reason = "Approval needed: user 'admin' requesting dangerous operation in context {\"level\": \"critical\"}";
        let v = Verdict::RequireApproval { reason: reason.to_string() };
        logger.log_entry(&a, &v, json!({})).await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0].verdict {
            Verdict::RequireApproval { reason: loaded_reason } => {
                assert_eq!(loaded_reason, reason);
            }
            other => panic!("Expected RequireApproval, got {:?}", other),
        }
    });
}

#[test]
fn report_counts_correct_with_varied_reasons() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();

        // 3 denies with different reasons, 2 approvals with different reasons
        logger.log_entry(&a, &Verdict::Deny { reason: "".to_string() }, json!({})).await.unwrap();
        logger.log_entry(&a, &Verdict::Deny { reason: "long".repeat(100) }, json!({})).await.unwrap();
        logger.log_entry(&a, &Verdict::Deny { reason: "unicode: 🚫".to_string() }, json!({})).await.unwrap();
        logger.log_entry(&a, &Verdict::RequireApproval { reason: "check".to_string() }, json!({})).await.unwrap();
        logger.log_entry(&a, &Verdict::RequireApproval { reason: "".to_string() }, json!({})).await.unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 5);
        assert_eq!(report.deny_count, 3);
        assert_eq!(report.require_approval_count, 2);
        assert_eq!(report.allow_count, 0);
    });
}