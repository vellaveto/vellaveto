//! Tests for audit types that are defined but have zero test coverage.
//! ErrorLogEntry is exported from vellaveto_audit but never tested.
//! Also tests AuditEntry construction edge cases and AuditReport field access patterns.

use serde_json::json;
use vellaveto_audit::{AuditEntry, AuditReport, ErrorLogEntry};
use vellaveto_types::{Action, Verdict};

// ═══════════════════════════════════
// ERROR LOG ENTRY — ZERO EXISTING COVERAGE
// ═══════════════════════════════════

#[test]
fn error_log_entry_serialization_roundtrip() {
    let entry = ErrorLogEntry {
        timestamp: "2025-06-01T00:00:00Z".to_string(),
        error: "disk full".to_string(),
        context: "writing audit log".to_string(),
    };
    let json_str = serde_json::to_string(&entry).unwrap();
    let deserialized: ErrorLogEntry = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.timestamp, entry.timestamp);
    assert_eq!(deserialized.error, entry.error);
    assert_eq!(deserialized.context, entry.context);
}

#[test]
fn error_log_entry_with_empty_fields() {
    let entry = ErrorLogEntry {
        timestamp: String::new(),
        error: String::new(),
        context: String::new(),
    };
    let json_str = serde_json::to_string(&entry).unwrap();
    let deserialized: ErrorLogEntry = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.error, "");
}

#[test]
fn error_log_entry_with_special_characters_in_error() {
    let entry = ErrorLogEntry {
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        error: "line1\nline2\ttab\"quote\\backslash\0null".to_string(),
        context: "unicode: 🔥 中文 العربية".to_string(),
    };
    let json_str = serde_json::to_string(&entry).unwrap();
    let deserialized: ErrorLogEntry = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.error, entry.error);
    assert_eq!(deserialized.context, entry.context);
}

#[test]
fn error_log_entry_deserialization_from_json_value() {
    let val = json!({
        "timestamp": "2025-01-01T00:00:00Z",
        "error": "test error",
        "context": "test context"
    });
    let entry: ErrorLogEntry = serde_json::from_value(val).unwrap();
    assert_eq!(entry.error, "test error");
}

#[test]
fn error_log_entry_missing_field_fails() {
    let incomplete = json!({"timestamp": "t", "error": "e"});
    let result: Result<ErrorLogEntry, _> = serde_json::from_value(incomplete);
    assert!(
        result.is_err(),
        "Missing 'context' should fail deserialization"
    );
}

#[test]
fn error_log_entry_clone_is_independent() {
    let entry = ErrorLogEntry {
        timestamp: "t".to_string(),
        error: "e".to_string(),
        context: "c".to_string(),
    };
    let cloned = entry.clone();
    // Verify clone produces an independent copy
    assert_eq!(cloned.timestamp, entry.timestamp);
    assert_eq!(cloned.error, entry.error);
    assert_eq!(cloned.context, entry.context);
}

// ═══════════════════════════════════
// AUDIT REPORT — MANUAL CONSTRUCTION EDGE CASES
// ═══════════════════════════════════

#[test]
fn audit_report_with_zero_entries_serializes() {
    let report = AuditReport {
        total_entries: 0,
        allow_count: 0,
        deny_count: 0,
        require_approval_count: 0,
        entries: vec![],
    };
    let json_str = serde_json::to_string(&report).unwrap();
    let deserialized: AuditReport = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.total_entries, 0);
    assert_eq!(deserialized.entries.len(), 0);
}

#[test]
fn audit_report_clone_preserves_all_fields() {
    let report = AuditReport {
        total_entries: 3,
        allow_count: 1,
        deny_count: 1,
        require_approval_count: 1,
        entries: vec![AuditEntry {
            id: "id1".to_string(),
            action: Action::new("t".to_string(), "f".to_string(), json!({})),
            verdict: Verdict::Allow,
            timestamp: "ts1".to_string(),
            metadata: json!({"k": "v"}),
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
        }],
    };
    let cloned = report.clone();
    assert_eq!(cloned.total_entries, report.total_entries);
    assert_eq!(cloned.allow_count, report.allow_count);
    assert_eq!(cloned.entries.len(), report.entries.len());
    assert_eq!(cloned.entries[0].id, report.entries[0].id);
}

// ═══════════════════════════════════
// AUDIT REPORT SERIALIZATION ROUNDTRIP WITH ALL VERDICT TYPES
// ═══════════════════════════════════

#[test]
fn audit_report_with_mixed_verdicts_roundtrips() {
    let report = AuditReport {
        total_entries: 3,
        allow_count: 1,
        deny_count: 1,
        require_approval_count: 1,
        entries: vec![
            AuditEntry {
                id: "a".to_string(),
                action: Action::new("tool".to_string(), "func".to_string(), json!({"p": 1})),
                verdict: Verdict::Allow,
                timestamp: "2025-01-01T00:00:00Z".to_string(),
                metadata: json!({}),
                sequence: 0,
                entry_hash: None,
                prev_hash: None,
            },
            AuditEntry {
                id: "b".to_string(),
                action: Action::new("tool".to_string(), "func".to_string(), json!({})),
                verdict: Verdict::Deny {
                    reason: "blocked".to_string(),
                },
                timestamp: "2025-01-01T00:00:01Z".to_string(),
                metadata: json!({"user": "test"}),
                sequence: 1,
                entry_hash: None,
                prev_hash: None,
            },
            AuditEntry {
                id: "c".to_string(),
                action: Action::new("tool".to_string(), "func".to_string(), json!({})),
                verdict: Verdict::RequireApproval {
                    reason: "needs review".to_string(),
                },
                timestamp: "2025-01-01T00:00:02Z".to_string(),
                metadata: json!(null),
                sequence: 2,
                entry_hash: None,
                prev_hash: None,
            },
        ],
    };

    let json_str = serde_json::to_string(&report).unwrap();
    let deserialized: AuditReport = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.total_entries, 3);
    assert_eq!(deserialized.allow_count, 1);
    assert_eq!(deserialized.deny_count, 1);
    assert_eq!(deserialized.require_approval_count, 1);
    assert_eq!(deserialized.entries.len(), 3);
    assert_eq!(
        deserialized.entries[1].verdict,
        Verdict::Deny {
            reason: "blocked".to_string()
        }
    );
}

/// NOTE: AuditReport has no is_empty() method. Verify total_entries == 0 is the idiom.
#[test]
fn audit_report_emptiness_check_uses_total_entries() {
    let report = AuditReport {
        total_entries: 0,
        allow_count: 0,
        deny_count: 0,
        require_approval_count: 0,
        entries: vec![],
    };
    // This is the correct way to check emptiness — no is_empty() method exists
    assert!(report.total_entries == 0);
    assert!(report.entries.is_empty());
}
