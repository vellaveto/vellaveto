//! Serialization roundtrip tests for AuditEntry and AuditReport.
//! Existing tests only roundtrip sentinel-types structs; these test
//! the audit-specific types that go through JSONL persistence.

use sentinel_audit::{AuditEntry, AuditReport};
use sentinel_types::{Action, Verdict};
use serde_json::json;

// ═══════════════════════════════════
// AUDIT ENTRY ROUNDTRIPS
// ═══════════════════════════════════

fn make_entry(verdict: Verdict, metadata: serde_json::Value) -> AuditEntry {
    AuditEntry {
        id: "test-uuid-1234".to_string(),
        action: Action::new(
            "test_tool".to_string(),
            "test_func".to_string(),
            json!({"key": "value"}),
        ),
        verdict,
        timestamp: "2025-01-01T00:00:00+00:00".to_string(),
        metadata,
        entry_hash: None,
        prev_hash: None,
    }
}

#[test]
fn audit_entry_allow_roundtrip() {
    let entry = make_entry(Verdict::Allow, json!({}));
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.id, entry.id);
    assert_eq!(deserialized.action, entry.action);
    assert_eq!(deserialized.verdict, entry.verdict);
    assert_eq!(deserialized.timestamp, entry.timestamp);
    assert_eq!(deserialized.metadata, entry.metadata);
}

#[test]
fn audit_entry_deny_roundtrip() {
    let entry = make_entry(
        Verdict::Deny {
            reason: "policy violation".to_string(),
        },
        json!({"user": "admin", "ip": "10.0.0.1"}),
    );
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.verdict, entry.verdict);
    assert_eq!(deserialized.metadata, entry.metadata);
}

#[test]
fn audit_entry_require_approval_roundtrip() {
    let entry = make_entry(
        Verdict::RequireApproval {
            reason: "needs manager sign-off".to_string(),
        },
        json!({"escalation_level": 2}),
    );
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.verdict, entry.verdict);
}

#[test]
fn audit_entry_with_complex_metadata_roundtrip() {
    let metadata = json!({
        "nested": {
            "array": [1, 2, 3],
            "object": {"deep": true},
            "null_val": null
        },
        "unicode": "日本語テト🎉",
        "empty_string": "",
        "number": 42.5
    });
    let entry = make_entry(Verdict::Allow, metadata.clone());
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.metadata, metadata);
}

#[test]
fn audit_entry_with_null_metadata_roundtrip() {
    let entry = make_entry(Verdict::Allow, json!(null));
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.metadata, json!(null));
}

#[test]
fn audit_entry_with_array_metadata_roundtrip() {
    let entry = make_entry(Verdict::Allow, json!([1, "two", null]));
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.metadata, json!([1, "two", null]));
}

// ══════════════════════════════════
// AUDIT ENTRY: JSONL FORMAT (one entry per line)
// ══════════════════════════════════

#[test]
fn audit_entry_serializes_to_single_line() {
    let entry = make_entry(Verdict::Allow, json!({"multi": "field", "data": [1,2,3]}));
    let serialized = serde_json::to_string(&entry).unwrap();
    // serde_json::to_string (not to_string_pretty) should produce a single line
    assert!(
        !serialized.contains('\n'),
        "Serialized entry should be a single line"
    );
    assert!(
        !serialized.contains('\r'),
        "Serialized entry should not contain carriage returns"
    );
}

// ══════════════════════════════════
// AUDIT REPORT ROUNDTRIPS
// ══════════════════════════════════

fn make_report(entries: Vec<AuditEntry>) -> AuditReport {
    let mut allow_count = 0;
    let mut deny_count = 0;
    let mut require_approval_count = 0;
    for e in &entries {
        match &e.verdict {
            Verdict::Allow => allow_count += 1,
            Verdict::Deny { .. } => deny_count += 1,
            Verdict::RequireApproval { .. } => require_approval_count += 1,
        }
    }
    AuditReport {
        total_entries: entries.len(),
        allow_count,
        deny_count,
        require_approval_count,
        entries,
    }
}

#[test]
fn empty_report_roundtrip() {
    let report = make_report(vec![]);
    let serialized = serde_json::to_string(&report).unwrap();
    let deserialized: AuditReport = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.total_entries, 0);
    assert_eq!(deserialized.allow_count, 0);
    assert_eq!(deserialized.deny_count, 0);
    assert_eq!(deserialized.require_approval_count, 0);
    assert!(deserialized.entries.is_empty());
}

#[test]
fn report_with_mixed_verdicts_roundtrip() {
    let entries = vec![
        make_entry(Verdict::Allow, json!({})),
        make_entry(
            Verdict::Deny {
                reason: "bad".to_string(),
            },
            json!({}),
        ),
        make_entry(
            Verdict::RequireApproval {
                reason: "review".to_string(),
            },
            json!({}),
        ),
        make_entry(Verdict::Allow, json!({})),
    ];
    let report = make_report(entries);
    let serialized = serde_json::to_string(&report).unwrap();
    let deserialized: AuditReport = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.total_entries, 4);
    assert_eq!(deserialized.allow_count, 2);
    assert_eq!(deserialized.deny_count, 1);
    assert_eq!(deserialized.require_approval_count, 1);
    assert_eq!(deserialized.entries.len(), 4);
}

#[test]
fn report_counts_match_entries_after_roundtrip() {
    let entries = vec![
        make_entry(
            Verdict::Deny {
                reason: "a".to_string(),
            },
            json!({}),
        ),
        make_entry(
            Verdict::Deny {
                reason: "b".to_string(),
            },
            json!({}),
        ),
        make_entry(
            Verdict::Deny {
                reason: "c".to_string(),
            },
            json!({}),
        ),
    ];
    let report = make_report(entries);
    let serialized = serde_json::to_string(&report).unwrap();
    let deserialized: AuditReport = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.total_entries, deserialized.entries.len());
    assert_eq!(deserialized.deny_count, 3);
    assert_eq!(deserialized.allow_count, 0);
    assert_eq!(deserialized.require_approval_count, 0);
}

// ═══════════════════════════════════
// AUDIT ENTRY DESERIALIZATION FROM RAW JSON
// ═══════════════════════════════════

#[test]
fn audit_entry_from_raw_json() {
    let raw = json!({
        "id": "manual-id",
        "action": {
            "tool": "bash",
            "function": "exec",
            "parameters": {}
        },
        "verdict": "Allow",
        "timestamp": "2025-06-01T12:00:00Z",
        "metadata": {"source": "test"}
    });
    let entry: AuditEntry = serde_json::from_value(raw).unwrap();
    assert_eq!(entry.id, "manual-id");
    assert_eq!(entry.action.tool, "bash");
    assert_eq!(entry.verdict, Verdict::Allow);
}

#[test]
fn audit_entry_from_raw_json_deny_verdict() {
    let raw = json!({
        "id": "deny-entry",
        "action": {
            "tool": "file",
            "function": "delete",
            "parameters": {"path": "/etc/passwd"}
        },
        "verdict": {"Deny": {"reason": "forbidden file"}},
        "timestamp": "2025-06-01T12:00:00Z",
        "metadata": {}
    });
    let entry: AuditEntry = serde_json::from_value(raw).unwrap();
    assert_eq!(
        entry.verdict,
        Verdict::Deny {
            reason: "forbidden file".to_string()
        }
    );
}

#[test]
fn audit_entry_missing_field_fails_deserialization() {
    // Missing "verdict" field
    let raw = json!({
        "id": "bad",
        "action": {"tool": "t", "function": "f", "parameters": {}},
        "timestamp": "2025-01-01T00:00:00Z",
        "metadata": {}
    });
    let result: Result<AuditEntry, _> = serde_json::from_value(raw);
    assert!(result.is_err(), "Missing verdict field should fail");
}

// ══════════════════════════════════
// ERROR LOG ENTRY ROUNDTRIP
// ══════════════════════════════════

#[test]
fn error_log_entry_roundtrip() {
    use sentinel_audit::ErrorLogEntry;

    let entry = ErrorLogEntry {
        timestamp: "2025-01-01T00:00:00Z".to_string(),
        error: "connection refused".to_string(),
        context: "audit flush".to_string(),
    };
    let serialized = serde_json::to_string(&entry).unwrap();
    let deserialized: ErrorLogEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.error, "connection refused");
    assert_eq!(deserialized.context, "audit flush");
}
