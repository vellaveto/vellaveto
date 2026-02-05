//! Audit log export formatters for SIEM integration.
//!
//! Supports two formats:
//! - **CEF** (Common Event Format): Standardized format used by ArcSight, Splunk, and
//!   most SIEM platforms. Each entry becomes one line in CEF format.
//! - **JSON Lines**: One JSON object per line (`.jsonl` / `.ndjson`), compatible with
//!   Elasticsearch, Datadog, and generic log pipelines.

use crate::AuditEntry;
use sentinel_types::Verdict;

/// Export format for audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// Common Event Format (CEF) — standard SIEM interchange format.
    Cef,
    /// JSON Lines (one JSON object per line) — ndjson format.
    JsonLines,
}

impl ExportFormat {
    /// Parse a format name from a string.
    ///
    /// Accepts case-insensitive: `"cef"`, `"jsonl"`, `"json_lines"`, `"jsonlines"`.
    /// Returns `None` for unrecognized formats.
    pub fn parse_format(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cef" => Some(Self::Cef),
            "jsonl" | "json_lines" | "jsonlines" => Some(Self::JsonLines),
            _ => None,
        }
    }
}

/// Convert an AuditEntry to CEF (Common Event Format) string.
///
/// Format: `CEF:0|Sentinel|MCP Firewall|1.0|{signatureId}|{name}|{severity}|extensions`
///
/// CEF severity mapping:
/// - `Allow` -> 1 (Low)
/// - `RequireApproval` -> 5 (Medium)
/// - `Deny` -> 8 (High)
pub fn to_cef(entry: &AuditEntry) -> String {
    let verdict_str = match &entry.verdict {
        Verdict::Allow => "Allow",
        Verdict::Deny { .. } => "Deny",
        Verdict::RequireApproval { .. } => "RequireApproval",
    };

    let severity = match &entry.verdict {
        Verdict::Allow => 1,
        Verdict::RequireApproval { .. } => 5,
        Verdict::Deny { .. } => 8,
    };

    let tool_function = format!(
        "{}:{}",
        cef_escape(&entry.action.tool),
        cef_escape(&entry.action.function)
    );

    // SECURITY (R24-SUP-3): Include deny reason in CEF output for SIEM
    // analysts to understand why a tool call was blocked.
    let reason_ext = match &entry.verdict {
        Verdict::Deny { reason } => format!(" cs2={} cs2Label=denyReason", cef_escape_ext(reason)),
        Verdict::RequireApproval { reason, .. } => format!(" cs2={} cs2Label=approvalReason", cef_escape_ext(reason)),
        Verdict::Allow => String::new(),
    };

    format!(
        "CEF:0|Sentinel|MCP Firewall|1.0|{}|{}|{}|rt={} cs1={} cs1Label=entryId{}",
        cef_escape(verdict_str),
        tool_function,
        severity,
        cef_escape_ext(&entry.timestamp),
        cef_escape_ext(&entry.id),
        reason_ext,
    )
}

/// Escape special characters for CEF header fields.
///
/// Per the CEF specification, the following characters must be escaped in
/// header values (pipe-delimited fields): backslash, pipe, newline, carriage return.
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        // SECURITY (R15-SIEM-2): Unicode line separators can inject fake CEF entries
        .replace(['\u{2028}', '\u{2029}'], "\\n")
}

/// Escape special characters for CEF extension values (key=value pairs).
///
/// Per the CEF specification, extension values must escape: backslash,
/// equals sign, newline, carriage return. Pipe is NOT escaped in extensions.
fn cef_escape_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        // SECURITY (R15-SIEM-2): Unicode line separators can inject fake CEF entries
        .replace(['\u{2028}', '\u{2029}'], "\\n")
}

/// Convert an AuditEntry to JSON Lines format (one JSON object per line).
///
/// Uses compact serialization (no pretty-print) with a trailing newline.
/// If serialization fails (which should not happen for a valid AuditEntry),
/// returns an empty string rather than panicking.
pub fn to_json_lines(entry: &AuditEntry) -> String {
    match serde_json::to_string(entry) {
        Ok(json) => format!("{}\n", json),
        Err(_) => String::new(),
    }
}

/// Format a batch of entries in the requested format.
///
/// Returns a single string with all entries formatted and newline-separated.
pub fn format_entries(entries: &[AuditEntry], format: ExportFormat) -> String {
    let mut output = String::new();
    for entry in entries {
        match format {
            ExportFormat::Cef => {
                output.push_str(&to_cef(entry));
                output.push('\n');
            }
            ExportFormat::JsonLines => {
                output.push_str(&to_json_lines(entry));
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_types::Action;

    /// Helper to create a test AuditEntry with the given verdict.
    fn make_entry(tool: &str, function: &str, verdict: Verdict) -> AuditEntry {
        AuditEntry {
            id: "test-entry-001".to_string(),
            action: Action::new(tool, function, serde_json::json!({"path": "/tmp/test"})),
            verdict,
            timestamp: "2026-02-04T12:00:00Z".to_string(),
            metadata: serde_json::json!({"source": "test"}),
            entry_hash: Some("abc123".to_string()),
            prev_hash: None,
        }
    }

    #[test]
    fn test_cef_format_allow_verdict() {
        let entry = make_entry("read_file", "execute", Verdict::Allow);
        let cef = to_cef(&entry);

        assert!(cef.starts_with("CEF:0|Sentinel|MCP Firewall|1.0|"));
        assert!(cef.contains("|Allow|"));
        assert!(cef.contains("read_file:execute"));
        assert!(cef.contains("|1|")); // severity 1 for Allow
        assert!(cef.contains("rt=2026-02-04T12:00:00Z"));
        assert!(cef.contains("cs1=test-entry-001"));
        assert!(cef.contains("cs1Label=entryId"));
    }

    #[test]
    fn test_cef_format_deny_verdict() {
        let entry = make_entry(
            "bash",
            "exec",
            Verdict::Deny {
                reason: "blocked by policy".to_string(),
            },
        );
        let cef = to_cef(&entry);

        assert!(cef.contains("|Deny|"));
        assert!(cef.contains("bash:exec"));
        assert!(cef.contains("|8|")); // severity 8 for Deny
    }

    #[test]
    fn test_cef_deny_includes_reason() {
        // R24-SUP-3: CEF output must include deny reason for SIEM analysts
        let entry = make_entry(
            "bash",
            "exec",
            Verdict::Deny {
                reason: "blocked by policy X".to_string(),
            },
        );
        let cef = to_cef(&entry);
        assert!(
            cef.contains("cs2=blocked by policy X"),
            "CEF should include deny reason, got: {}",
            cef
        );
        assert!(
            cef.contains("cs2Label=denyReason"),
            "CEF should label deny reason, got: {}",
            cef
        );
    }

    #[test]
    fn test_cef_allow_has_no_reason() {
        let entry = make_entry("t", "f", Verdict::Allow);
        let cef = to_cef(&entry);
        assert!(
            !cef.contains("cs2="),
            "Allow verdict should have no reason field, got: {}",
            cef
        );
    }

    #[test]
    fn test_cef_severity_mapping() {
        // Allow -> severity 1
        let allow_entry = make_entry("t", "f", Verdict::Allow);
        let allow_cef = to_cef(&allow_entry);
        assert!(
            allow_cef.contains("|1|"),
            "Allow should have severity 1, got: {}",
            allow_cef
        );

        // RequireApproval -> severity 5
        let approval_entry = make_entry(
            "t",
            "f",
            Verdict::RequireApproval {
                reason: "needs review".to_string(),
            },
        );
        let approval_cef = to_cef(&approval_entry);
        assert!(
            approval_cef.contains("|5|"),
            "RequireApproval should have severity 5, got: {}",
            approval_cef
        );

        // Deny -> severity 8
        let deny_entry = make_entry(
            "t",
            "f",
            Verdict::Deny {
                reason: "denied".to_string(),
            },
        );
        let deny_cef = to_cef(&deny_entry);
        assert!(
            deny_cef.contains("|8|"),
            "Deny should have severity 8, got: {}",
            deny_cef
        );
    }

    #[test]
    fn test_json_lines_format() {
        let entry = make_entry("read_file", "execute", Verdict::Allow);
        let jsonl = to_json_lines(&entry);

        // Must end with exactly one newline
        assert!(jsonl.ends_with('\n'));
        assert!(!jsonl.ends_with("\n\n"));

        // Must be valid JSON when trimmed
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.trim()).expect("JSON Lines output must be valid JSON");

        // Spot-check key fields
        assert_eq!(parsed["id"], "test-entry-001");
        assert_eq!(parsed["action"]["tool"], "read_file");
        assert_eq!(parsed["action"]["function"], "execute");
        assert_eq!(parsed["verdict"], "Allow");
        assert_eq!(parsed["timestamp"], "2026-02-04T12:00:00Z");
    }

    #[test]
    fn test_format_entries_batch() {
        let entries = vec![
            make_entry("tool_a", "func_a", Verdict::Allow),
            make_entry(
                "tool_b",
                "func_b",
                Verdict::Deny {
                    reason: "blocked".to_string(),
                },
            ),
        ];

        // CEF batch
        let cef_output = format_entries(&entries, ExportFormat::Cef);
        let cef_lines: Vec<&str> = cef_output.trim_end().split('\n').collect();
        assert_eq!(cef_lines.len(), 2, "Should have 2 CEF lines");
        assert!(cef_lines[0].contains("tool_a:func_a"));
        assert!(cef_lines[1].contains("tool_b:func_b"));

        // JSONL batch
        let jsonl_output = format_entries(&entries, ExportFormat::JsonLines);
        let jsonl_lines: Vec<&str> = jsonl_output.trim_end().split('\n').collect();
        assert_eq!(jsonl_lines.len(), 2, "Should have 2 JSONL lines");
        // Each line must be valid JSON
        for line in &jsonl_lines {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("Each JSONL line must be valid JSON");
        }

        // Empty batch
        let empty_cef = format_entries(&[], ExportFormat::Cef);
        assert!(empty_cef.is_empty());
        let empty_jsonl = format_entries(&[], ExportFormat::JsonLines);
        assert!(empty_jsonl.is_empty());
    }

    #[test]
    fn test_cef_escape_special_chars() {
        // Backslash
        assert_eq!(cef_escape("a\\b"), "a\\\\b");
        // Pipe
        assert_eq!(cef_escape("a|b"), "a\\|b");
        // Newline
        assert_eq!(cef_escape("a\nb"), "a\\nb");
        // Carriage return
        assert_eq!(cef_escape("a\rb"), "a\\rb");
        // Multiple special chars
        assert_eq!(cef_escape("a\\|b\nc\rd"), "a\\\\\\|b\\nc\\rd");
        // No special chars
        assert_eq!(cef_escape("normal text"), "normal text");
        // Empty string
        assert_eq!(cef_escape(""), "");
    }

    #[test]
    fn test_export_format_from_str() {
        assert_eq!(ExportFormat::parse_format("cef"), Some(ExportFormat::Cef));
        assert_eq!(ExportFormat::parse_format("CEF"), Some(ExportFormat::Cef));
        assert_eq!(ExportFormat::parse_format("Cef"), Some(ExportFormat::Cef));
        assert_eq!(
            ExportFormat::parse_format("jsonl"),
            Some(ExportFormat::JsonLines)
        );
        assert_eq!(
            ExportFormat::parse_format("json_lines"),
            Some(ExportFormat::JsonLines)
        );
        assert_eq!(
            ExportFormat::parse_format("jsonlines"),
            Some(ExportFormat::JsonLines)
        );
        assert_eq!(
            ExportFormat::parse_format("JSONL"),
            Some(ExportFormat::JsonLines)
        );
        assert_eq!(ExportFormat::parse_format("xml"), None);
        assert_eq!(ExportFormat::parse_format(""), None);
    }

    #[test]
    fn test_cef_entry_with_special_chars_in_fields() {
        // Tool name with pipe character (should be escaped)
        let entry = make_entry("tool|with|pipes", "func\\with\\backslash", Verdict::Allow);
        let cef = to_cef(&entry);
        // Verify the output doesn't break CEF format (extra unescaped pipes)
        assert!(cef.contains("tool\\|with\\|pipes"));
        assert!(cef.contains("func\\\\with\\\\backslash"));
        // The CEF header should still have exactly 7 pipe-delimited fields
        // (unescaped pipes count)
        let unescaped_pipes = cef
            .chars()
            .zip(cef.chars().skip(1).chain(std::iter::once('\0')))
            .filter(|&(prev, cur)| cur == '|' && prev != '\\')
            .count()
            // Also count pipes at position 0 if present
            + if cef.starts_with('|') { 1 } else { 0 };
        // CEF:0|vendor|product|version|sigId|name|severity|extensions
        // That's 7 unescaped pipes
        assert!(
            unescaped_pipes >= 7,
            "CEF should have at least 7 unescaped pipes, got {}",
            unescaped_pipes
        );
    }

    // ── Adversarial Tests: CEF Extension Escaping ──

    #[test]
    fn test_cef_ext_escape_equals_sign() {
        // CEF extension values must escape '=' to prevent injection
        assert_eq!(cef_escape_ext("key=value"), "key\\=value");
        assert_eq!(cef_escape_ext("a=b=c"), "a\\=b\\=c");
    }

    #[test]
    fn test_cef_ext_escape_backslash_and_newline() {
        assert_eq!(cef_escape_ext("a\\b"), "a\\\\b");
        assert_eq!(cef_escape_ext("a\nb"), "a\\nb");
        assert_eq!(cef_escape_ext("a\rb"), "a\\rb");
    }

    #[test]
    fn test_cef_ext_does_not_escape_pipe() {
        // Pipe is only escaped in headers, NOT in extension values
        assert_eq!(cef_escape_ext("a|b"), "a|b");
    }

    #[test]
    fn test_cef_escape_unicode_line_separators() {
        // U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR
        // These could inject fake CEF lines if not escaped
        assert_eq!(cef_escape("before\u{2028}after"), "before\\nafter");
        assert_eq!(cef_escape("before\u{2029}after"), "before\\nafter");
        assert_eq!(cef_escape_ext("val\u{2028}ue"), "val\\nue");
        assert_eq!(cef_escape_ext("val\u{2029}ue"), "val\\nue");
    }

    #[test]
    fn test_cef_header_does_not_escape_equals() {
        // Header escaping should NOT escape '=' (only needed in extensions)
        assert_eq!(cef_escape("a=b"), "a=b");
    }

    #[test]
    fn test_cef_entry_with_equals_in_id() {
        // Entry ID with '=' should be escaped in extensions
        let entry = make_entry("tool", "func", Verdict::Allow);
        let mut entry_with_eq = entry;
        entry_with_eq.id = "entry=id=test".to_string();
        let cef = to_cef(&entry_with_eq);
        assert!(
            cef.contains("cs1=entry\\=id\\=test"),
            "Equals signs in extension values must be escaped: {}",
            cef
        );
    }
}
