//! Tests that probe audit logger validation for control characters
//! beyond basic \n. The source code rejects \n, \r, and \0.
//! These tests verify that ONLY those specific characters are rejected,
//! and that other control characters (tabs, form feeds) are accepted.

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

fn make_action(tool: &str, function: &str) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: json!({}),
    }
}

// ═══════════════════════════════════
// CARRIAGE RETURN ALONE (\r without \n)
// ═══════════════════════════════════

#[test]
fn rejects_tool_with_cr_only() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("bad\rtool", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Tool with \\r should be rejected");
    });
}

#[test]
fn rejects_function_with_cr_only() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool", "bad\rfunc");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Function with \\r should be rejected");
    });
}

#[test]
fn rejects_tool_with_crlf() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("bad\r\ntool", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Tool with \\r\\n should be rejected");
    });
}

// ═══════════════════════════════════
// NULL BYTES IN FUNCTION NAME
// ═══════════════════════════════════

#[test]
fn rejects_function_with_null_byte() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool", "func\0tion");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Function with null byte should be rejected");
    });
}

// ═══════════════════════════════════
// CHARACTERS THAT SHOULD BE ACCEPTED
// ═══════════════════════════════════

/// Tab characters are NOT rejected by the validator.
#[test]
fn accepts_tool_with_tab() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\twith\ttabs", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Tab characters should be accepted");
    });
}

/// Form feed is NOT rejected.
#[test]
fn accepts_tool_with_form_feed() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\x0cfunc", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Form feed should be accepted (not in reject list)");
    });
}

/// Backspace is NOT rejected.
#[test]
fn accepts_tool_with_backspace() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\x08here", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Backspace should be accepted (not in reject list)");
    });
}

/// Vertical tab is NOT rejected.
#[test]
fn accepts_tool_with_vertical_tab() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\x0bhere", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Vertical tab should be accepted");
    });
}

// ════════════════════════════════════
// MULTIPLE REJECTED CHARS IN ONE STRING
// ═══════════════════════════════════

/// First invalid char triggers rejection; test that order doesn't matter.
#[test]
fn rejects_tool_with_null_and_newline() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        // \n comes first in the string
        let action = make_action("a\nb\0c", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err());
    });
}

#[test]
fn rejects_tool_with_null_before_newline() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        // \0 comes first in the string
        let action = make_action("a\0b\nc", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err());
    });
}

// ═══════════════════════════════════
// VERY LONG TOOL NAME (NO FORBIDDEN CHARS)
// ═══════════════════════════════════

/// Long tool name with no control characters should pass validation.
/// The validator only checks for \n, \r, \0 — no length limit on names.
#[test]
fn accepts_very_long_tool_name() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let long_name = "a".repeat(100_000);
        let action = make_action(&long_name, "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Long tool name without control chars should be accepted");
    });
}