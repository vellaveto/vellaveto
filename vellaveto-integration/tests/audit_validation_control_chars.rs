//! Tests that probe audit logger validation for control characters.
//!
//! SECURITY (FIND-074): The validator now rejects ALL control characters
//! (U+0000–U+001F, U+007F, U+0080–U+009F) in tool/function names, not
//! just \n, \r, and \0. This prevents log injection via tabs, backspaces,
//! escape sequences, and other control chars.

use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};
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
    Action::new(tool.to_string(), function.to_string(), json!({}))
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
        assert!(
            result.is_err(),
            "Function with null byte should be rejected"
        );
    });
}

// ═══════════════════════════════════
// ALL CONTROL CHARACTERS REJECTED (FIND-074)
// ═══════════════════════════════════

/// Tab characters are now rejected as control characters.
#[test]
fn rejects_tool_with_tab() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\twith\ttabs", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Tab characters should be rejected");
    });
}

/// Form feed is now rejected as a control character.
#[test]
fn rejects_tool_with_form_feed() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\x0cfunc", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Form feed should be rejected");
    });
}

/// Backspace is now rejected as a control character.
#[test]
fn rejects_tool_with_backspace() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\x08here", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Backspace should be rejected");
    });
}

/// Vertical tab is now rejected as a control character.
#[test]
fn rejects_tool_with_vertical_tab() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\x0bhere", "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Vertical tab should be rejected");
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
/// The validator checks for control chars — no length limit on names.
#[test]
fn accepts_very_long_tool_name() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let long_name = "a".repeat(100_000);
        let action = make_action(&long_name, "func");
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_ok(),
            "Long tool name without control chars should be accepted"
        );
    });
}
