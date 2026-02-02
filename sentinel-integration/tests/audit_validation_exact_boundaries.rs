//! Tests that probe exact validation boundaries in AuditLogger::validate_action.
//! Source: sentinel-audit/src/lib.rs validate_action method.
//!
//! Limits:
//! - No \n, \r in tool or function names
//! - No \0 in tool or function names
//! - JSON nesting depth <= 20
//! - Serialized parameter size <= 1,000,000 bytes

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

fn action_with_params(params: serde_json::Value) -> Action {
    Action {
        tool: "boundary_test".to_string(),
        function: "probe".to_string(),
        parameters: params,
    }
}

// ═══════════════════════════════
// NESTING DEPTH: EXACTLY 20 (ACCEPTED)
// ════════════════════════════════

fn nested_json(depth: usize) -> serde_json::Value {
    let mut val = json!("leaf");
    for _ in 0..depth {
        val = json!({"n": val});
    }
    val
}

/// Depth 20 is exactly the limit — should succeed.
#[test]
fn nesting_depth_20_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let params = nested_json(20);
        let action = action_with_params(params);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Depth 20 should be accepted: {:?}", result.err());
    });
}

/// Depth 21 exceeds the limit — should be rejected.
#[test]
fn nesting_depth_21_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let params = nested_json(21);
        let action = action_with_params(params);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Depth 21 should be rejected");
    });
}

// ═══════════════════════════════
// TOOL NAME: CLEAN NAMES ACCEPTED
// ════════════════════════════════

/// Tool with tab character is allowed (only \n, \r, \0 are rejected).
#[test]
fn tool_with_tab_is_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "tool\twith\ttabs".to_string(),
            function: "func".to_string(),
            parameters: json!({}),
        };
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Tab in tool name should be accepted");
    });
}

/// Tool with unicode is allowed.
#[test]
fn tool_with_unicode_is_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "工具_🔧".to_string(),
            function: "函数".to_string(),
            parameters: json!({}),
        };
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Unicode in tool/function names should be accepted");
    });
}

// ════════════════════════════════
// TOOL/FUNCTION NAME: REJECTED CHARACTERS
// ═══════════════════════════════

/// \n in tool → rejected
#[test]
fn tool_with_newline_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "bad\ntool".to_string(),
            function: "func".to_string(),
            parameters: json!({}),
        };
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err());
    });
}

/// \r in function → rejected
#[test]
fn function_with_cr_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "tool".to_string(),
            function: "bad\rfunc".to_string(),
            parameters: json!({}),
        };
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err());
    });
}

/// \0 in tool → rejected
#[test]
fn tool_with_null_byte_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "bad\0tool".to_string(),
            function: "func".to_string(),
            parameters: json!({}),
        };
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err());
    });
}

/// \0 in function → rejected
#[test]
fn function_with_null_byte_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "tool".to_string(),
            function: "bad\0func".to_string(),
            parameters: json!({}),
        };
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err());
    });
}

// ═══════════════════════════════
// EMPTY TOOL AND FUNCTION NAMES
// ════════════════════════════════

/// Empty tool and function names are valid (no newlines, no null bytes).
#[test]
fn empty_tool_and_function_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: String::new(),
            function: String::new(),
            parameters: json!({}),
        };
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Empty strings pass all validation checks");
    });
}

// ═══════════════════════════════
// VERY LONG TOOL NAMES (UNDER SIZE LIMIT)
// ════════════════════════════════

/// Very long tool name with no forbidden characters is accepted.
/// (Parameters size is checked separately — tool name length is not limited.)
#[test]
fn very_long_tool_name_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action {
            tool: "a".repeat(10_000),
            function: "b".repeat(10_000),
            parameters: json!({}),
        };
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Long tool/function names should be accepted");
    });
}