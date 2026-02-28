// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests that probe exact validation boundaries in AuditLogger::validate_action.
//! Source: vellaveto-audit/src/lib.rs validate_action method.
//!
//! Limits:
//! - No \n, \r in tool or function names
//! - No \0 in tool or function names
//! - JSON nesting depth <= 20
//! - Serialized parameter size <= 1,000,000 bytes

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

fn action_with_params(params: serde_json::Value) -> Action {
    Action::new("boundary_test".to_string(), "probe".to_string(), params)
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
        assert!(
            result.is_ok(),
            "Depth 20 should be accepted: {:?}",
            result.err()
        );
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
fn tool_with_tab_is_rejected() {
    // SECURITY (FIND-074): All control characters are now rejected
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action::new(
            "tool\twith\ttabs".to_string(),
            "func".to_string(),
            json!({}),
        );
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Tab in tool name should be rejected");
    });
}

/// Tool with unicode is allowed.
#[test]
fn tool_with_unicode_is_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = Action::new("工具_🔧".to_string(), "函数".to_string(), json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_ok(),
            "Unicode in tool/function names should be accepted"
        );
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
        let action = Action::new("bad\ntool".to_string(), "func".to_string(), json!({}));
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
        let action = Action::new("tool".to_string(), "bad\rfunc".to_string(), json!({}));
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
        let action = Action::new("bad\0tool".to_string(), "func".to_string(), json!({}));
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
        let action = Action::new("tool".to_string(), "bad\0func".to_string(), json!({}));
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
        let action = Action::new(String::new(), String::new(), json!({}));
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
        let action = Action::new("a".repeat(10_000), "b".repeat(10_000), json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_ok(),
            "Long tool/function names should be accepted"
        );
    });
}
