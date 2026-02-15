//! Tests that probe the exact boundaries of audit logger validation:
//! - Parameter size limit: 1,000,000 bytes
//! - Nesting depth limit: 20 levels
//! - Tool/function name character restrictions
//!
//! These tests try to find off-by-one errors.

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

fn make_action_with_params(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

// ═══════════════════════════════════════
// NESTING DEPTH BOUNDARY: 20 LEVELS
// ═══════════════════════════════════════

/// Build JSON nested to exactly `depth` levels.
fn nested_json(depth: usize) -> serde_json::Value {
    let mut val = json!("leaf");
    for _ in 0..depth {
        val = json!({"nested": val});
    }
    val
}

/// Depth 19 should be accepted (under limit of 20).
#[test]
fn nesting_depth_19_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let params = nested_json(19);
        let action = make_action_with_params("tool", "func", params);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Depth 19 should be accepted");
    });
}

/// Depth 20 should be accepted (at limit of 20).
#[test]
fn nesting_depth_20_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let params = nested_json(20);
        let action = make_action_with_params("tool", "func", params);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_ok(),
            "Depth 20 should be accepted (limit is >20, not >=20)"
        );
    });
}

/// Depth 21 should be rejected (exceeds limit of 20).
#[test]
fn nesting_depth_21_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let params = nested_json(21);
        let action = make_action_with_params("tool", "func", params);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Depth 21 should be rejected");
    });
}

/// Depth 0 (flat value) should be accepted.
#[test]
fn nesting_depth_0_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action_with_params("tool", "func", json!("flat string"));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Flat value should be accepted");
    });
}

// ═══════════════════════════════════════
// PARAMETER SIZE BOUNDARY: 1,000,000 BYTES
// ═══════════════════════════════════════

/// Build a JSON value that serializes to approximately `target_size` bytes.
fn sized_json(target_size: usize) -> serde_json::Value {
    // {"data":"AAAA..."} — overhead is ~10 bytes
    let overhead = 10;
    if target_size <= overhead {
        return json!({});
    }
    let fill = "A".repeat(target_size - overhead);
    json!({"data": fill})
}

/// Just under 1MB should be accepted.
#[test]
fn parameters_just_under_1mb_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        // 999,990 bytes — safely under 1,000,000
        let params = sized_json(999_990);
        let actual_size = params.to_string().len();
        assert!(
            actual_size < 1_000_000,
            "Test setup: size should be under 1MB, got {}",
            actual_size
        );

        let action = make_action_with_params("tool", "func", params);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Parameters under 1MB should be accepted");
    });
}

/// Exactly at or over 1MB should be rejected.
#[test]
fn parameters_over_1mb_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        // 1,000,010 bytes — safely over 1,000,000
        let params = sized_json(1_000_010);
        let actual_size = params.to_string().len();
        assert!(
            actual_size > 1_000_000,
            "Test setup: size should be over 1MB, got {}",
            actual_size
        );

        let action = make_action_with_params("tool", "func", params);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Parameters over 1MB should be rejected");
    });
}

// ═══════════════════════════════════════
// NAME CHARACTER RESTRICTIONS
// ══════════════════════════════════════

/// Tool name with \r (carriage return) should be rejected.
#[test]
fn tool_name_with_carriage_return_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action_with_params("bad\rtool", "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_err(),
            "Carriage return in tool name should be rejected"
        );
    });
}

/// Function name with null byte should be rejected.
#[test]
fn function_name_with_null_byte_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action_with_params("tool", "func\0tion", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_err(),
            "Null byte in function name should be rejected"
        );
    });
}

/// Very long tool name (no forbidden chars) should be accepted.
#[test]
fn very_long_tool_name_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let long_name = "a".repeat(10_000);
        let action = make_action_with_params(&long_name, "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_ok(),
            "Long tool name without forbidden chars should be accepted"
        );
    });
}

/// Tool name with tabs is now rejected (FIND-074: all control chars rejected).
/// Spaces are still accepted.
#[test]
fn tool_name_with_tabs_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action_with_params("  \t  ", "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_err(),
            "Tabs in tool name should be rejected (control chars)"
        );
    });
}

/// Tool name with only spaces (no control chars) should still be accepted.
#[test]
fn tool_name_with_spaces_only_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action_with_params("  tool  name  ", "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Spaces in tool name should be accepted");
    });
}

/// Empty tool name should be accepted (no validation against empty strings).
#[test]
fn empty_tool_name_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action_with_params("", "", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_ok(),
            "Empty tool/function names should be accepted (no empty check)"
        );
    });
}

/// Unicode tool/function names should be accepted.
#[test]
fn unicode_names_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action_with_params("具", "函数", json!({"日本語": "スト"}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Unicode names should be accepted");

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "具");
        assert_eq!(entries[0].action.function, "函数");
    });
}

// ═══════════════════════════════════════
// COMBINED BOUNDARY: DEEP NESTING + LARGE SIZE
// ═══════════════════════════════════════

/// Parameters that are deeply nested (but under 20) AND large (but under 1MB).
/// Both checks must pass.
#[test]
fn deep_and_large_but_within_limits_accepted() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        // 18 levels of nesting with a large leaf value
        let mut val = json!({"data": "X".repeat(50_000)});
        for _ in 0..17 {
            val = json!({"nested": val});
        }
        let size = val.to_string().len();
        assert!(
            size < 1_000_000,
            "Test setup: combined size {} should be under 1MB",
            size
        );

        let action = make_action_with_params("tool", "func", val);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(
            result.is_ok(),
            "Deep but within limits + large but within limits should pass both checks"
        );
    });
}
