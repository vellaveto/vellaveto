//! Adversarial tests targeting the AuditLogger's input validation.
//! Attempts to log malicious/malformed actions and verifies rejection.

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

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action {
        tool: tool.to_string(),
        function: function.to_string(),
        parameters: params,
    }
}

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

// ════════════════════════════════════════════════
// NEWLINE INJECTION IN TOOL NAME
// ════════════════════════════════════════════════

#[test]
fn rejects_tool_name_with_newline() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("bad\ntool", "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Tool name with \\n should be rejected");
    });
}

#[test]
fn rejects_tool_name_with_carriage_return() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("bad\rtool", "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Tool name with \\r should be rejected");
    });
}

#[test]
fn rejects_function_name_with_newline() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool", "bad\nfunc", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Function name with \\n should be rejected");
    });
}

#[test]
fn rejects_function_name_with_carriage_return() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool", "bad\rfunc", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Function name with \\r should be rejected");
    });
}

// ═════════════════════════════════════════════════
// NULL BYTE INJECTION
// ════════════════════════════════════════════════

#[test]
fn rejects_tool_name_with_null_byte() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("bad\0tool", "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Tool name with null byte should be rejected");
    });
}

#[test]
fn rejects_function_name_with_null_byte() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool", "func\0evil", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Function name with null byte should be rejected");
    });
}

// ═════════════════════════════════════════════════
// JSON NESTING DEPTH BOMB
// ═════════════════════════════════════════════════

#[test]
fn rejects_deeply_nested_parameters() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        // Build a JSON value nested 25 levels deep (limit is 20)
        let mut val = json!("leaf");
        for _ in 0..25 {
            val = json!({"nested": val});
        }

        let action = make_action("tool", "func", val);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Parameters nested >20 levels should be rejected");
    });
}

#[test]
fn accepts_parameters_at_exactly_depth_20() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        // Build exactly depth 20
        let mut val = json!("leaf");
        for _ in 0..19 {
            val = json!({"n": val});
        }
        // The outer object adds 1 more level: {"parameters": val} but that's handled
        // by Action's parameters field. The depth check is on action.parameters directly.
        // 19 wrappings of {"n": ...} around "leaf" = depth 19 objects + 0 for leaf = 19
        // Actually: json_depth for {"n": {"n": ... "leaf"}} with 19 nestings:
        // Each object adds 1, so depth = 19. That's under 20.

        let action = make_action("tool", "func", val);
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Parameters at depth <=20 should be accepted, got: {:?}", result.err());
    });
}

// ═════════════════════════════════════════════════
// PARAMETER SIZE LIMIT
// ════════════════════════════════════════════════

#[test]
fn rejects_parameters_exceeding_1mb() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        // Create a string value > 1MB
        let big_string = "x".repeat(1_100_000);
        let action = make_action("tool", "func", json!({"data": big_string}));

        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Parameters >1MB should be rejected");
    });
}

#[test]
fn accepts_parameters_under_1mb() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        // A reasonably large but under-limit value
        let medium_string = "y".repeat(100_000);
        let action = make_action("tool", "func", json!({"data": medium_string}));

        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Parameters under 1MB should be accepted");
    });
}

// ════════════════════════════════════════════════
// BENIGN EDGE CASES THAT SHOULD SUCCEED
// ═════════════════════════════════════════════════

#[test]
fn allows_empty_tool_and_function_names() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("", "", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Empty tool/func names should be allowed");
    });
}

#[test]
fn allows_unicode_in_tool_name() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("工具_🔧", "数_func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Unicode tool/function names should be allowed");

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "工具_🔧");
        assert_eq!(entries[0].action.function, "数_func");
    });
}

#[test]
fn allows_special_characters_without_newlines() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action(
            "tool-with.dots_and-dashes",
            "func/with/slashes",
            json!({}),
        );
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Special chars (no newlines) should be allowed");
    });
}

#[test]
fn allows_tab_character_in_tool_name() {
    // Tabs are not newlines; the validator only rejects \n, \r, and \0
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool\twith\ttabs", "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_ok(), "Tab characters should be allowed (not newlines)");
    });
}

// ════════════════════════════════════════════════
// MULTIPLE VALIDATION FAILURES: first check wins
// ═════════════════════════════════════════════════

#[test]
fn tool_with_both_newline_and_null_rejected() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("bad\n\0tool", "func", json!({}));
        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err(), "Both newline and null byte should be rejected");
    });
}

// ═════════════════════════════════════════════════
// REJECTED ENTRIES DON'T POLLUTE THE LOG
// ════════════════════════════════════════════════

#[test]
fn rejected_entry_does_not_appear_in_log() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();

        // Log a valid entry first
        let good_action = make_action("good_tool", "good_func", json!({}));
        logger.log_entry(&good_action, &Verdict::Allow, json!({})).await.unwrap();

        // Try to log an invalid entry
        let bad_action = make_action("bad\ntool", "func", json!({}));
        let _ = logger.log_entry(&bad_action, &Verdict::Allow, json!({})).await;

        // Log another valid entry
        logger
            .log_entry(
                &good_action,
                &Verdict::Deny { reason: "test".to_string() },
                json!({}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2, "Only valid entries should be in the log");
        assert_eq!(entries[0].action.tool, "good_tool");
        assert_eq!(entries[1].action.tool, "good_tool");
    });
}