//! Property-based tests for vellaveto-mcp injection scanning.
//!
//! Per Directive C-16.2: Tests critical injection scanner invariants:
//! - Determinism: same input → same detection result
//! - Unicode normalization: NFKC-equivalent strings → same scan result
//! - Sanitization idempotence: sanitize(sanitize(x)) == sanitize(x)

use proptest::prelude::*;
use vellaveto_mcp::extractor::{classify_message, MessageType};
use vellaveto_mcp::inspection::{inspect_for_injection, sanitize_for_injection_scan};
use serde_json::{json, Value};

// ═══════════════════════════════════
// PROPERTY: inspect_for_injection is deterministic
// ═══════════════════════════════════

proptest! {
    #[test]
    fn injection_scan_is_deterministic(
        text in "\\PC{0,200}",
    ) {
        let result1 = inspect_for_injection(&text);
        let result2 = inspect_for_injection(&text);

        prop_assert_eq!(&result1, &result2,
            "inspect_for_injection must be deterministic.\n\
             input: {:?}\n\
             result1: {:?}\n\
             result2: {:?}", text, result1, result2);
    }
}

// ═══════════════════════════════════
// PROPERTY: sanitize_for_injection_scan is idempotent
// ═══════════════════════════════════

proptest! {
    #[test]
    fn sanitize_is_idempotent(
        text in "\\PC{0,200}",
    ) {
        let once = sanitize_for_injection_scan(&text);
        let twice = sanitize_for_injection_scan(&once);

        prop_assert_eq!(&once, &twice,
            "sanitize_for_injection_scan must be idempotent.\n\
             input: {:?}\n\
             once:  {:?}\n\
             twice: {:?}", text, once, twice);
    }
}

// ═══════════════════════════════════
// PROPERTY: Zero-width characters don't affect detection
// ═══════════════════════════════════

proptest! {
    #[test]
    fn zero_width_chars_dont_affect_detection(
        text in "[a-z ]{5,50}",
    ) {
        // Results on clean text
        let clean_result = inspect_for_injection(&text);

        // Insert zero-width spaces at random positions
        let mut with_zwsp = String::new();
        for ch in text.chars() {
            with_zwsp.push(ch);
            with_zwsp.push('\u{200B}'); // zero-width space
        }
        let zwsp_result = inspect_for_injection(&with_zwsp);

        prop_assert_eq!(&clean_result, &zwsp_result,
            "Zero-width characters must not affect detection.\n\
             clean input: {:?}\n\
             zwsp input:  {:?}\n\
             clean result: {:?}\n\
             zwsp result:  {:?}", text, with_zwsp, clean_result, zwsp_result);
    }
}

// ═══════════════════════════════════
// PROPERTY: Case insensitivity — detection is case-independent
// ═══════════════════════════════════

proptest! {
    #[test]
    fn detection_is_case_insensitive(
        text in "[a-z ]{5,50}",
    ) {
        let lower_result = inspect_for_injection(&text);
        let upper_result = inspect_for_injection(&text.to_uppercase());

        prop_assert_eq!(&lower_result, &upper_result,
            "Detection must be case-insensitive.\n\
             lower: {:?} → {:?}\n\
             upper: {:?} → {:?}",
            text, lower_result, text.to_uppercase(), upper_result);
    }
}

// ═══════════════════════════════════
// PROPERTY: Sanitization always produces valid UTF-8
// ═══════════════════════════════════

proptest! {
    #[test]
    fn sanitize_produces_valid_utf8(
        text in "\\PC{0,200}",
    ) {
        let sanitized = sanitize_for_injection_scan(&text);
        // If we got a String back, it's already valid UTF-8.
        // But let's verify it doesn't contain control characters we strip.
        for ch in sanitized.chars() {
            // Zero-width characters should be stripped
            prop_assert!(ch != '\u{200B}', "Zero-width space not stripped");
            prop_assert!(ch != '\u{200C}', "Zero-width non-joiner not stripped");
            prop_assert!(ch != '\u{200D}', "Zero-width joiner not stripped");
            prop_assert!(ch != '\u{FEFF}', "BOM not stripped");
            // Bidi overrides should be stripped
            prop_assert!(ch != '\u{202A}', "LRE not stripped");
            prop_assert!(ch != '\u{202B}', "RLE not stripped");
            prop_assert!(ch != '\u{202C}', "PDF not stripped");
            prop_assert!(ch != '\u{202D}', "LRO not stripped");
            prop_assert!(ch != '\u{202E}', "RLO not stripped");
        }
    }
}

// ═══════════════════════════════════
// PROPERTY: Known injection patterns always detected
// ═══════════════════════════════════

proptest! {
    #[test]
    fn known_pattern_always_detected(
        pattern_idx in 0..5usize,
        prefix in "[a-z ]{0,20}",
        suffix in "[a-z ]{0,20}",
    ) {
        let patterns = [
            "ignore all previous instructions",
            "disregard previous",
            "new system prompt",
            "pretend you are",
            "forget your instructions",
        ];
        let pattern = patterns[pattern_idx];
        let text = format!("{} {} {}", prefix, pattern, suffix);

        let result = inspect_for_injection(&text);
        prop_assert!(!result.is_empty(),
            "Known pattern {:?} must always be detected in text {:?}.\n\
             Result: {:?}", pattern, text, result);
    }
}

// ═══════════════════════════════════════════════════
// MCP CLASSIFICATION ROBUSTNESS PROPERTIES
// ═══════════════════════════════════════════════════

/// Build a tools/call message with the given method string.
fn make_tool_call_msg(method: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}}
    })
}

// PROPERTY: tools/call detected despite injected null/zero-width noise
proptest! {
    #[test]
    fn tools_call_detected_despite_noise(
        noise_variant in 0..5usize,
    ) {
        let noisy_method = match noise_variant {
            0 => "tools/call\0".to_string(),
            1 => "tools/call\u{200B}".to_string(),
            2 => "\u{FEFF}tools/call".to_string(),
            3 => "tools/call/".to_string(),
            4 => "Tools/Call".to_string(),
            _ => unreachable!(),
        };

        let msg = make_tool_call_msg(&noisy_method);
        let result = classify_message(&msg);
        prop_assert!(
            matches!(result, MessageType::ToolCall { .. }),
            "Method {:?} must classify as ToolCall. Got: {:?}", noisy_method, result
        );
    }
}

// PROPERTY: classify_message never panics on arbitrary JSON
proptest! {
    #[test]
    fn classification_never_panics(
        has_method in proptest::bool::ANY,
        has_id in proptest::bool::ANY,
        method_str in "[\\PC]{0,50}",
        id_val in 0..1000i64,
    ) {
        let mut msg = serde_json::Map::new();
        msg.insert("jsonrpc".to_string(), json!("2.0"));
        if has_id {
            msg.insert("id".to_string(), json!(id_val));
        }
        if has_method {
            msg.insert("method".to_string(), json!(method_str));
        }

        // Must not panic — any result is acceptable
        let _result = classify_message(&Value::Object(msg));
    }
}

// PROPERTY: classify_message is deterministic
proptest! {
    #[test]
    fn classification_is_deterministic(
        method in "[a-z/]{0,30}",
    ) {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {"name": "test", "arguments": {}}
        });

        let r1 = classify_message(&msg);
        let r2 = classify_message(&msg);
        prop_assert_eq!(r1, r2,
            "classify_message must be deterministic for method {:?}", method);
    }
}

// PROPERTY: normalize_method is idempotent (tested via classify behavior)
// Since normalize_method is private, we test the observable effect:
// classifying a message twice gives the same result, even with whitespace/null prefixes.
proptest! {
    #[test]
    fn normalize_method_idempotent_via_classify(
        base_method in prop_oneof![
            Just("tools/call".to_string()),
            Just("resources/read".to_string()),
            Just("sampling/createmessage".to_string()),
            Just("notifications/progress".to_string()),
        ],
        noise_idx in 0..3usize,
    ) {
        // Apply noise to method string
        let noisy = match noise_idx {
            0 => format!("{}  ", base_method),       // trailing whitespace
            1 => format!("{}/", base_method),         // trailing slash
            2 => format!("\u{200B}{}", base_method),  // leading zero-width space
            _ => unreachable!(),
        };

        // Both should classify identically to the clean version
        let clean_result = classify_message(&json!({
            "jsonrpc": "2.0", "id": 1, "method": &base_method,
            "params": {"name": "test", "arguments": {}}
        }));
        let noisy_result = classify_message(&json!({
            "jsonrpc": "2.0", "id": 1, "method": &noisy,
            "params": {"name": "test", "arguments": {}}
        }));

        // Compare discriminants (variant type) since IDs may differ
        let clean_variant = std::mem::discriminant(&clean_result);
        let noisy_variant = std::mem::discriminant(&noisy_result);
        prop_assert_eq!(clean_variant, noisy_variant,
            "Noisy method {:?} must classify same as {:?}.\n\
             Clean: {:?}\n\
             Noisy: {:?}", noisy, base_method, clean_result, noisy_result);
    }
}
