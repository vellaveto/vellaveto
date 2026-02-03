//! Property-based tests for sentinel-mcp injection scanning.
//!
//! Per Directive C-16.2: Tests critical injection scanner invariants:
//! - Determinism: same input → same detection result
//! - Unicode normalization: NFKC-equivalent strings → same scan result
//! - Sanitization idempotence: sanitize(sanitize(x)) == sanitize(x)

use proptest::prelude::*;
use sentinel_mcp::inspection::{inspect_for_injection, sanitize_for_injection_scan};

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
