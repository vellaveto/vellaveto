// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Shared normalization utilities for policy compilation and evaluation.
//!
//! SECURITY (FIND-R218-001): This module provides the canonical normalization
//! pipeline used by both compile-time (policy_compile) and eval-time
//! (context_check) paths. Both MUST use the same function to prevent
//! compile/eval normalization mismatches that bypass policy enforcement.

use unicode_normalization::UnicodeNormalization;
use vellaveto_types::unicode::normalize_homoglyphs;

/// Apply full normalization pipeline: NFKC → lowercase → homoglyph mapping.
///
/// SECURITY (FIND-R218-001, FIND-R220-001–003): NFKC normalization catches
/// NFKC-only confusables (circled letters Ⓐ-ⓩ, mathematical script 𝐀-𝐳,
/// parenthesized ⒜-⒵) that `normalize_homoglyphs` alone does not map.
///
/// This function MUST be used for all string comparisons between compiled
/// policy values and runtime values. Using `normalize_homoglyphs` without
/// NFKC, or using `to_ascii_lowercase` instead of `to_lowercase`, creates
/// a normalization mismatch exploitable by attackers.
pub(crate) fn normalize_full(s: &str) -> String {
    let nfkc: String = s.nfkc().collect();
    normalize_homoglyphs(&nfkc.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_full_ascii_lowercase() {
        assert_eq!(normalize_full("Hello"), "hello");
        assert_eq!(normalize_full("HELLO"), "hello");
        assert_eq!(normalize_full("HeLLo WoRLD"), "hello world");
    }

    #[test]
    fn test_normalize_full_empty_string() {
        assert_eq!(normalize_full(""), "");
    }

    #[test]
    fn test_normalize_full_already_normalized() {
        assert_eq!(normalize_full("read_file"), "read_file");
        assert_eq!(normalize_full("tool_name"), "tool_name");
    }

    #[test]
    fn test_normalize_full_nfkc_circled_letters() {
        // Circled A (U+24B6) should NFKC-normalize to 'A' then lowercase to 'a'
        let circled_a = "\u{24B6}";
        let result = normalize_full(circled_a);
        assert_eq!(result, "a");
    }

    #[test]
    fn test_normalize_full_nfkc_fullwidth_chars() {
        // Fullwidth 'Ａ' (U+FF21) should NFKC-normalize to 'A' then lowercase to 'a'
        let fullwidth_a = "\u{FF21}";
        let result = normalize_full(fullwidth_a);
        assert_eq!(result, "a");
    }

    #[test]
    fn test_normalize_full_nfkc_parenthesized_letters() {
        // Parenthesized small a (U+249C) should NFKC-normalize
        let paren_a = "\u{249C}";
        let result = normalize_full(paren_a);
        // NFKC maps U+249C to "(a)"
        assert!(result.contains('a'), "Expected 'a' in result: {}", result);
    }

    #[test]
    fn test_normalize_full_homoglyph_cyrillic() {
        // Cyrillic 'а' (U+0430) should be mapped to Latin 'a' by homoglyph normalization
        let cyrillic_a = "\u{0430}";
        let result = normalize_full(cyrillic_a);
        assert_eq!(result, "a");
    }

    #[test]
    fn test_normalize_full_mixed_case_and_homoglyphs() {
        // Test pipeline: NFKC -> lowercase -> homoglyph
        // Fullwidth 'Ｂ' + regular 'a' + Cyrillic 'ѕ' + regular 'h'
        let mixed = "\u{FF22}a\u{0455}h";
        let result = normalize_full(mixed);
        assert_eq!(result, "bash");
    }

    #[test]
    fn test_normalize_full_unicode_lowercase() {
        // Capital Sharp S (U+1E9E) NFKC-normalizes to U+00DF (lowercase sharp s),
        // then to_lowercase() produces "ss" — but NFKC normalization of U+1E9E
        // results in U+00DF which to_lowercase() maps to U+00DF (not "ss" in all
        // Rust versions). Verify it at least lowercases.
        let upper_sharp_s = "\u{1E9E}"; // capital sharp S
        let result = normalize_full(upper_sharp_s);
        // The result should be either "ss" or "\u{00DF}" depending on Unicode version
        assert!(
            result == "ss" || result == "\u{00DF}",
            "Expected 'ss' or '\u{00DF}', got '{}'",
            result
        );
    }

    #[test]
    fn test_normalize_full_idempotent() {
        // Normalizing an already-normalized string should produce the same result
        let input = "read_file";
        let first = normalize_full(input);
        let second = normalize_full(&first);
        assert_eq!(first, second);
    }

    #[test]
    fn test_normalize_full_preserves_underscores_digits() {
        assert_eq!(normalize_full("tool_v2_beta"), "tool_v2_beta");
        assert_eq!(normalize_full("read_123"), "read_123");
    }

    #[test]
    fn test_normalize_full_mathematical_bold() {
        // Mathematical Bold Capital A (U+1D400) should NFKC-normalize to 'A'
        let math_bold_a = "\u{1D400}";
        let result = normalize_full(math_bold_a);
        assert_eq!(result, "a");
    }
}
