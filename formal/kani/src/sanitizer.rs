// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! PII sanitizer bidirectional correctness verification.
//!
//! Extracts the core token-replacement logic from
//! `vellaveto-mcp-shield/src/sanitizer.rs` and verifies:
//!
//! # Verified Properties (K69-K70)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K69 | Token insertion + replacement round-trip (inversion correctness) |
//! | K70 | Token uniqueness from monotonic sequence counter |
//!
//! # Production Correspondence
//!
//! - `sanitize_and_record` ↔ `QuerySanitizer::sanitize()` (sanitizer.rs:48-89)
//! - `desanitize` ↔ `QuerySanitizer::desanitize()` (sanitizer.rs:92-107)

use std::collections::HashMap;

/// A PII match found in input text.
pub struct PiiMatch {
    pub start: usize,
    pub end: usize,
    pub category: u8, // 0=EMAIL, 1=SSN, 2=CC, 3=PHONE
}

/// Category label for the token.
fn category_label(cat: u8) -> &'static str {
    match cat % 4 {
        0 => "EMAIL",
        1 => "SSN",
        2 => "CC",
        _ => "PHONE",
    }
}

/// Generate a PII placeholder token from category and sequence number.
///
/// Mirrors the production format: `[PII_{CAT}_{SEQ:06}]`
pub fn make_token(category: u8, seq: u64) -> String {
    format!("[PII_{}_{:06}]", category_label(category), seq)
}

/// Forward pass: replace PII matches with tokens, recording mappings.
///
/// Extracted from `QuerySanitizer::sanitize()`.
/// Precondition: matches are sorted by start position and non-overlapping.
pub fn sanitize_and_record(
    input: &str,
    matches: &[PiiMatch],
    start_seq: u64,
) -> (String, HashMap<String, String>, u64) {
    let mut result = String::with_capacity(input.len());
    let mut mappings: HashMap<String, String> = HashMap::new();
    let mut seq = start_seq;
    let mut last_end = 0;

    for m in matches {
        if m.start >= m.end || m.end > input.len() || m.start < last_end {
            continue; // Skip invalid/overlapping matches
        }
        result.push_str(&input[last_end..m.start]);
        let token = make_token(m.category, seq);
        let original = &input[m.start..m.end];
        mappings.insert(token.clone(), original.to_string());
        seq = seq.saturating_add(1);
        result.push_str(&token);
        last_end = m.end;
    }
    result.push_str(&input[last_end..]);
    (result, mappings, seq)
}

/// Backward pass: replace tokens with original values.
///
/// Extracted from `QuerySanitizer::desanitize()`.
pub fn desanitize(input: &str, mappings: &HashMap<String, String>) -> String {
    let mut result = input.to_string();
    for (token, original) in mappings {
        result = result.replace(token, original);
    }
    result
}

/// Check if a string contains any PII token pattern `[PII_`.
pub fn contains_token_prefix(s: &str) -> bool {
    s.contains("[PII_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_single_match() {
        let input = "hello user@example.com world";
        let matches = vec![PiiMatch {
            start: 6,
            end: 22,
            category: 0,
        }];
        let (sanitized, mappings, _) = sanitize_and_record(input, &matches, 0);
        assert!(!sanitized.contains("user@example.com"));
        assert!(sanitized.contains("[PII_EMAIL_000000]"));
        let restored = desanitize(&sanitized, &mappings);
        assert_eq!(restored, input);
    }

    #[test]
    fn test_roundtrip_multiple_matches() {
        let input = "email user@ex.com and ssn 123-45-6789 done";
        let matches = vec![
            PiiMatch {
                start: 6,
                end: 17,
                category: 0,
            },
            PiiMatch {
                start: 26,
                end: 37,
                category: 1,
            },
        ];
        let (sanitized, mappings, _) = sanitize_and_record(input, &matches, 0);
        let restored = desanitize(&sanitized, &mappings);
        assert_eq!(restored, input);
    }

    #[test]
    fn test_no_matches_identity() {
        let input = "no pii here";
        let (sanitized, mappings, _) = sanitize_and_record(input, &[], 0);
        assert_eq!(sanitized, input);
        let restored = desanitize(&sanitized, &mappings);
        assert_eq!(restored, input);
    }

    #[test]
    fn test_token_uniqueness() {
        let t1 = make_token(0, 0);
        let t2 = make_token(0, 1);
        let t3 = make_token(1, 0);
        assert_ne!(t1, t2, "Same category, different seq must differ");
        assert_ne!(t1, t3, "Different category, same seq must differ");
    }

    #[test]
    fn test_monotonic_sequence() {
        let input = "a@b.c and d@e.f";
        let matches = vec![
            PiiMatch {
                start: 0,
                end: 5,
                category: 0,
            },
            PiiMatch {
                start: 10,
                end: 15,
                category: 0,
            },
        ];
        let (_, _, final_seq) = sanitize_and_record(input, &matches, 42);
        assert_eq!(final_seq, 44, "Sequence should advance by match count");
    }

    #[test]
    fn test_non_pii_text_without_token_pattern() {
        // If the non-PII text doesn't contain "[PII_", desanitize is correct
        let input = "hello world";
        assert!(!contains_token_prefix(input));
    }
}
