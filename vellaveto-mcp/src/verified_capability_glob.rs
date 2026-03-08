// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability parent-glob matcher for literal child patterns.
//!
//! This module extracts the literal-child branch from
//! `capability_token.rs::grant_is_subset()` so the parent-glob containment
//! decision can be mirrored in Verus without changing the broader runtime
//! matcher used for action coverage.

const ASCII_CASE_OFFSET: u8 = b'a' - b'A';

#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn ascii_fold_byte(byte: u8) -> u8 {
    if byte >= b'A' && byte <= b'Z' {
        byte + ASCII_CASE_OFFSET
    } else {
        byte
    }
}

#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn byte_eq_ignore_ascii_case(left: u8, right: u8) -> bool {
    ascii_fold_byte(left) == ascii_fold_byte(right)
}

fn literal_child_matches_parent_glob_from(parent_pattern: &[u8], child_literal: &[u8]) -> bool {
    match parent_pattern.split_first() {
        None => child_literal.is_empty(),
        Some((&b'*', tail)) => {
            literal_child_matches_parent_glob_from(tail, child_literal)
                || child_literal.split_first().is_some_and(|(_, child_tail)| {
                    literal_child_matches_parent_glob_from(parent_pattern, child_tail)
                })
        }
        Some((&b'?', tail)) => child_literal.split_first().is_some_and(|(_, child_tail)| {
            literal_child_matches_parent_glob_from(tail, child_tail)
        }),
        Some((&pattern_head, tail)) => {
            child_literal
                .split_first()
                .is_some_and(|(&child_head, child_tail)| {
                    byte_eq_ignore_ascii_case(pattern_head, child_head)
                        && literal_child_matches_parent_glob_from(tail, child_tail)
                })
        }
    }
}

/// Return true when the parent glob pattern matches the literal child value
/// under the case-insensitive `*`/`?` rules used by capability delegation.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn literal_child_matches_parent_glob(parent_pattern: &str, child_literal: &str) -> bool {
    literal_child_matches_parent_glob_from(parent_pattern.as_bytes(), child_literal.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_fold_byte_lowers_ascii_uppercase() {
        assert_eq!(ascii_fold_byte(b'F'), b'f');
        assert_eq!(ascii_fold_byte(b'f'), b'f');
        assert_eq!(ascii_fold_byte(b'_'), b'_');
    }

    #[test]
    fn test_byte_eq_ignore_ascii_case_is_case_insensitive() {
        assert!(byte_eq_ignore_ascii_case(b'F', b'f'));
        assert!(byte_eq_ignore_ascii_case(b'o', b'O'));
        assert!(!byte_eq_ignore_ascii_case(b'f', b'x'));
    }

    #[test]
    fn test_literal_child_matches_parent_glob_accepts_case_insensitive_literal() {
        assert!(literal_child_matches_parent_glob("FILE_READ", "file_read"));
    }

    #[test]
    fn test_literal_child_matches_parent_glob_accepts_question_mark() {
        assert!(literal_child_matches_parent_glob("fi?", "fix"));
        assert!(!literal_child_matches_parent_glob("fi?", "fi"));
    }

    #[test]
    fn test_literal_child_matches_parent_glob_accepts_star_backtracking() {
        assert!(literal_child_matches_parent_glob("a*b*c", "axbyc"));
        assert!(!literal_child_matches_parent_glob("a*b*c", "axbyd"));
    }

    #[test]
    fn test_literal_child_matches_parent_glob_accepts_empty_star_match() {
        assert!(literal_child_matches_parent_glob("file_*", "file_"));
    }
}
