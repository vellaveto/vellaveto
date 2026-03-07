// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability literal matching kernel.
//!
//! This module extracts the literal-only fast paths from
//! `capability_token.rs::pattern_matches()` and
//! `capability_token.rs::grant_is_subset()` so they can be mirrored in Verus
//! without pulling full glob-language containment into the proof boundary.

/// Return true when a pattern with no glob metacharacters matches a value via
/// ASCII-case-insensitive equality.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn literal_pattern_matches(
    pattern_has_metacharacters: bool,
    pattern_equals_value_ignore_ascii_case: bool,
) -> bool {
    !pattern_has_metacharacters && pattern_equals_value_ignore_ascii_case
}

/// Return true when a literal child pattern is safely contained by the parent
/// pattern according to the runtime matcher result.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn literal_child_pattern_subset(
    child_has_metacharacters: bool,
    parent_matches_child_literal: bool,
) -> bool {
    !child_has_metacharacters && parent_matches_child_literal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_pattern_matches_accepts_equal_literal() {
        assert!(literal_pattern_matches(false, true));
    }

    #[test]
    fn test_literal_pattern_matches_rejects_literal_mismatch() {
        assert!(!literal_pattern_matches(false, false));
    }

    #[test]
    fn test_literal_pattern_matches_rejects_metacharacter_pattern() {
        assert!(!literal_pattern_matches(true, true));
    }

    #[test]
    fn test_literal_child_pattern_subset_accepts_matching_literal_child() {
        assert!(literal_child_pattern_subset(false, true));
    }

    #[test]
    fn test_literal_child_pattern_subset_rejects_mismatching_literal_child() {
        assert!(!literal_child_pattern_subset(false, false));
    }

    #[test]
    fn test_literal_child_pattern_subset_rejects_child_glob() {
        assert!(!literal_child_pattern_subset(true, true));
    }
}
