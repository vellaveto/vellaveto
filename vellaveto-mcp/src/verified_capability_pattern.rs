// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability pattern attenuation guard.
//!
//! This module extracts the conservative child-glob rejection rule from
//! `capability_token.rs::grant_is_subset()`. It does not attempt to prove full
//! glob-language containment; it only formalizes the fail-closed guard that
//! rejects non-identical child patterns containing `*` or `?`.

/// Return true when the pattern contains glob metacharacters used by capability
/// delegation (`*` or `?`).
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn has_glob_metacharacters(pattern: &str) -> bool {
    pattern.as_bytes().iter().any(|b| *b == b'*' || *b == b'?')
}

/// Return true when the child pattern is allowed to continue through the
/// delegation subset check.
///
/// This guard encodes the conservative fix for non-identical child glob
/// patterns:
/// - wildcard parent: always allowed to continue
/// - exact case-insensitive equality: always allowed to continue
/// - otherwise, child patterns containing `*` or `?` are rejected
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn pattern_subset_guard(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
) -> bool {
    parent_is_wildcard || parent_equals_child_ignore_ascii_case || !child_has_metacharacters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_glob_metacharacters() {
        assert!(has_glob_metacharacters("fi*"));
        assert!(has_glob_metacharacters("fi?"));
        assert!(!has_glob_metacharacters("file_read"));
    }

    #[test]
    fn test_pattern_subset_guard_rejects_non_identical_child_glob() {
        assert!(!pattern_subset_guard(false, false, true));
    }

    #[test]
    fn test_pattern_subset_guard_allows_wildcard_parent() {
        assert!(pattern_subset_guard(true, false, true));
    }

    #[test]
    fn test_pattern_subset_guard_allows_identical_pattern() {
        assert!(pattern_subset_guard(false, true, true));
    }

    #[test]
    fn test_pattern_subset_guard_allows_literal_child_fallthrough() {
        assert!(pattern_subset_guard(false, false, false));
    }
}
