// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability grant-selection kernel.
//!
//! This module extracts the first-match selection rule from
//! `capability_token.rs::check_grant_coverage()` so it can be mirrored in
//! Verus without pulling the full grant matcher into the proof boundary.

/// Return the first matching grant index seen so far.
///
/// Once a matching index is selected, later matching grants cannot replace it.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn next_covering_grant_index(
    selected_index: Option<usize>,
    current_index: usize,
    current_grant_covers: bool,
) -> Option<usize> {
    match selected_index {
        Some(existing_index) => Some(existing_index),
        None => {
            if current_grant_covers {
                Some(current_index)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_covering_grant_index_selects_first_match() {
        assert_eq!(next_covering_grant_index(None, 3, true), Some(3));
    }

    #[test]
    fn test_next_covering_grant_index_skips_non_match() {
        assert_eq!(next_covering_grant_index(None, 3, false), None);
    }

    #[test]
    fn test_next_covering_grant_index_preserves_existing_selection() {
        assert_eq!(next_covering_grant_index(Some(1), 4, false), Some(1));
        assert_eq!(next_covering_grant_index(Some(1), 4, true), Some(1));
    }
}
