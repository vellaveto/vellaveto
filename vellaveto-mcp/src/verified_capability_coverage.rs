// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability grant-coverage gate.
//!
//! This module extracts the fail-closed path/domain restriction gate from
//! `capability_token.rs::grant_covers_action()` so it can be mirrored in Verus
//! without pulling path normalization or glob matching into the proof boundary.

/// Return true when a restricted grant is satisfied by the action's extracted
/// target paths/domains.
///
/// If a grant restricts paths or domains, the corresponding action target set
/// must be present and every supplied target must already have been checked as
/// covered by the caller's normalization and pattern-matching pipeline.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn grant_restrictions_cover_action(
    grant_has_allowed_paths: bool,
    action_has_target_paths: bool,
    all_target_paths_covered: bool,
    grant_has_allowed_domains: bool,
    action_has_target_domains: bool,
    all_target_domains_covered: bool,
) -> bool {
    (!grant_has_allowed_paths || (action_has_target_paths && all_target_paths_covered))
        && (!grant_has_allowed_domains || (action_has_target_domains && all_target_domains_covered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_restrictions_cover_action_rejects_missing_paths() {
        assert!(!grant_restrictions_cover_action(
            true, false, false, false, false, false
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_rejects_uncovered_paths() {
        assert!(!grant_restrictions_cover_action(
            true, true, false, false, false, false
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_rejects_missing_domains() {
        assert!(!grant_restrictions_cover_action(
            false, false, false, true, false, false
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_rejects_uncovered_domains() {
        assert!(!grant_restrictions_cover_action(
            false, false, false, true, true, false
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_accepts_satisfied_restrictions() {
        assert!(grant_restrictions_cover_action(
            true, true, true, true, true, true
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_ignores_absent_restrictions() {
        assert!(grant_restrictions_cover_action(
            false, false, false, false, false, false
        ));
        assert!(grant_restrictions_cover_action(
            false, false, false, true, true, true
        ));
        assert!(grant_restrictions_cover_action(
            true, true, true, false, false, false
        ));
    }
}
