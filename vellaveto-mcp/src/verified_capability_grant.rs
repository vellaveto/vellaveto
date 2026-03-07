// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability grant attenuation kernel.
//!
//! This module extracts the pure restriction-shape and `max_invocations`
//! attenuation checks from `capability_token.rs::grant_is_subset()` so they can
//! be proved in Verus without pulling pattern language containment into the
//! proof boundary.

/// Return true when a child grant preserves the parent's mandatory restriction
/// shapes and does not widen the invocation bound.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn grant_restrictions_attenuated(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: u64,
    child_max_invocations: u64,
) -> bool {
    (!parent_has_allowed_paths || child_has_allowed_paths)
        && (!parent_has_allowed_domains || child_has_allowed_domains)
        && (parent_max_invocations == 0
            || (child_max_invocations > 0 && child_max_invocations <= parent_max_invocations))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_restrictions_cannot_be_dropped() {
        assert!(!grant_restrictions_attenuated(
            true, false, false, false, 0, 0
        ));
    }

    #[test]
    fn test_domain_restrictions_cannot_be_dropped() {
        assert!(!grant_restrictions_attenuated(
            false, false, true, false, 0, 0
        ));
    }

    #[test]
    fn test_limited_parent_rejects_unlimited_child() {
        assert!(!grant_restrictions_attenuated(
            false, false, false, false, 10, 0
        ));
    }

    #[test]
    fn test_limited_parent_rejects_larger_child_limit() {
        assert!(!grant_restrictions_attenuated(
            false, false, false, false, 10, 11
        ));
    }

    #[test]
    fn test_limited_parent_accepts_smaller_child_limit() {
        assert!(grant_restrictions_attenuated(true, true, true, true, 10, 5));
    }

    #[test]
    fn test_unlimited_parent_leaves_only_shape_checks() {
        assert!(grant_restrictions_attenuated(
            false, false, false, false, 0, 0
        ));
        assert!(grant_restrictions_attenuated(
            true, true, false, false, 0, 99
        ));
    }
}
