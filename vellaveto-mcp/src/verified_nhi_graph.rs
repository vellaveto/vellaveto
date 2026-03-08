// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified NHI delegation graph guards.
//!
//! This module extracts the pure graph predicates used by `nhi.rs` when
//! deciding whether an existing delegation link is live for forward traversal
//! and whether inserting a new delegation edge preserves acyclicity.

/// Return true when a delegation link can be followed from the current agent to
/// its successor during forward graph traversal.
///
/// The expiry parse boundary is fail-closed: an unparseable timestamp is not a
/// live edge.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_link_effective_for_successor(
    from_agent_matches_current: bool,
    link_active: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
) -> bool {
    from_agent_matches_current && link_active && expiry_parsed && now_before_expiry
}

/// Return true when inserting a new delegation edge preserves acyclicity.
///
/// Callers compute `path_from_delegatee_to_delegator_exists` over the currently
/// live delegation graph. If such a path exists, adding `delegator ->
/// delegatee` would close a cycle and must be rejected.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_edge_preserves_acyclicity(
    path_from_delegatee_to_delegator_exists: bool,
) -> bool {
    !path_from_delegatee_to_delegator_exists
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_link_effective_for_successor_requires_all_guards() {
        assert!(delegation_link_effective_for_successor(
            true, true, true, true
        ));
        assert!(!delegation_link_effective_for_successor(
            false, true, true, true
        ));
        assert!(!delegation_link_effective_for_successor(
            true, false, true, true
        ));
        assert!(!delegation_link_effective_for_successor(
            true, true, false, false
        ));
    }

    #[test]
    fn test_delegation_edge_preserves_acyclicity_rejects_live_back_path() {
        assert!(delegation_edge_preserves_acyclicity(false));
        assert!(!delegation_edge_preserves_acyclicity(true));
    }
}
