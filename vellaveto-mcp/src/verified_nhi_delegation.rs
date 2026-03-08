// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified NHI delegation terminal-state and chain guards.
//!
//! This module extracts the fail-closed predicates around delegation
//! participants, active/unexpired chain links, and depth bounding from
//! `nhi.rs` so they can be mirrored in Verus.

/// Return true when an identity is in a delegation-blocking terminal state.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn identity_is_terminal(status_is_revoked: bool, status_is_expired: bool) -> bool {
    status_is_revoked || status_is_expired
}

/// Return true when an identity is allowed to participate in delegation.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_participant_allowed(
    status_is_revoked: bool,
    status_is_expired: bool,
) -> bool {
    !identity_is_terminal(status_is_revoked, status_is_expired)
}

/// Return true when a delegation link is still effective for chain traversal.
///
/// The expiry parse boundary is fail-closed: an unparseable timestamp is not an
/// effective link.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_link_effective_for_chain(
    to_agent_matches_current: bool,
    link_active: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
) -> bool {
    to_agent_matches_current && link_active && expiry_parsed && now_before_expiry
}

/// Return true when the current chain depth has exceeded the configured bound.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_chain_depth_exceeded(chain_len: usize, max_depth: usize) -> bool {
    chain_len > max_depth
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_is_terminal_matches_revoked_or_expired() {
        assert!(identity_is_terminal(true, false));
        assert!(identity_is_terminal(false, true));
        assert!(!identity_is_terminal(false, false));
    }

    #[test]
    fn test_delegation_participant_allowed_rejects_terminal_states() {
        assert!(!delegation_participant_allowed(true, false));
        assert!(!delegation_participant_allowed(false, true));
        assert!(delegation_participant_allowed(false, false));
    }

    #[test]
    fn test_delegation_link_effective_for_chain_requires_all_guards() {
        assert!(delegation_link_effective_for_chain(true, true, true, true));
        assert!(!delegation_link_effective_for_chain(
            false, true, true, true
        ));
        assert!(!delegation_link_effective_for_chain(
            true, false, true, true
        ));
        assert!(!delegation_link_effective_for_chain(
            true, true, false, false
        ));
    }

    #[test]
    fn test_delegation_chain_depth_exceeded_is_strict() {
        assert!(!delegation_chain_depth_exceeded(3, 3));
        assert!(delegation_chain_depth_exceeded(4, 3));
    }
}
