// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified confused-deputy delegation guards.
//!
//! This module extracts the pure predicates from `deputy.rs` so the runtime
//! delegation chain and validation boundaries can be mirrored in Verus.

/// Return the next delegation depth using the runtime saturating increment.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn next_delegation_depth(current_depth: u8) -> u8 {
    current_depth.saturating_add(1)
}

/// Return true when a delegation depth stays within the configured limit.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_depth_within_limit(new_depth: u8, max_depth: u8) -> bool {
    new_depth <= max_depth
}

/// Return true when a chained delegation comes from the currently delegated
/// principal for the session.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn redelegation_chain_principal_valid(
    parent_has_delegate: bool,
    normalized_from_matches_parent_delegate: bool,
) -> bool {
    !parent_has_delegate || normalized_from_matches_parent_delegate
}

/// Return true when a requested child tool stays within the parent's granted
/// tool set, unless the parent has unrestricted delegation scope.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn redelegation_tool_allowed(
    parent_has_unrestricted_tools: bool,
    parent_allows_requested_tool: bool,
) -> bool {
    parent_has_unrestricted_tools || parent_allows_requested_tool
}

/// Return true when the claimed principal matches the stored delegate.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_principal_matches(normalized_claimed_matches_delegate: bool) -> bool {
    normalized_claimed_matches_delegate
}

/// Return true when the requested tool is allowed under the current delegation
/// context.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_tool_allowed(
    allowed_tools_empty: bool,
    requested_tool_found: bool,
) -> bool {
    allowed_tools_empty || requested_tool_found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_delegation_depth_saturates() {
        assert_eq!(next_delegation_depth(0), 1);
        assert_eq!(next_delegation_depth(u8::MAX), u8::MAX);
    }

    #[test]
    fn test_delegation_depth_within_limit_is_strict() {
        assert!(delegation_depth_within_limit(1, 1));
        assert!(!delegation_depth_within_limit(2, 1));
    }

    #[test]
    fn test_redelegation_chain_principal_valid_requires_parent_delegate_match() {
        assert!(redelegation_chain_principal_valid(false, false));
        assert!(redelegation_chain_principal_valid(true, true));
        assert!(!redelegation_chain_principal_valid(true, false));
    }

    #[test]
    fn test_redelegation_tool_allowed_respects_parent_scope() {
        assert!(redelegation_tool_allowed(true, false));
        assert!(redelegation_tool_allowed(false, true));
        assert!(!redelegation_tool_allowed(false, false));
    }

    #[test]
    fn test_delegated_principal_and_tool_checks_are_identities() {
        assert!(delegated_principal_matches(true));
        assert!(!delegated_principal_matches(false));
        assert!(delegated_tool_allowed(true, false));
        assert!(delegated_tool_allowed(false, true));
        assert!(!delegated_tool_allowed(false, false));
    }
}
