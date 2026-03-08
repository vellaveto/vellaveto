// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified engine-side delegation and call-chain context guards.
//!
//! This module extracts the pure predicates from `context_check.rs` that
//! consume `EvaluationContext.call_chain.len()` and the presence of a principal.

/// Return true when either an attested agent identity or a legacy `agent_id`
/// is present in the evaluation context.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn identified_principal_present(
    agent_identity_present: bool,
    agent_id_present: bool,
) -> bool {
    agent_identity_present || agent_id_present
}

/// Return true when the policy's principal requirement is satisfied.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn principal_requirement_satisfied(
    require_principal: bool,
    principal_present: bool,
) -> bool {
    !require_principal || principal_present
}

/// Return true when the current call-chain depth is within the policy limit.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn chain_depth_within_limit(chain_depth: usize, max_depth: usize) -> bool {
    chain_depth <= max_depth
}

/// Return true when the delegated call depth is within the policy limit.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_depth_within_limit(
    delegation_depth: usize,
    max_delegation_depth: u8,
) -> bool {
    delegation_depth <= max_delegation_depth as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identified_principal_present_accepts_either_identity_source() {
        assert!(!identified_principal_present(false, false));
        assert!(identified_principal_present(true, false));
        assert!(identified_principal_present(false, true));
        assert!(identified_principal_present(true, true));
    }

    #[test]
    fn test_principal_requirement_satisfied_fails_closed_when_required() {
        assert!(!principal_requirement_satisfied(true, false));
        assert!(principal_requirement_satisfied(true, true));
        assert!(principal_requirement_satisfied(false, false));
    }

    #[test]
    fn test_chain_depth_within_limit_is_inclusive() {
        assert!(chain_depth_within_limit(0, 0));
        assert!(chain_depth_within_limit(2, 2));
        assert!(!chain_depth_within_limit(3, 2));
    }

    #[test]
    fn test_delegation_depth_within_limit_is_inclusive() {
        assert!(delegation_depth_within_limit(0, 0));
        assert!(delegation_depth_within_limit(2, 2));
        assert!(!delegation_depth_within_limit(3, 2));
    }
}
