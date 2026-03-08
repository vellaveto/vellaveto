// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified combined deputy/capability context guards.
//!
//! This module extracts the pure conjunction used when a policy requires both
//! deputy validation and a capability token in the same engine evaluation.

use crate::verified_capability_context;
use crate::verified_context_delegation;

/// Return true when a delegated request has a bound principal and capability
/// token holder for a policy that requires both checks.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_capability_principal_and_holder_valid(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    capability_token_present: bool,
    normalized_holder_equals_agent: bool,
) -> bool {
    let principal_present = verified_context_delegation::identified_principal_present(
        agent_identity_present,
        agent_id_present,
    );

    verified_context_delegation::principal_requirement_satisfied(
        require_principal,
        principal_present,
    ) && capability_token_present
        && verified_capability_context::capability_holder_binding_valid(
            agent_id_present,
            normalized_holder_equals_agent,
        )
}

/// Return true when both delegated call depth and capability-token depth satisfy
/// the policy's fail-closed bounds.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_capability_depths_valid(
    delegation_depth: usize,
    max_delegation_depth: u8,
    capability_token_present: bool,
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> bool {
    verified_context_delegation::delegation_depth_within_limit(
        delegation_depth,
        max_delegation_depth,
    ) && capability_token_present
        && verified_capability_context::capability_remaining_depth_sufficient(
            remaining_depth,
            min_remaining_depth,
        )
}

/// Return true when the token issuer satisfies the configured allowlist in the
/// combined delegated-capability path.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_capability_issuer_valid(
    required_issuers_empty: bool,
    issuer_allowed: bool,
) -> bool {
    verified_capability_context::capability_issuer_allowed(required_issuers_empty, issuer_allowed)
}

/// Return true when the evaluation context satisfies the combined fail-closed
/// deputy/capability boundary.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_capability_context_valid(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    capability_token_present: bool,
    normalized_holder_equals_agent: bool,
    required_issuers_empty: bool,
    issuer_allowed: bool,
    delegation_depth: usize,
    max_delegation_depth: u8,
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> bool {
    delegated_capability_principal_and_holder_valid(
        require_principal,
        agent_identity_present,
        agent_id_present,
        capability_token_present,
        normalized_holder_equals_agent,
    ) && delegated_capability_issuer_valid(required_issuers_empty, issuer_allowed)
        && delegated_capability_depths_valid(
            delegation_depth,
            max_delegation_depth,
            capability_token_present,
            remaining_depth,
            min_remaining_depth,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegated_capability_principal_and_holder_valid_requires_token_and_binding() {
        assert!(delegated_capability_principal_and_holder_valid(
            true, true, true, true, true
        ));
        assert!(!delegated_capability_principal_and_holder_valid(
            true, true, true, false, true
        ));
        assert!(!delegated_capability_principal_and_holder_valid(
            true, true, false, true, false
        ));
    }

    #[test]
    fn test_delegated_capability_depths_valid_requires_both_bounds() {
        assert!(delegated_capability_depths_valid(1, 2, true, 3, 1));
        assert!(!delegated_capability_depths_valid(3, 2, true, 3, 1));
        assert!(!delegated_capability_depths_valid(1, 2, true, 0, 1));
        assert!(!delegated_capability_depths_valid(1, 2, false, 3, 1));
    }

    #[test]
    fn test_delegated_capability_issuer_valid_respects_allowlist() {
        assert!(delegated_capability_issuer_valid(true, false));
        assert!(delegated_capability_issuer_valid(false, true));
        assert!(!delegated_capability_issuer_valid(false, false));
    }

    #[test]
    fn test_delegated_capability_context_valid_conjoins_principal_and_depth() {
        assert!(delegated_capability_context_valid(
            true, true, true, true, true, true, true, 1, 2, 3, 1
        ));
        assert!(!delegated_capability_context_valid(
            true, true, true, true, true, true, true, 3, 2, 3, 1
        ));
        assert!(!delegated_capability_context_valid(
            true, true, true, true, false, true, true, 1, 2, 3, 1
        ));
        assert!(!delegated_capability_context_valid(
            true, true, true, true, true, false, false, 1, 2, 3, 1
        ));
    }
}
