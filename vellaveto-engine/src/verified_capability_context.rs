// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability-token context guards.
//!
//! This module extracts the pure predicates from the engine's
//! `require_capability_token` condition so the runtime authorization boundary
//! can be mirrored in Verus without pulling in the full policy engine.

/// Return true when the evaluation context includes an identified agent and the
/// normalized capability-token holder matches that agent.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_holder_binding_valid(
    agent_present: bool,
    normalized_holder_equals_agent: bool,
) -> bool {
    agent_present && normalized_holder_equals_agent
}

/// Return true when the token issuer is allowed by the configured issuer
/// allowlist.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_issuer_allowed(
    required_issuers_empty: bool,
    issuer_allowed: bool,
) -> bool {
    required_issuers_empty || issuer_allowed
}

/// Return true when the token retains enough delegation depth for the policy.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_remaining_depth_sufficient(
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> bool {
    remaining_depth >= min_remaining_depth
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_holder_binding_valid_fails_closed_without_agent() {
        assert!(!capability_holder_binding_valid(false, false));
        assert!(!capability_holder_binding_valid(false, true));
        assert!(!capability_holder_binding_valid(true, false));
        assert!(capability_holder_binding_valid(true, true));
    }

    #[test]
    fn test_capability_issuer_allowed_respects_allowlist() {
        assert!(capability_issuer_allowed(true, false));
        assert!(capability_issuer_allowed(false, true));
        assert!(!capability_issuer_allowed(false, false));
    }

    #[test]
    fn test_capability_remaining_depth_sufficient_is_inclusive() {
        assert!(capability_remaining_depth_sufficient(3, 3));
        assert!(capability_remaining_depth_sufficient(4, 3));
        assert!(!capability_remaining_depth_sufficient(2, 3));
    }
}
