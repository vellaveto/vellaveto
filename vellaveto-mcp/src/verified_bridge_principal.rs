// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified stdio bridge principal-binding guards.
//!
//! This module extracts the pure decision logic that aligns the trusted
//! `VELLAVETO_AGENT_ID` session principal with untrusted per-message
//! `_meta.agent_id` claims in the stdio bridge.

/// Source used for request principal selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestPrincipalSource {
    None,
    Configured,
    Claimed,
}

/// Return true when the configured session principal and per-message claim are
/// compatible.
///
/// If either side is absent there is no consistency obligation. If both are
/// present they must match after the caller's normalization pipeline.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn configured_claim_consistent(
    configured_present: bool,
    claimed_present: bool,
    normalized_equal: bool,
) -> bool {
    !configured_present || !claimed_present || normalized_equal
}

/// Choose the principal source used for deputy validation.
///
/// The trusted configured principal wins when present; otherwise the deputy
/// subsystem may fall back to the claimed per-message principal.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn deputy_principal_source(
    configured_present: bool,
    claimed_present: bool,
) -> RequestPrincipalSource {
    if configured_present {
        RequestPrincipalSource::Configured
    } else if claimed_present {
        RequestPrincipalSource::Claimed
    } else {
        RequestPrincipalSource::None
    }
}

/// Choose the principal source trusted for engine evaluation.
///
/// Only the configured session principal is trusted enough to populate
/// `EvaluationContext.agent_id` in stdio mode.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn evaluation_principal_source(
    configured_present: bool,
) -> RequestPrincipalSource {
    if configured_present {
        RequestPrincipalSource::Configured
    } else {
        RequestPrincipalSource::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configured_claim_consistent_requires_match_when_both_present() {
        assert!(configured_claim_consistent(false, false, false));
        assert!(configured_claim_consistent(true, false, false));
        assert!(configured_claim_consistent(false, true, false));
        assert!(configured_claim_consistent(true, true, true));
        assert!(!configured_claim_consistent(true, true, false));
    }

    #[test]
    fn test_deputy_principal_source_prefers_configured_identity() {
        assert_eq!(
            deputy_principal_source(true, true),
            RequestPrincipalSource::Configured
        );
        assert_eq!(
            deputy_principal_source(true, false),
            RequestPrincipalSource::Configured
        );
        assert_eq!(
            deputy_principal_source(false, true),
            RequestPrincipalSource::Claimed
        );
        assert_eq!(
            deputy_principal_source(false, false),
            RequestPrincipalSource::None
        );
    }

    #[test]
    fn test_evaluation_principal_source_only_trusts_configured_identity() {
        assert_eq!(
            evaluation_principal_source(true),
            RequestPrincipalSource::Configured
        );
        assert_eq!(
            evaluation_principal_source(false),
            RequestPrincipalSource::None
        );
    }
}
