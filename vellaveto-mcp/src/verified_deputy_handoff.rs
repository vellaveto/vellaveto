// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified relay handoff after deputy validation.
//!
//! This module extracts the pure decision logic for when the stdio bridge may
//! promote a claimed `_meta.agent_id` into engine evaluation after the deputy
//! subsystem has validated that claim against an active server-side delegation
//! context.

/// Source used for evaluation-principal selection after deputy validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvaluationPrincipalSource {
    None,
    Configured,
    DeputyValidatedClaim,
}

/// Return true when a claimed principal has been validated against an active
/// delegation context and may therefore be treated as trusted by higher layers.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn deputy_validated_claim_trusted(
    has_active_delegation: bool,
    claimed_present: bool,
) -> bool {
    has_active_delegation && claimed_present
}

/// Choose the principal source trusted for engine evaluation after deputy
/// validation has completed.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn evaluation_principal_source_after_deputy(
    configured_present: bool,
    deputy_validated_claim: bool,
) -> EvaluationPrincipalSource {
    if configured_present {
        EvaluationPrincipalSource::Configured
    } else if deputy_validated_claim {
        EvaluationPrincipalSource::DeputyValidatedClaim
    } else {
        EvaluationPrincipalSource::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deputy_validated_claim_trusted_requires_active_delegation() {
        assert!(!deputy_validated_claim_trusted(false, false));
        assert!(!deputy_validated_claim_trusted(false, true));
        assert!(!deputy_validated_claim_trusted(true, false));
        assert!(deputy_validated_claim_trusted(true, true));
    }

    #[test]
    fn test_evaluation_principal_source_after_deputy_prefers_configured_identity() {
        assert_eq!(
            evaluation_principal_source_after_deputy(true, true),
            EvaluationPrincipalSource::Configured
        );
        assert_eq!(
            evaluation_principal_source_after_deputy(true, false),
            EvaluationPrincipalSource::Configured
        );
    }

    #[test]
    fn test_evaluation_principal_source_after_deputy_promotes_validated_claim() {
        assert_eq!(
            evaluation_principal_source_after_deputy(false, true),
            EvaluationPrincipalSource::DeputyValidatedClaim
        );
        assert_eq!(
            evaluation_principal_source_after_deputy(false, false),
            EvaluationPrincipalSource::None
        );
    }
}
