// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified relay projection into engine evaluation context.
//!
//! This module extracts the post-deputy projection that decides which
//! principal may populate `EvaluationContext.agent_id` and what synthetic
//! delegation depth should populate `EvaluationContext.call_chain`.

use crate::verified_delegation_projection;
use crate::verified_deputy_handoff;

/// Source used to populate `EvaluationContext.agent_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvaluationContextAgentSource {
    None,
    Configured,
    DeputyValidatedClaim,
}

/// Verified projection of relay state into engine-visible context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EvaluationContextProjection {
    pub(crate) agent_source: EvaluationContextAgentSource,
    pub(crate) projected_call_chain_len: usize,
}

/// Project the trusted engine-visible context shape after deputy validation.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn project_evaluation_context(
    configured_present: bool,
    claimed_present: bool,
    has_active_delegation: bool,
    delegation_depth: u8,
) -> EvaluationContextProjection {
    let deputy_validated_claim = verified_deputy_handoff::deputy_validated_claim_trusted(
        has_active_delegation,
        claimed_present,
    );

    let agent_source = match verified_deputy_handoff::evaluation_principal_source_after_deputy(
        configured_present,
        deputy_validated_claim,
    ) {
        verified_deputy_handoff::EvaluationPrincipalSource::Configured => {
            EvaluationContextAgentSource::Configured
        }
        verified_deputy_handoff::EvaluationPrincipalSource::DeputyValidatedClaim => {
            EvaluationContextAgentSource::DeputyValidatedClaim
        }
        verified_deputy_handoff::EvaluationPrincipalSource::None => {
            EvaluationContextAgentSource::None
        }
    };

    let projected_call_chain_len = verified_delegation_projection::projected_call_chain_len(
        has_active_delegation,
        delegation_depth,
    );

    EvaluationContextProjection {
        agent_source,
        projected_call_chain_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_project_evaluation_context_prefers_configured_identity() {
        let projection = project_evaluation_context(true, true, true, 3);

        assert_eq!(
            projection.agent_source,
            EvaluationContextAgentSource::Configured
        );
        assert_eq!(projection.projected_call_chain_len, 3);
    }

    #[test]
    fn test_project_evaluation_context_promotes_validated_claim() {
        let projection = project_evaluation_context(false, true, true, 2);

        assert_eq!(
            projection.agent_source,
            EvaluationContextAgentSource::DeputyValidatedClaim
        );
        assert_eq!(projection.projected_call_chain_len, 2);
    }

    #[test]
    fn test_project_evaluation_context_rejects_unvalidated_claim() {
        let projection = project_evaluation_context(false, true, false, 4);

        assert_eq!(projection.agent_source, EvaluationContextAgentSource::None);
        assert_eq!(projection.projected_call_chain_len, 0);
    }

    #[test]
    fn test_project_evaluation_context_without_any_principal_is_empty() {
        let projection = project_evaluation_context(false, false, false, 0);

        assert_eq!(projection.agent_source, EvaluationContextAgentSource::None);
        assert_eq!(projection.projected_call_chain_len, 0);
    }
}
