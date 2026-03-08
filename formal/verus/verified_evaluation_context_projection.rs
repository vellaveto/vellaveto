// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified relay projection into engine evaluation context.
//!
//! This file proves the extracted predicates in
//! `vellaveto-mcp/src/verified_evaluation_context_projection.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_evaluation_context_projection.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum EvaluationContextAgentSource {
    None,
    Configured,
    DeputyValidatedClaim,
}

pub struct EvaluationContextProjection {
    pub agent_source: EvaluationContextAgentSource,
    pub projected_call_chain_len: usize,
}

pub open spec fn spec_projected_agent_source(
    configured_present: bool,
    claimed_present: bool,
    has_active_delegation: bool,
) -> EvaluationContextAgentSource {
    if configured_present {
        EvaluationContextAgentSource::Configured
    } else if has_active_delegation && claimed_present {
        EvaluationContextAgentSource::DeputyValidatedClaim
    } else {
        EvaluationContextAgentSource::None
    }
}

pub open spec fn spec_projected_call_chain_len(
    has_active_delegation: bool,
    delegation_depth: u8,
) -> nat {
    if has_active_delegation {
        delegation_depth as nat
    } else {
        0
    }
}

pub fn project_evaluation_context(
    configured_present: bool,
    claimed_present: bool,
    has_active_delegation: bool,
    delegation_depth: u8,
) -> (result: EvaluationContextProjection)
    ensures
        result.agent_source
            == spec_projected_agent_source(
                configured_present,
                claimed_present,
                has_active_delegation,
            ),
        result.projected_call_chain_len as nat
            == spec_projected_call_chain_len(has_active_delegation, delegation_depth),
        configured_present ==> result.agent_source == EvaluationContextAgentSource::Configured,
        !configured_present && has_active_delegation && claimed_present
            ==> result.agent_source == EvaluationContextAgentSource::DeputyValidatedClaim,
        !configured_present && (!has_active_delegation || !claimed_present)
            ==> result.agent_source == EvaluationContextAgentSource::None,
        !has_active_delegation ==> result.projected_call_chain_len == 0,
        has_active_delegation
            ==> result.projected_call_chain_len == delegation_depth as usize,
{
    let agent_source = if configured_present {
        EvaluationContextAgentSource::Configured
    } else if has_active_delegation && claimed_present {
        EvaluationContextAgentSource::DeputyValidatedClaim
    } else {
        EvaluationContextAgentSource::None
    };

    let projected_call_chain_len = if has_active_delegation {
        delegation_depth as usize
    } else {
        0
    };

    EvaluationContextProjection {
        agent_source,
        projected_call_chain_len,
    }
}

pub proof fn lemma_configured_identity_dominates_claim_and_depth(
    claimed_present: bool,
    has_active_delegation: bool,
    delegation_depth: u8,
)
    ensures
        spec_projected_agent_source(true, claimed_present, has_active_delegation)
            == EvaluationContextAgentSource::Configured,
        spec_projected_call_chain_len(has_active_delegation, delegation_depth)
            <= delegation_depth as nat,
{
}

pub proof fn lemma_validated_claim_only_promotes_with_active_delegation()
    ensures
        spec_projected_agent_source(false, true, true)
            == EvaluationContextAgentSource::DeputyValidatedClaim,
        spec_projected_agent_source(false, true, false)
            == EvaluationContextAgentSource::None,
        spec_projected_agent_source(false, false, true)
            == EvaluationContextAgentSource::None,
{
}

pub proof fn lemma_inactive_delegation_projects_empty_chain(delegation_depth: u8)
    ensures spec_projected_call_chain_len(false, delegation_depth) == 0,
{
}

pub proof fn lemma_active_delegation_preserves_depth(delegation_depth: u8)
    ensures spec_projected_call_chain_len(true, delegation_depth) == delegation_depth as nat,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::evaluation_context_projection_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
