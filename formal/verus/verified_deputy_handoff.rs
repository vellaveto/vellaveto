// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified relay handoff after deputy validation.
//!
//! This file proves the extracted predicates in
//! `vellaveto-mcp/src/verified_deputy_handoff.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_deputy_handoff.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum EvaluationPrincipalSource {
    None,
    Configured,
    DeputyValidatedClaim,
}

pub open spec fn spec_deputy_validated_claim_trusted(
    has_active_delegation: bool,
    claimed_present: bool,
) -> bool {
    has_active_delegation && claimed_present
}

pub fn deputy_validated_claim_trusted(
    has_active_delegation: bool,
    claimed_present: bool,
) -> (result: bool)
    ensures
        result == spec_deputy_validated_claim_trusted(has_active_delegation, claimed_present),
        result ==> has_active_delegation,
        result ==> claimed_present,
{
    has_active_delegation && claimed_present
}

pub open spec fn spec_evaluation_principal_source_after_deputy(
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

pub fn evaluation_principal_source_after_deputy(
    configured_present: bool,
    deputy_validated_claim: bool,
) -> (result: EvaluationPrincipalSource)
    ensures
        result
            == spec_evaluation_principal_source_after_deputy(
                configured_present,
                deputy_validated_claim,
            ),
        configured_present ==> result == EvaluationPrincipalSource::Configured,
        !configured_present && deputy_validated_claim
            ==> result == EvaluationPrincipalSource::DeputyValidatedClaim,
        !configured_present && !deputy_validated_claim
            ==> result == EvaluationPrincipalSource::None,
{
    if configured_present {
        EvaluationPrincipalSource::Configured
    } else if deputy_validated_claim {
        EvaluationPrincipalSource::DeputyValidatedClaim
    } else {
        EvaluationPrincipalSource::None
    }
}

pub proof fn lemma_deputy_validated_claim_requires_active_delegation()
    ensures
        !spec_deputy_validated_claim_trusted(false, false),
        !spec_deputy_validated_claim_trusted(false, true),
        !spec_deputy_validated_claim_trusted(true, false),
        spec_deputy_validated_claim_trusted(true, true),
{
}

pub proof fn lemma_configured_source_dominates_validated_claim()
    ensures
        spec_evaluation_principal_source_after_deputy(true, true)
            == EvaluationPrincipalSource::Configured,
        spec_evaluation_principal_source_after_deputy(true, false)
            == EvaluationPrincipalSource::Configured,
{
}

pub proof fn lemma_validated_claim_promotes_only_without_configured_source()
    ensures
        spec_evaluation_principal_source_after_deputy(false, true)
            == EvaluationPrincipalSource::DeputyValidatedClaim,
        spec_evaluation_principal_source_after_deputy(false, false)
            == EvaluationPrincipalSource::None,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::deputy_handoff_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
