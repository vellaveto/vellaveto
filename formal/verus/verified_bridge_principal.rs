// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified stdio bridge principal-binding guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-mcp/src/verified_bridge_principal.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_bridge_principal.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum RequestPrincipalSource {
    None,
    Configured,
    Claimed,
}

pub open spec fn spec_configured_claim_consistent(
    configured_present: bool,
    claimed_present: bool,
    normalized_equal: bool,
) -> bool {
    !configured_present || !claimed_present || normalized_equal
}

pub fn configured_claim_consistent(
    configured_present: bool,
    claimed_present: bool,
    normalized_equal: bool,
) -> (result: bool)
    ensures
        result
            == spec_configured_claim_consistent(
                configured_present,
                claimed_present,
                normalized_equal,
            ),
        configured_present && claimed_present && result ==> normalized_equal,
{
    !configured_present || !claimed_present || normalized_equal
}

pub open spec fn spec_deputy_principal_source(
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

pub fn deputy_principal_source(
    configured_present: bool,
    claimed_present: bool,
) -> (result: RequestPrincipalSource)
    ensures
        result == spec_deputy_principal_source(configured_present, claimed_present),
        configured_present ==> result == RequestPrincipalSource::Configured,
        !configured_present && claimed_present ==> result == RequestPrincipalSource::Claimed,
        !configured_present && !claimed_present ==> result == RequestPrincipalSource::None,
{
    if configured_present {
        RequestPrincipalSource::Configured
    } else if claimed_present {
        RequestPrincipalSource::Claimed
    } else {
        RequestPrincipalSource::None
    }
}

pub open spec fn spec_evaluation_principal_source(
    configured_present: bool,
) -> RequestPrincipalSource {
    if configured_present {
        RequestPrincipalSource::Configured
    } else {
        RequestPrincipalSource::None
    }
}

pub fn evaluation_principal_source(
    configured_present: bool,
) -> (result: RequestPrincipalSource)
    ensures
        result == spec_evaluation_principal_source(configured_present),
        configured_present ==> result == RequestPrincipalSource::Configured,
        !configured_present ==> result == RequestPrincipalSource::None,
{
    if configured_present {
        RequestPrincipalSource::Configured
    } else {
        RequestPrincipalSource::None
    }
}

pub proof fn lemma_mismatch_rejected_when_both_sources_present()
    ensures
        !spec_configured_claim_consistent(true, true, false),
        spec_configured_claim_consistent(true, true, true),
{
}

pub proof fn lemma_missing_side_has_no_consistency_obligation(normalized_equal: bool)
    ensures
        spec_configured_claim_consistent(false, true, normalized_equal),
        spec_configured_claim_consistent(true, false, normalized_equal),
        spec_configured_claim_consistent(false, false, normalized_equal),
{
}

pub proof fn lemma_deputy_prefers_configured_identity()
    ensures
        spec_deputy_principal_source(true, true) == RequestPrincipalSource::Configured,
        spec_deputy_principal_source(true, false) == RequestPrincipalSource::Configured,
        spec_deputy_principal_source(false, true) == RequestPrincipalSource::Claimed,
        spec_deputy_principal_source(false, false) == RequestPrincipalSource::None,
{
}

pub proof fn lemma_engine_only_trusts_configured_identity()
    ensures
        spec_evaluation_principal_source(true) == RequestPrincipalSource::Configured,
        spec_evaluation_principal_source(false) == RequestPrincipalSource::None,
{
}

pub proof fn lemma_configured_source_aligns_deputy_and_engine(claimed_present: bool)
    ensures
        spec_deputy_principal_source(true, claimed_present) == RequestPrincipalSource::Configured,
        spec_evaluation_principal_source(true) == RequestPrincipalSource::Configured,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::bridge_principal_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
