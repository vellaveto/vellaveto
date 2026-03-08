// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified engine-side delegation and call-chain context guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-engine/src/verified_context_delegation.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_context_delegation.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_identified_principal_present(
    agent_identity_present: bool,
    agent_id_present: bool,
) -> bool {
    agent_identity_present || agent_id_present
}

pub fn identified_principal_present(
    agent_identity_present: bool,
    agent_id_present: bool,
) -> (result: bool)
    ensures
        result
            == spec_identified_principal_present(
                agent_identity_present,
                agent_id_present,
            ),
        !agent_identity_present && !agent_id_present ==> !result,
{
    agent_identity_present || agent_id_present
}

pub open spec fn spec_principal_requirement_satisfied(
    require_principal: bool,
    principal_present: bool,
) -> bool {
    !require_principal || principal_present
}

pub fn principal_requirement_satisfied(
    require_principal: bool,
    principal_present: bool,
) -> (result: bool)
    ensures
        result
            == spec_principal_requirement_satisfied(
                require_principal,
                principal_present,
            ),
        require_principal && !principal_present ==> !result,
{
    !require_principal || principal_present
}

pub open spec fn spec_chain_depth_within_limit(chain_depth: nat, max_depth: nat) -> bool {
    chain_depth <= max_depth
}

pub fn chain_depth_within_limit(
    chain_depth: usize,
    max_depth: usize,
) -> (result: bool)
    ensures
        result == spec_chain_depth_within_limit(chain_depth as nat, max_depth as nat),
        result ==> chain_depth as nat <= max_depth as nat,
        !result ==> chain_depth as nat > max_depth as nat,
{
    chain_depth <= max_depth
}

pub open spec fn spec_delegation_depth_within_limit(
    delegation_depth: nat,
    max_delegation_depth: nat,
) -> bool {
    delegation_depth <= max_delegation_depth
}

pub fn delegation_depth_within_limit(
    delegation_depth: usize,
    max_delegation_depth: u8,
) -> (result: bool)
    ensures
        result
            == spec_delegation_depth_within_limit(
                delegation_depth as nat,
                max_delegation_depth as nat,
            ),
        result ==> delegation_depth as nat <= max_delegation_depth as nat,
        !result ==> delegation_depth as nat > max_delegation_depth as nat,
{
    delegation_depth <= max_delegation_depth as usize
}

pub proof fn lemma_missing_identity_sources_mean_no_principal()
    ensures !spec_identified_principal_present(false, false),
{
}

pub proof fn lemma_principal_requirement_fails_closed_without_principal()
    ensures
        !spec_principal_requirement_satisfied(true, false),
        spec_principal_requirement_satisfied(true, true),
        spec_principal_requirement_satisfied(false, false),
{
}

pub proof fn lemma_chain_depth_limit_is_inclusive(max_depth: nat)
    ensures
        spec_chain_depth_within_limit(max_depth, max_depth),
        spec_chain_depth_within_limit(0, max_depth),
{
}

pub proof fn lemma_delegation_depth_limit_is_inclusive(max_delegation_depth: nat)
    requires max_delegation_depth <= 255,
    ensures
        spec_delegation_depth_within_limit(
            max_delegation_depth,
            max_delegation_depth,
        ),
        spec_delegation_depth_within_limit(0, max_delegation_depth),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::context_delegation_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
