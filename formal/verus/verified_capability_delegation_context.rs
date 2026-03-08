// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified combined deputy/capability context guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-engine/src/verified_capability_delegation_context.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_delegation_context.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_delegated_capability_principal_and_holder_valid(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    capability_token_present: bool,
    normalized_holder_equals_agent: bool,
) -> bool {
    let principal_present = agent_identity_present || agent_id_present;
    (!require_principal || principal_present)
        && capability_token_present
        && agent_id_present
        && normalized_holder_equals_agent
}

pub fn delegated_capability_principal_and_holder_valid(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    capability_token_present: bool,
    normalized_holder_equals_agent: bool,
) -> (result: bool)
    ensures
        result
            == spec_delegated_capability_principal_and_holder_valid(
                require_principal,
                agent_identity_present,
                agent_id_present,
                capability_token_present,
                normalized_holder_equals_agent,
            ),
        result ==> capability_token_present,
        result ==> agent_id_present,
        result ==> normalized_holder_equals_agent,
        result && require_principal ==> agent_identity_present || agent_id_present,
{
    let principal_present = agent_identity_present || agent_id_present;
    (!require_principal || principal_present)
        && capability_token_present
        && agent_id_present
        && normalized_holder_equals_agent
}

pub open spec fn spec_delegated_capability_depths_valid(
    delegation_depth: nat,
    max_delegation_depth: u8,
    capability_token_present: bool,
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> bool {
    delegation_depth <= max_delegation_depth as nat
        && capability_token_present
        && remaining_depth >= min_remaining_depth
}

pub fn delegated_capability_depths_valid(
    delegation_depth: usize,
    max_delegation_depth: u8,
    capability_token_present: bool,
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> (result: bool)
    ensures
        result
            == spec_delegated_capability_depths_valid(
                delegation_depth as nat,
                max_delegation_depth,
                capability_token_present,
                remaining_depth,
                min_remaining_depth,
            ),
        result ==> delegation_depth <= max_delegation_depth as usize,
        result ==> capability_token_present,
        result ==> remaining_depth >= min_remaining_depth,
{
    delegation_depth <= max_delegation_depth as usize
        && capability_token_present
        && remaining_depth >= min_remaining_depth
}

pub open spec fn spec_delegated_capability_issuer_valid(
    required_issuers_empty: bool,
    issuer_allowed: bool,
) -> bool {
    required_issuers_empty || issuer_allowed
}

pub fn delegated_capability_issuer_valid(
    required_issuers_empty: bool,
    issuer_allowed: bool,
) -> (result: bool)
    ensures
        result
            == spec_delegated_capability_issuer_valid(
                required_issuers_empty,
                issuer_allowed,
            ),
        result && !required_issuers_empty ==> issuer_allowed,
{
    required_issuers_empty || issuer_allowed
}

pub open spec fn spec_delegated_capability_context_valid(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    capability_token_present: bool,
    normalized_holder_equals_agent: bool,
    required_issuers_empty: bool,
    issuer_allowed: bool,
    delegation_depth: nat,
    max_delegation_depth: u8,
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> bool {
    spec_delegated_capability_principal_and_holder_valid(
        require_principal,
        agent_identity_present,
        agent_id_present,
        capability_token_present,
        normalized_holder_equals_agent,
    ) && spec_delegated_capability_issuer_valid(
        required_issuers_empty,
        issuer_allowed,
    ) && spec_delegated_capability_depths_valid(
        delegation_depth,
        max_delegation_depth,
        capability_token_present,
        remaining_depth,
        min_remaining_depth,
    )
}

pub fn delegated_capability_context_valid(
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
) -> (result: bool)
    ensures
        result
            == spec_delegated_capability_context_valid(
                require_principal,
                agent_identity_present,
                agent_id_present,
                capability_token_present,
                normalized_holder_equals_agent,
                required_issuers_empty,
                issuer_allowed,
                delegation_depth as nat,
                max_delegation_depth,
                remaining_depth,
                min_remaining_depth,
            ),
        result ==> capability_token_present,
        result ==> agent_id_present,
        result ==> normalized_holder_equals_agent,
        result && !required_issuers_empty ==> issuer_allowed,
        result ==> delegation_depth <= max_delegation_depth as usize,
        result ==> remaining_depth >= min_remaining_depth,
{
    delegated_capability_principal_and_holder_valid(
        require_principal,
        agent_identity_present,
        agent_id_present,
        capability_token_present,
        normalized_holder_equals_agent,
    ) && delegated_capability_issuer_valid(
        required_issuers_empty,
        issuer_allowed,
    ) && delegated_capability_depths_valid(
        delegation_depth,
        max_delegation_depth,
        capability_token_present,
        remaining_depth,
        min_remaining_depth,
    )
}

pub proof fn lemma_missing_capability_token_fails_closed(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    normalized_holder_equals_agent: bool,
    required_issuers_empty: bool,
    issuer_allowed: bool,
    delegation_depth: nat,
    max_delegation_depth: u8,
    remaining_depth: u8,
    min_remaining_depth: u8,
)
    ensures
        !spec_delegated_capability_context_valid(
            require_principal,
            agent_identity_present,
            agent_id_present,
            false,
            normalized_holder_equals_agent,
            required_issuers_empty,
            issuer_allowed,
            delegation_depth,
            max_delegation_depth,
            remaining_depth,
            min_remaining_depth,
        ),
{
}

pub proof fn lemma_principal_requirement_and_holder_binding_are_conjoined(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    capability_token_present: bool,
    normalized_holder_equals_agent: bool,
)
    ensures
        spec_delegated_capability_principal_and_holder_valid(
            require_principal,
            agent_identity_present,
            agent_id_present,
            capability_token_present,
            normalized_holder_equals_agent,
        ) ==> capability_token_present,
        spec_delegated_capability_principal_and_holder_valid(
            require_principal,
            agent_identity_present,
            agent_id_present,
            capability_token_present,
            normalized_holder_equals_agent,
        ) ==> agent_id_present,
{
}

pub proof fn lemma_issuer_allowlist_is_conjoined(
    required_issuers_empty: bool,
    issuer_allowed: bool,
)
    ensures
        spec_delegated_capability_issuer_valid(
            required_issuers_empty,
            issuer_allowed,
        ) ==> required_issuers_empty || issuer_allowed,
{
}

pub proof fn lemma_delegation_and_remaining_depth_bounds_are_conjoined(
    delegation_depth: nat,
    max_delegation_depth: u8,
    capability_token_present: bool,
    remaining_depth: u8,
    min_remaining_depth: u8,
)
    ensures
        spec_delegated_capability_depths_valid(
            delegation_depth,
            max_delegation_depth,
            capability_token_present,
            remaining_depth,
            min_remaining_depth,
        ) ==> delegation_depth <= max_delegation_depth as nat,
        spec_delegated_capability_depths_valid(
            delegation_depth,
            max_delegation_depth,
            capability_token_present,
            remaining_depth,
            min_remaining_depth,
        ) ==> remaining_depth >= min_remaining_depth,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_delegation_context_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
