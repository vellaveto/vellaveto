// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability-token context guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-engine/src/verified_capability_context.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_context.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_capability_holder_binding_valid(
    agent_present: bool,
    normalized_holder_equals_agent: bool,
) -> bool {
    agent_present && normalized_holder_equals_agent
}

pub fn capability_holder_binding_valid(
    agent_present: bool,
    normalized_holder_equals_agent: bool,
) -> (result: bool)
    ensures
        result
            == spec_capability_holder_binding_valid(
                agent_present,
                normalized_holder_equals_agent,
            ),
        result ==> agent_present,
        result ==> normalized_holder_equals_agent,
{
    agent_present && normalized_holder_equals_agent
}

pub open spec fn spec_capability_issuer_allowed(
    required_issuers_empty: bool,
    issuer_allowed: bool,
) -> bool {
    required_issuers_empty || issuer_allowed
}

pub fn capability_issuer_allowed(
    required_issuers_empty: bool,
    issuer_allowed: bool,
) -> (result: bool)
    ensures
        result == spec_capability_issuer_allowed(required_issuers_empty, issuer_allowed),
{
    required_issuers_empty || issuer_allowed
}

pub open spec fn spec_capability_remaining_depth_sufficient(
    remaining_depth: nat,
    min_remaining_depth: nat,
) -> bool {
    remaining_depth >= min_remaining_depth
}

pub fn capability_remaining_depth_sufficient(
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> (result: bool)
    ensures
        result
            == spec_capability_remaining_depth_sufficient(
                remaining_depth as nat,
                min_remaining_depth as nat,
            ),
        result ==> (remaining_depth as nat) >= (min_remaining_depth as nat),
        !result ==> (remaining_depth as nat) < (min_remaining_depth as nat),
{
    remaining_depth >= min_remaining_depth
}

pub proof fn lemma_missing_agent_fails_closed(normalized_holder_equals_agent: bool)
    ensures
        !spec_capability_holder_binding_valid(false, normalized_holder_equals_agent),
{
}

pub proof fn lemma_holder_binding_requires_match()
    ensures
        !spec_capability_holder_binding_valid(true, false),
        spec_capability_holder_binding_valid(true, true),
{
}

pub proof fn lemma_empty_issuer_allowlist_allows_any_issuer(issuer_allowed: bool)
    ensures
        spec_capability_issuer_allowed(true, issuer_allowed),
{
}

pub proof fn lemma_nonempty_issuer_allowlist_requires_membership()
    ensures
        !spec_capability_issuer_allowed(false, false),
        spec_capability_issuer_allowed(false, true),
{
}

pub proof fn lemma_depth_threshold_is_inclusive(min_remaining_depth: nat)
    requires min_remaining_depth < 255,
    ensures
        spec_capability_remaining_depth_sufficient(
            min_remaining_depth,
            min_remaining_depth,
        ),
        spec_capability_remaining_depth_sufficient(
            min_remaining_depth + 1,
            min_remaining_depth,
        ),
{
}

pub proof fn lemma_depth_below_threshold_fails_closed(
    remaining_depth: nat,
    min_remaining_depth: nat,
)
    requires remaining_depth < min_remaining_depth,
    ensures
        !spec_capability_remaining_depth_sufficient(
            remaining_depth,
            min_remaining_depth,
        ),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_context_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
