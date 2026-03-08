// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified confused-deputy delegation guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-engine/src/verified_deputy.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_deputy.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_next_delegation_depth(current_depth: nat) -> nat {
    if current_depth >= 255 { 255 } else { current_depth + 1 }
}

pub fn next_delegation_depth(current_depth: u8) -> (result: u8)
    ensures result as nat == spec_next_delegation_depth(current_depth as nat),
{
    current_depth.saturating_add(1)
}

pub open spec fn spec_delegation_depth_within_limit(new_depth: nat, max_depth: nat) -> bool {
    new_depth <= max_depth
}

pub fn delegation_depth_within_limit(new_depth: u8, max_depth: u8) -> (result: bool)
    ensures result == spec_delegation_depth_within_limit(new_depth as nat, max_depth as nat),
{
    new_depth <= max_depth
}

pub open spec fn spec_redelegation_chain_principal_valid(
    parent_has_delegate: bool,
    normalized_from_matches_parent_delegate: bool,
) -> bool {
    !parent_has_delegate || normalized_from_matches_parent_delegate
}

pub fn redelegation_chain_principal_valid(
    parent_has_delegate: bool,
    normalized_from_matches_parent_delegate: bool,
) -> (result: bool)
    ensures
        result
            == spec_redelegation_chain_principal_valid(
                parent_has_delegate,
                normalized_from_matches_parent_delegate,
            ),
        parent_has_delegate && result ==> normalized_from_matches_parent_delegate,
{
    !parent_has_delegate || normalized_from_matches_parent_delegate
}

pub open spec fn spec_redelegation_tool_allowed(
    parent_has_unrestricted_tools: bool,
    parent_allows_requested_tool: bool,
) -> bool {
    parent_has_unrestricted_tools || parent_allows_requested_tool
}

pub fn redelegation_tool_allowed(
    parent_has_unrestricted_tools: bool,
    parent_allows_requested_tool: bool,
) -> (result: bool)
    ensures
        result
            == spec_redelegation_tool_allowed(
                parent_has_unrestricted_tools,
                parent_allows_requested_tool,
            ),
{
    parent_has_unrestricted_tools || parent_allows_requested_tool
}

pub open spec fn spec_delegated_principal_matches(
    normalized_claimed_matches_delegate: bool,
) -> bool {
    normalized_claimed_matches_delegate
}

pub fn delegated_principal_matches(
    normalized_claimed_matches_delegate: bool,
) -> (result: bool)
    ensures result == spec_delegated_principal_matches(normalized_claimed_matches_delegate),
{
    normalized_claimed_matches_delegate
}

pub open spec fn spec_delegated_tool_allowed(
    allowed_tools_empty: bool,
    requested_tool_found: bool,
) -> bool {
    allowed_tools_empty || requested_tool_found
}

pub fn delegated_tool_allowed(
    allowed_tools_empty: bool,
    requested_tool_found: bool,
) -> (result: bool)
    ensures
        result == spec_delegated_tool_allowed(allowed_tools_empty, requested_tool_found),
{
    allowed_tools_empty || requested_tool_found
}

pub proof fn lemma_depth_saturates_at_max()
    ensures
        spec_next_delegation_depth(0) == 1,
        spec_next_delegation_depth(255) == 255,
{
}

pub proof fn lemma_depth_limit_is_strict(max_depth: nat)
    requires max_depth < 255,
    ensures
        spec_delegation_depth_within_limit(max_depth, max_depth),
        !spec_delegation_depth_within_limit(max_depth + 1, max_depth),
{
}

pub proof fn lemma_root_delegation_has_no_parent_principal_obligation(
    normalized_from_matches_parent_delegate: bool,
)
    ensures
        spec_redelegation_chain_principal_valid(
            false,
            normalized_from_matches_parent_delegate,
        ),
{
}

pub proof fn lemma_redelegation_requires_parent_delegate_match()
    ensures !spec_redelegation_chain_principal_valid(true, false),
{
}

pub proof fn lemma_restricted_parent_scope_blocks_missing_tool()
    ensures
        !spec_redelegation_tool_allowed(false, false),
        spec_redelegation_tool_allowed(false, true),
        spec_redelegation_tool_allowed(true, false),
{
}

pub proof fn lemma_delegated_principal_and_tool_guards_are_fail_closed()
    ensures
        !spec_delegated_principal_matches(false),
        spec_delegated_principal_matches(true),
        !spec_delegated_tool_allowed(false, false),
        spec_delegated_tool_allowed(true, false),
        spec_delegated_tool_allowed(false, true),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::deputy_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
