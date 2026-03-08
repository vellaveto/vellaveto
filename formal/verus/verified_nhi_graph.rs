// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified NHI delegation graph guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-mcp/src/verified_nhi_graph.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_nhi_graph.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_delegation_link_effective_for_successor(
    from_agent_matches_current: bool,
    link_active: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
) -> bool {
    from_agent_matches_current && link_active && expiry_parsed && now_before_expiry
}

pub fn delegation_link_effective_for_successor(
    from_agent_matches_current: bool,
    link_active: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
) -> (result: bool)
    ensures
        result == spec_delegation_link_effective_for_successor(
            from_agent_matches_current,
            link_active,
            expiry_parsed,
            now_before_expiry,
        ),
        result ==> expiry_parsed,
{
    from_agent_matches_current && link_active && expiry_parsed && now_before_expiry
}

pub open spec fn spec_delegation_edge_preserves_acyclicity(
    path_from_delegatee_to_delegator_exists: bool,
) -> bool {
    !path_from_delegatee_to_delegator_exists
}

pub fn delegation_edge_preserves_acyclicity(
    path_from_delegatee_to_delegator_exists: bool,
) -> (result: bool)
    ensures
        result
            == spec_delegation_edge_preserves_acyclicity(
                path_from_delegatee_to_delegator_exists,
            ),
        path_from_delegatee_to_delegator_exists ==> !result,
{
    !path_from_delegatee_to_delegator_exists
}

pub struct SuccessorLink {
    pub from_agent_matches: bool,
    pub active: bool,
    pub expiry_parsed: bool,
    pub now_before_expiry: bool,
}

pub open spec fn spec_successor_link_effective(link: SuccessorLink) -> bool {
    spec_delegation_link_effective_for_successor(
        link.from_agent_matches,
        link.active,
        link.expiry_parsed,
        link.now_before_expiry,
    )
}

pub open spec fn spec_live_successor_path(chain: Seq<SuccessorLink>, n: nat) -> bool
    decreases n,
{
    if n == 0 {
        true
    } else if n > chain.len() {
        false
    } else {
        spec_successor_link_effective(chain[(n - 1) as int])
            && spec_live_successor_path(chain, (n - 1) as nat)
    }
}

pub open spec fn spec_cycle_exists_after_insert(
    path_from_delegatee_to_delegator_exists: bool,
    new_edge_is_live: bool,
) -> bool {
    path_from_delegatee_to_delegator_exists && new_edge_is_live
}

pub proof fn lemma_inactive_or_unparseable_successor_link_is_not_effective(
    from_agent_matches_current: bool,
    now_before_expiry: bool,
)
    ensures
        !spec_delegation_link_effective_for_successor(
            from_agent_matches_current,
            true,
            false,
            now_before_expiry,
        ),
        !spec_delegation_link_effective_for_successor(
            from_agent_matches_current,
            false,
            true,
            true,
        ),
{
}

pub proof fn lemma_live_back_path_with_live_inserted_edge_forms_cycle(chain: Seq<SuccessorLink>, n: nat)
    requires
        n <= chain.len(),
        n > 0,
        spec_live_successor_path(chain, n),
    ensures
        spec_cycle_exists_after_insert(true, true),
        !spec_delegation_edge_preserves_acyclicity(true),
{
}

pub proof fn lemma_no_live_back_path_preserves_acyclicity()
    ensures
        spec_delegation_edge_preserves_acyclicity(false),
        !spec_cycle_exists_after_insert(false, true),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::nhi_graph_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
