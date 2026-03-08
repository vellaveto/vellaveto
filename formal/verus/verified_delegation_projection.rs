// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified projection of deputy delegation state into engine evaluation.
//!
//! This file proves the extracted predicate in
//! `vellaveto-mcp/src/verified_delegation_projection.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_delegation_projection.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

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

pub fn projected_call_chain_len(
    has_active_delegation: bool,
    delegation_depth: u8,
) -> (result: usize)
    ensures
        result as nat == spec_projected_call_chain_len(has_active_delegation, delegation_depth),
        !has_active_delegation ==> result == 0,
        has_active_delegation ==> result == delegation_depth as usize,
{
    if has_active_delegation {
        delegation_depth as usize
    } else {
        0
    }
}

pub proof fn lemma_inactive_delegation_projects_empty_chain(delegation_depth: u8)
    ensures spec_projected_call_chain_len(false, delegation_depth) == 0,
{
}

pub proof fn lemma_active_delegation_preserves_depth(delegation_depth: u8)
    ensures spec_projected_call_chain_len(true, delegation_depth) == delegation_depth as nat,
{
}

pub proof fn lemma_projected_depth_is_bounded_by_u8_max(
    has_active_delegation: bool,
    delegation_depth: u8,
)
    ensures spec_projected_call_chain_len(has_active_delegation, delegation_depth) <= 255,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::delegation_projection_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
