// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability grant path-normalization kernel.
//!
//! This file proves the fail-closed component transition extracted into
//! `vellaveto-mcp/src/verified_capability_path.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_path.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_path_component_next_depth(
    current_depth: usize,
    component_is_empty_or_dot: bool,
    component_is_dotdot: bool,
) -> Option<usize> {
    if component_is_empty_or_dot {
        Some(current_depth)
    } else if component_is_dotdot {
        if current_depth == 0 {
            None
        } else {
            Some((((current_depth as nat) - 1) as int) as usize)
        }
    } else if current_depth == usize::MAX {
        None
    } else {
        Some((((current_depth as nat) + 1) as int) as usize)
    }
}

pub fn path_component_next_depth(
    current_depth: usize,
    component_is_empty_or_dot: bool,
    component_is_dotdot: bool,
) -> (result: Option<usize>)
    ensures
        result
            == spec_path_component_next_depth(
                current_depth,
                component_is_empty_or_dot,
                component_is_dotdot,
            ),
{
    if component_is_empty_or_dot {
        Some(current_depth)
    } else if component_is_dotdot {
        if current_depth == 0 {
            None
        } else {
            Some(current_depth - 1)
        }
    } else if current_depth == usize::MAX {
        None
    } else {
        Some(current_depth + 1)
    }
}

pub proof fn lemma_empty_or_dot_component_keeps_depth(
    current_depth: usize,
    component_is_dotdot: bool,
)
    ensures
        spec_path_component_next_depth(current_depth, true, component_is_dotdot)
            == Some(current_depth),
{
}

pub proof fn lemma_dotdot_at_root_fails_closed()
    ensures spec_path_component_next_depth(0, false, true) == None::<usize>,
{
}

pub proof fn lemma_dotdot_below_root_pops(current_depth: usize)
    requires current_depth > 0
    ensures
        spec_path_component_next_depth(current_depth, false, true)
            == Some((((current_depth as nat) - 1) as int) as usize),
{
}

pub proof fn lemma_literal_component_pushes_when_bounded(current_depth: usize)
    requires current_depth < usize::MAX
    ensures
        spec_path_component_next_depth(current_depth, false, false)
            == Some((((current_depth as nat) + 1) as int) as usize),
{
}

pub proof fn lemma_literal_component_overflow_fails_closed()
    ensures spec_path_component_next_depth(usize::MAX, false, false) == None::<usize>,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_path_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
