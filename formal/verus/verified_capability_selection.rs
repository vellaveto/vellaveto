// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability grant-selection kernel.
//!
//! This file proves the first-match selection rule extracted into
//! `vellaveto-mcp/src/verified_capability_selection.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_selection.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_next_covering_grant_index(
    selected_index: Option<usize>,
    current_index: usize,
    current_grant_covers: bool,
) -> Option<usize> {
    match selected_index {
        Some(existing_index) => Some(existing_index),
        None => {
            if current_grant_covers {
                Some(current_index)
            } else {
                None
            }
        }
    }
}

pub fn next_covering_grant_index(
    selected_index: Option<usize>,
    current_index: usize,
    current_grant_covers: bool,
) -> (result: Option<usize>)
    ensures
        result == spec_next_covering_grant_index(selected_index, current_index, current_grant_covers),
{
    match selected_index {
        Some(existing_index) => Some(existing_index),
        None => {
            if current_grant_covers {
                Some(current_index)
            } else {
                None
            }
        }
    }
}

pub proof fn lemma_non_matching_grant_keeps_none(current_index: usize)
    ensures
        spec_next_covering_grant_index(None::<usize>, current_index, false)
            == None::<usize>,
{
}

pub proof fn lemma_first_matching_grant_is_selected(current_index: usize)
    ensures
        spec_next_covering_grant_index(None::<usize>, current_index, true)
            == Some(current_index),
{
}

pub proof fn lemma_existing_selection_is_preserved(
    existing_index: usize,
    current_index: usize,
    current_grant_covers: bool,
)
    ensures
        spec_next_covering_grant_index(
            Some(existing_index),
            current_index,
            current_grant_covers,
        ) == Some(existing_index),
{
}

pub proof fn lemma_selected_index_never_moves_forward(
    existing_index: usize,
    current_index: usize,
    current_grant_covers: bool,
)
    ensures
        spec_next_covering_grant_index(
            Some(existing_index),
            current_index,
            current_grant_covers,
        ) == Some(existing_index),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_selection_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
