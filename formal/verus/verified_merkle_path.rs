// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified Merkle proof-path kernel.
//!
//! This file proves the pure structural sibling/orientation/parent rules
//! extracted into `vellaveto-audit/src/verified_merkle_path.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_merkle_path.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_proof_sibling_index(node_index: nat) -> nat {
    if node_index % 2 == 0 {
        node_index + 1
    } else {
        (node_index as int - 1) as nat
    }
}

pub fn proof_sibling_index(node_index: usize) -> (result: usize)
    ensures result as nat == spec_proof_sibling_index(node_index as nat),
{
    if node_index % 2 == 0 {
        node_index + 1
    } else {
        node_index - 1
    }
}

pub open spec fn spec_proof_step_is_left(node_index: nat) -> bool {
    node_index % 2 == 1
}

pub fn proof_step_is_left(node_index: usize) -> (result: bool)
    ensures result == spec_proof_step_is_left(node_index as nat),
{
    node_index % 2 == 1
}

pub open spec fn spec_proof_level_has_sibling(node_index: nat, level_len: nat) -> bool {
    spec_proof_sibling_index(node_index) < level_len
}

pub fn proof_level_has_sibling(node_index: usize, level_len: usize) -> (result: bool)
    ensures result == spec_proof_level_has_sibling(node_index as nat, level_len as nat),
{
    proof_sibling_index(node_index) < level_len
}

pub open spec fn spec_proof_parent_index(node_index: nat) -> nat {
    node_index / 2
}

pub fn proof_parent_index(node_index: usize) -> (result: usize)
    ensures result as nat == spec_proof_parent_index(node_index as nat),
{
    node_index / 2
}

pub open spec fn spec_proof_step_places_sibling_left(step_is_left: bool) -> bool {
    step_is_left
}

pub fn proof_step_places_sibling_left(step_is_left: bool) -> (result: bool)
    ensures result == spec_proof_step_places_sibling_left(step_is_left),
{
    step_is_left
}

pub proof fn lemma_even_index_uses_right_sibling(node_index: nat)
    requires node_index % 2 == 0
    ensures
        spec_proof_sibling_index(node_index) == node_index + 1,
        !spec_proof_step_is_left(node_index),
{
}

pub proof fn lemma_odd_index_uses_left_sibling(node_index: nat)
    requires node_index % 2 == 1
    ensures
        spec_proof_sibling_index(node_index) + 1 == node_index,
        spec_proof_step_is_left(node_index),
{
}

pub proof fn lemma_trailing_even_index_without_pair_is_promoted(level_len: nat)
    requires level_len > 0, level_len % 2 == 1
    ensures !spec_proof_level_has_sibling((level_len as int - 1) as nat, level_len),
{
}

pub proof fn lemma_paired_even_index_has_sibling(node_index: nat, level_len: nat)
    requires node_index % 2 == 0, node_index + 1 < level_len
    ensures spec_proof_level_has_sibling(node_index, level_len),
{
}

pub proof fn lemma_valid_odd_index_has_left_sibling(node_index: nat, level_len: nat)
    requires node_index % 2 == 1, node_index < level_len
    ensures spec_proof_level_has_sibling(node_index, level_len),
{
}

pub proof fn lemma_parent_index_halves_child(node_index: nat)
    ensures spec_proof_parent_index(node_index) == node_index / 2,
{
}

pub proof fn lemma_verifier_direction_is_identity(step_is_left: bool)
    ensures spec_proof_step_places_sibling_left(step_is_left) == step_is_left,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::merkle_path_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
