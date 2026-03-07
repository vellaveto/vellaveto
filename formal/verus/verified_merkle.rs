// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified Merkle fail-closed guard kernel.
//!
//! This file proves the pure capacity and proof-shape guards extracted into
//! `vellaveto-audit/src/verified_merkle.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_merkle.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub const MAX_PROOF_SIBLINGS: usize = 64;
pub const HASH_SIZE: usize = 32;

pub open spec fn spec_append_allowed(leaf_count: nat, max_leaf_count: nat) -> bool {
    leaf_count < max_leaf_count
}

pub fn append_allowed(leaf_count: u64, max_leaf_count: u64) -> (result: bool)
    ensures result == spec_append_allowed(leaf_count as nat, max_leaf_count as nat),
{
    leaf_count < max_leaf_count
}

pub open spec fn spec_stored_leaf_count_valid(leaf_count: nat, max_leaf_count: nat) -> bool {
    leaf_count <= max_leaf_count
}

pub fn stored_leaf_count_valid(leaf_count: u64, max_leaf_count: u64) -> (result: bool)
    ensures result == spec_stored_leaf_count_valid(leaf_count as nat, max_leaf_count as nat),
{
    leaf_count <= max_leaf_count
}

pub open spec fn spec_proof_tree_size_valid(tree_size: nat) -> bool {
    tree_size > 0
}

pub fn proof_tree_size_valid(tree_size: u64) -> (result: bool)
    ensures result == spec_proof_tree_size_valid(tree_size as nat),
{
    tree_size > 0
}

pub open spec fn spec_proof_leaf_index_valid(leaf_index: nat, tree_size: nat) -> bool {
    leaf_index < tree_size
}

pub fn proof_leaf_index_valid(leaf_index: u64, tree_size: u64) -> (result: bool)
    ensures result == spec_proof_leaf_index_valid(leaf_index as nat, tree_size as nat),
{
    leaf_index < tree_size
}

pub open spec fn spec_proof_sibling_count_valid(sibling_count: nat) -> bool {
    sibling_count <= MAX_PROOF_SIBLINGS as nat
}

pub fn proof_sibling_count_valid(sibling_count: usize) -> (result: bool)
    ensures result == spec_proof_sibling_count_valid(sibling_count as nat),
{
    sibling_count <= 64
}

pub open spec fn spec_sibling_hash_len_valid(sibling_len: nat) -> bool {
    sibling_len == HASH_SIZE
}

pub fn sibling_hash_len_valid(sibling_len: usize) -> (result: bool)
    ensures result == spec_sibling_hash_len_valid(sibling_len as nat),
{
    sibling_len == 32
}

pub proof fn lemma_append_rejects_at_limit(max_leaf_count: nat)
    ensures !spec_append_allowed(max_leaf_count, max_leaf_count),
{
}

pub proof fn lemma_append_accepts_below_limit(leaf_count: nat, max_leaf_count: nat)
    requires leaf_count < max_leaf_count
    ensures spec_append_allowed(leaf_count, max_leaf_count),
{
}

pub proof fn lemma_stored_leaf_count_accepts_equal_limit(max_leaf_count: nat)
    ensures spec_stored_leaf_count_valid(max_leaf_count, max_leaf_count),
{
}

pub proof fn lemma_stored_leaf_count_rejects_over_limit(leaf_count: nat, max_leaf_count: nat)
    requires leaf_count > max_leaf_count
    ensures !spec_stored_leaf_count_valid(leaf_count, max_leaf_count),
{
}

pub proof fn lemma_zero_tree_size_rejected()
    ensures !spec_proof_tree_size_valid(0),
{
}

pub proof fn lemma_positive_tree_size_accepted(tree_size: nat)
    requires tree_size > 0
    ensures spec_proof_tree_size_valid(tree_size),
{
}

pub proof fn lemma_leaf_index_out_of_range_rejected(leaf_index: nat, tree_size: nat)
    requires leaf_index >= tree_size
    ensures !spec_proof_leaf_index_valid(leaf_index, tree_size),
{
}

pub proof fn lemma_leaf_index_in_range_accepted(leaf_index: nat, tree_size: nat)
    requires leaf_index < tree_size
    ensures spec_proof_leaf_index_valid(leaf_index, tree_size),
{
}

pub proof fn lemma_too_many_siblings_rejected(sibling_count: nat)
    requires sibling_count > MAX_PROOF_SIBLINGS as nat
    ensures !spec_proof_sibling_count_valid(sibling_count),
{
}

pub proof fn lemma_bounded_sibling_count_accepted(sibling_count: nat)
    requires sibling_count <= MAX_PROOF_SIBLINGS as nat
    ensures spec_proof_sibling_count_valid(sibling_count),
{
}

pub proof fn lemma_hash_len_32_accepted()
    ensures spec_sibling_hash_len_valid(32),
{
}

pub proof fn lemma_hash_len_non_32_rejected(sibling_len: nat)
    requires sibling_len != HASH_SIZE as nat
    ensures !spec_sibling_hash_len_valid(sibling_len),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::merkle_guard_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
