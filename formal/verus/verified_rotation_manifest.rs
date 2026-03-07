// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified cross-rotation manifest guard kernel.
//!
//! This file proves the pure linkage and path-safety predicates extracted into
//! `vellaveto-audit/src/verified_rotation_manifest.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_rotation_manifest.rs`

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_rotation_start_hash_link_valid(
    claimed_start_hash_is_empty: bool,
    has_previous_tail_hash: bool,
    claimed_start_hash_matches_previous_tail: bool,
) -> bool {
    claimed_start_hash_is_empty || !has_previous_tail_hash || claimed_start_hash_matches_previous_tail
}

pub fn rotation_start_hash_link_valid(
    claimed_start_hash_is_empty: bool,
    has_previous_tail_hash: bool,
    claimed_start_hash_matches_previous_tail: bool,
) -> (result: bool)
    ensures
        result == spec_rotation_start_hash_link_valid(
            claimed_start_hash_is_empty,
            has_previous_tail_hash,
            claimed_start_hash_matches_previous_tail,
        ),
{
    claimed_start_hash_is_empty || !has_previous_tail_hash || claimed_start_hash_matches_previous_tail
}

pub open spec fn spec_rotated_file_reference_valid(
    has_traversal: bool,
    is_absolute: bool,
    is_bare_filename: bool,
    is_empty: bool,
) -> bool {
    !has_traversal && !is_absolute && is_bare_filename && !is_empty
}

pub fn rotated_file_reference_valid(
    has_traversal: bool,
    is_absolute: bool,
    is_bare_filename: bool,
    is_empty: bool,
) -> (result: bool)
    ensures
        result == spec_rotated_file_reference_valid(
            has_traversal,
            is_absolute,
            is_bare_filename,
            is_empty,
        ),
{
    !has_traversal && !is_absolute && is_bare_filename && !is_empty
}

pub open spec fn spec_missing_rotated_file_allowed(files_checked: nat) -> bool {
    files_checked == 0
}

pub fn missing_rotated_file_allowed(files_checked: usize) -> (result: bool)
    ensures result == spec_missing_rotated_file_allowed(files_checked as nat),
{
    files_checked == 0
}

pub proof fn lemma_empty_start_hash_always_valid(has_previous_tail_hash: bool, claimed_start_hash_matches_previous_tail: bool)
    ensures spec_rotation_start_hash_link_valid(true, has_previous_tail_hash, claimed_start_hash_matches_previous_tail),
{
}

pub proof fn lemma_first_segment_without_previous_tail_is_valid(claimed_start_hash_is_empty: bool, claimed_start_hash_matches_previous_tail: bool)
    ensures spec_rotation_start_hash_link_valid(claimed_start_hash_is_empty, false, claimed_start_hash_matches_previous_tail),
{
}

pub proof fn lemma_matching_previous_tail_is_valid(claimed_start_hash_is_empty: bool)
    ensures spec_rotation_start_hash_link_valid(claimed_start_hash_is_empty, true, true),
{
}

pub proof fn lemma_mismatching_nonempty_start_hash_is_rejected()
    ensures !spec_rotation_start_hash_link_valid(false, true, false),
{
}

pub proof fn lemma_safe_rotated_file_reference_is_valid()
    ensures spec_rotated_file_reference_valid(false, false, true, false),
{
}

pub proof fn lemma_traversal_reference_is_rejected(is_absolute: bool, is_bare_filename: bool, is_empty: bool)
    ensures !spec_rotated_file_reference_valid(true, is_absolute, is_bare_filename, is_empty),
{
}

pub proof fn lemma_absolute_reference_is_rejected(has_traversal: bool, is_bare_filename: bool, is_empty: bool)
    ensures !spec_rotated_file_reference_valid(has_traversal, true, is_bare_filename, is_empty),
{
}

pub proof fn lemma_non_bare_reference_is_rejected(has_traversal: bool, is_absolute: bool, is_empty: bool)
    ensures !spec_rotated_file_reference_valid(has_traversal, is_absolute, false, is_empty),
{
}

pub proof fn lemma_empty_reference_is_rejected(has_traversal: bool, is_absolute: bool, is_bare_filename: bool)
    ensures !spec_rotated_file_reference_valid(has_traversal, is_absolute, is_bare_filename, true),
{
}

pub proof fn lemma_only_prefix_missing_files_are_allowed(files_checked: nat)
    ensures spec_missing_rotated_file_allowed(files_checked) == (files_checked == 0),
{
}

fn main() {}

} // verus!
