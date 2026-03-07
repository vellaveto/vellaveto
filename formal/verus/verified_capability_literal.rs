// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability literal matching kernel.
//!
//! This file proves the literal-only fast paths extracted into
//! `vellaveto-mcp/src/verified_capability_literal.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_literal.rs`

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_literal_pattern_matches(
    pattern_has_metacharacters: bool,
    pattern_equals_value_ignore_ascii_case: bool,
) -> bool {
    !pattern_has_metacharacters && pattern_equals_value_ignore_ascii_case
}

pub fn literal_pattern_matches(
    pattern_has_metacharacters: bool,
    pattern_equals_value_ignore_ascii_case: bool,
) -> (result: bool)
    ensures
        result == spec_literal_pattern_matches(
            pattern_has_metacharacters,
            pattern_equals_value_ignore_ascii_case,
        ),
        result ==> !pattern_has_metacharacters,
        result ==> pattern_equals_value_ignore_ascii_case,
{
    !pattern_has_metacharacters && pattern_equals_value_ignore_ascii_case
}

pub open spec fn spec_literal_child_pattern_subset(
    child_has_metacharacters: bool,
    parent_matches_child_literal: bool,
) -> bool {
    !child_has_metacharacters && parent_matches_child_literal
}

pub fn literal_child_pattern_subset(
    child_has_metacharacters: bool,
    parent_matches_child_literal: bool,
) -> (result: bool)
    ensures
        result == spec_literal_child_pattern_subset(
            child_has_metacharacters,
            parent_matches_child_literal,
        ),
        result ==> !child_has_metacharacters,
        result ==> parent_matches_child_literal,
{
    !child_has_metacharacters && parent_matches_child_literal
}

pub proof fn lemma_equal_literal_pattern_matches()
    ensures spec_literal_pattern_matches(false, true),
{
}

pub proof fn lemma_mismatching_literal_pattern_is_denied()
    ensures !spec_literal_pattern_matches(false, false),
{
}

pub proof fn lemma_metacharacter_pattern_skips_literal_fast_path(
    pattern_equals_value_ignore_ascii_case: bool,
)
    ensures !spec_literal_pattern_matches(true, pattern_equals_value_ignore_ascii_case),
{
}

pub proof fn lemma_matching_literal_child_is_subset()
    ensures spec_literal_child_pattern_subset(false, true),
{
}

pub proof fn lemma_mismatching_literal_child_is_denied()
    ensures !spec_literal_child_pattern_subset(false, false),
{
}

pub proof fn lemma_child_glob_cannot_use_literal_subset_branch(
    parent_matches_child_literal: bool,
)
    ensures !spec_literal_child_pattern_subset(true, parent_matches_child_literal),
{
}

fn main() {}

} // verus!
