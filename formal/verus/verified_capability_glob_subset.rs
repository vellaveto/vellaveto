// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability parent-glob/child-glob subset kernel.
//!
//! This file proves the exact fast-path combiner and the core reachability
//! invariants for the extracted child-glob subset boundary in
//! `vellaveto-mcp/src/verified_capability_glob_subset.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_glob_subset.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_glob_subset_accepting_counterexample(
    parent_accepts: bool,
    child_accepts: bool,
) -> bool {
    child_accepts && !parent_accepts
}

pub fn glob_subset_accepting_counterexample(
    parent_accepts: bool,
    child_accepts: bool,
) -> (result: bool)
    ensures
        result == spec_glob_subset_accepting_counterexample(parent_accepts, child_accepts),
        result ==> child_accepts,
        result ==> !parent_accepts,
{
    child_accepts && !parent_accepts
}

pub open spec fn spec_glob_subset_fast_path(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
    literal_child_subset: bool,
    exact_child_glob_subset: bool,
) -> bool {
    if parent_is_wildcard || parent_equals_child_ignore_ascii_case {
        true
    } else if !child_has_metacharacters {
        literal_child_subset
    } else {
        exact_child_glob_subset
    }
}

pub fn glob_subset_fast_path(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
    literal_child_subset: bool,
    exact_child_glob_subset: bool,
) -> (result: bool)
    ensures
        result == spec_glob_subset_fast_path(
            parent_is_wildcard,
            parent_equals_child_ignore_ascii_case,
            child_has_metacharacters,
            literal_child_subset,
            exact_child_glob_subset,
        ),
        parent_is_wildcard || parent_equals_child_ignore_ascii_case ==> result,
        !parent_is_wildcard && !parent_equals_child_ignore_ascii_case && !child_has_metacharacters
            ==> result == literal_child_subset,
        !parent_is_wildcard && !parent_equals_child_ignore_ascii_case && child_has_metacharacters
            ==> result == exact_child_glob_subset,
{
    if parent_is_wildcard || parent_equals_child_ignore_ascii_case {
        true
    } else if !child_has_metacharacters {
        literal_child_subset
    } else {
        exact_child_glob_subset
    }
}

pub open spec fn spec_representative_other_byte_needed(
    literal_class_count: nat,
) -> bool {
    literal_class_count < 256
}

pub fn representative_other_byte_needed(literal_class_count: usize) -> (result: bool)
    ensures result == spec_representative_other_byte_needed(literal_class_count as nat),
{
    literal_class_count < 256
}

pub proof fn lemma_counterexample_requires_child_acceptance(parent_accepts: bool)
    ensures
        spec_glob_subset_accepting_counterexample(parent_accepts, true) == !parent_accepts,
        !spec_glob_subset_accepting_counterexample(parent_accepts, false),
{
}

pub proof fn lemma_fast_path_accepts_wildcard_or_equality(
    child_has_metacharacters: bool,
    literal_child_subset: bool,
    exact_child_glob_subset: bool,
)
    ensures
        spec_glob_subset_fast_path(true, false, child_has_metacharacters, literal_child_subset, exact_child_glob_subset),
        spec_glob_subset_fast_path(false, true, child_has_metacharacters, literal_child_subset, exact_child_glob_subset),
{
}

pub proof fn lemma_fast_path_routes_literal_children(
    literal_child_subset: bool,
    exact_child_glob_subset: bool,
)
    ensures
        spec_glob_subset_fast_path(false, false, false, literal_child_subset, exact_child_glob_subset)
            == literal_child_subset,
{
}

pub proof fn lemma_fast_path_routes_child_globs(
    literal_child_subset: bool,
    exact_child_glob_subset: bool,
)
    ensures
        spec_glob_subset_fast_path(false, false, true, literal_child_subset, exact_child_glob_subset)
            == exact_child_glob_subset,
{
}

pub proof fn lemma_other_byte_needed_below_full_alphabet(literal_class_count: nat)
    requires literal_class_count < 256
    ensures spec_representative_other_byte_needed(literal_class_count),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_glob_subset_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
