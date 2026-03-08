// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability domain containment kernel.
//!
//! This file proves the fail-closed domain-pattern shape, normalized suffix
//! matching, and parent/child containment gates extracted into
//! `vellaveto-mcp/src/verified_capability_domain.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_domain.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_domain_pattern_shape_valid(
    has_wildcard_prefix: bool,
    has_other_metacharacters: bool,
    suffix_is_empty: bool,
) -> bool {
    !has_other_metacharacters && (!has_wildcard_prefix || !suffix_is_empty)
}

pub fn domain_pattern_shape_valid(
    has_wildcard_prefix: bool,
    has_other_metacharacters: bool,
    suffix_is_empty: bool,
) -> (result: bool)
    ensures
        result
            == spec_domain_pattern_shape_valid(
                has_wildcard_prefix,
                has_other_metacharacters,
                suffix_is_empty,
            ),
{
    !has_other_metacharacters && (!has_wildcard_prefix || !suffix_is_empty)
}

pub open spec fn spec_normalized_domain_suffix_matches(
    candidate_equals_suffix: bool,
    candidate_has_suffix_with_dot_boundary: bool,
) -> bool {
    candidate_equals_suffix || candidate_has_suffix_with_dot_boundary
}

pub fn normalized_domain_suffix_matches(
    candidate_equals_suffix: bool,
    candidate_has_suffix_with_dot_boundary: bool,
) -> (result: bool)
    ensures
        result
            == spec_normalized_domain_suffix_matches(
                candidate_equals_suffix,
                candidate_has_suffix_with_dot_boundary,
            ),
{
    candidate_equals_suffix || candidate_has_suffix_with_dot_boundary
}

pub open spec fn spec_normalized_domain_pattern_matches(
    pattern_is_wildcard: bool,
    wildcard_suffix_match: bool,
    exact_match: bool,
) -> bool {
    if pattern_is_wildcard {
        wildcard_suffix_match
    } else {
        exact_match
    }
}

pub fn normalized_domain_pattern_matches(
    pattern_is_wildcard: bool,
    wildcard_suffix_match: bool,
    exact_match: bool,
) -> (result: bool)
    ensures
        result
            == spec_normalized_domain_pattern_matches(
                pattern_is_wildcard,
                wildcard_suffix_match,
                exact_match,
            ),
{
    if pattern_is_wildcard {
        wildcard_suffix_match
    } else {
        exact_match
    }
}

pub open spec fn spec_normalized_domain_pattern_subset(
    parent_is_wildcard: bool,
    child_is_wildcard: bool,
    child_matches_parent_suffix: bool,
    exact_patterns_equal: bool,
) -> bool {
    if parent_is_wildcard {
        child_matches_parent_suffix
    } else {
        !child_is_wildcard && exact_patterns_equal
    }
}

pub fn normalized_domain_pattern_subset(
    parent_is_wildcard: bool,
    child_is_wildcard: bool,
    child_matches_parent_suffix: bool,
    exact_patterns_equal: bool,
) -> (result: bool)
    ensures
        result
            == spec_normalized_domain_pattern_subset(
                parent_is_wildcard,
                child_is_wildcard,
                child_matches_parent_suffix,
                exact_patterns_equal,
            ),
{
    if parent_is_wildcard {
        child_matches_parent_suffix
    } else {
        !child_is_wildcard && exact_patterns_equal
    }
}

pub proof fn lemma_exact_domain_pattern_shape_is_valid()
    ensures spec_domain_pattern_shape_valid(false, false, false),
{
}

pub proof fn lemma_wildcard_domain_pattern_requires_non_empty_suffix()
    ensures
        !spec_domain_pattern_shape_valid(true, false, true),
        spec_domain_pattern_shape_valid(true, false, false),
{
}

pub proof fn lemma_other_metacharacters_fail_closed(
    has_wildcard_prefix: bool,
    suffix_is_empty: bool,
)
    ensures
        !spec_domain_pattern_shape_valid(
            has_wildcard_prefix,
            true,
            suffix_is_empty,
        ),
{
}

pub proof fn lemma_suffix_match_accepts_exact_or_dot_boundary()
    ensures
        spec_normalized_domain_suffix_matches(true, false),
        spec_normalized_domain_suffix_matches(false, true),
        !spec_normalized_domain_suffix_matches(false, false),
{
}

pub proof fn lemma_exact_patterns_require_exact_domain_match(
    wildcard_suffix_match: bool,
    exact_match: bool,
)
    ensures
        spec_normalized_domain_pattern_matches(false, wildcard_suffix_match, exact_match)
            == exact_match,
{
}

pub proof fn lemma_wildcard_patterns_route_to_suffix_match(
    wildcard_suffix_match: bool,
    exact_match: bool,
)
    ensures
        spec_normalized_domain_pattern_matches(true, wildcard_suffix_match, exact_match)
            == wildcard_suffix_match,
{
}

pub proof fn lemma_exact_parent_rejects_child_wildcards(
    child_matches_parent_suffix: bool,
    exact_patterns_equal: bool,
)
    ensures
        !spec_normalized_domain_pattern_subset(
            false,
            true,
            child_matches_parent_suffix,
            exact_patterns_equal,
        ),
{
}

pub proof fn lemma_exact_parent_accepts_only_exact_equal_child()
    ensures
        spec_normalized_domain_pattern_subset(false, false, false, true),
        !spec_normalized_domain_pattern_subset(false, false, true, false),
{
}

pub proof fn lemma_wildcard_parent_accepts_matching_exact_or_wildcard_child()
    ensures
        spec_normalized_domain_pattern_subset(true, false, true, false),
        spec_normalized_domain_pattern_subset(true, true, true, false),
        !spec_normalized_domain_pattern_subset(true, false, false, true),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_domain_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
