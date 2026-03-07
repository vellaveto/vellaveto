// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability pattern attenuation guard.
//!
//! This file proves the conservative child-glob rejection rule extracted into
//! `vellaveto-mcp/src/verified_capability_pattern.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_pattern.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_has_glob_metacharacters(pattern: Seq<u8>) -> bool
{
    spec_has_glob_metacharacters_from(pattern, 0)
}

pub open spec fn spec_has_glob_metacharacters_from(pattern: Seq<u8>, start: nat) -> bool
    decreases pattern.len() - start
{
    if start >= pattern.len() {
        false
    } else {
        pattern[start as int] == 0x2a
            || pattern[start as int] == 0x3f
            || spec_has_glob_metacharacters_from(pattern, start + 1)
    }
}

fn has_glob_metacharacters_from(pattern: &Vec<u8>, start: usize) -> (result: bool)
    requires start <= pattern.len()
    ensures result == spec_has_glob_metacharacters_from(pattern@, start as nat)
    decreases pattern.len() - start
{
    if start == pattern.len() {
        false
    } else if pattern[start] == 0x2a || pattern[start] == 0x3f {
        true
    } else {
        has_glob_metacharacters_from(pattern, start + 1)
    }
}

pub fn has_glob_metacharacters(pattern: Vec<u8>) -> (result: bool)
    ensures result == spec_has_glob_metacharacters(pattern@),
{
    has_glob_metacharacters_from(&pattern, 0)
}

pub open spec fn spec_pattern_subset_guard(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
) -> bool {
    parent_is_wildcard || parent_equals_child_ignore_ascii_case || !child_has_metacharacters
}

pub fn pattern_subset_guard(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
    child_has_metacharacters: bool,
) -> (result: bool)
    ensures
        result == spec_pattern_subset_guard(
            parent_is_wildcard,
            parent_equals_child_ignore_ascii_case,
            child_has_metacharacters,
        ),
        !parent_is_wildcard && !parent_equals_child_ignore_ascii_case && child_has_metacharacters ==> !result,
        child_has_metacharacters && result ==> parent_is_wildcard || parent_equals_child_ignore_ascii_case,
{
    parent_is_wildcard || parent_equals_child_ignore_ascii_case || !child_has_metacharacters
}

pub proof fn lemma_non_identical_child_glob_rejected()
    ensures !spec_pattern_subset_guard(false, false, true),
{
}

pub proof fn lemma_wildcard_parent_allows_child_glob()
    ensures spec_pattern_subset_guard(true, false, true),
{
}

pub proof fn lemma_identical_child_glob_allowed()
    ensures spec_pattern_subset_guard(false, true, true),
{
}

pub proof fn lemma_literal_child_falls_through()
    ensures spec_pattern_subset_guard(false, false, false),
{
}

pub proof fn lemma_accepted_child_glob_requires_wildcard_or_equality(
    parent_is_wildcard: bool,
    parent_equals_child_ignore_ascii_case: bool,
)
    ensures
        spec_pattern_subset_guard(parent_is_wildcard, parent_equals_child_ignore_ascii_case, true)
            ==> parent_is_wildcard || parent_equals_child_ignore_ascii_case,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_pattern_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
