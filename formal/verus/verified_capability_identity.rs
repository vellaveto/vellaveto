// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability identity-chain boundary.
//!
//! This file proves the normalized holder/issuer checks extracted into
//! `vellaveto-mcp/src/verified_capability_identity.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_identity.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_delegation_holder_distinct(
    normalized_new_equals_parent_holder_ignore_ascii_case: bool,
) -> bool {
    !normalized_new_equals_parent_holder_ignore_ascii_case
}

pub fn delegation_holder_distinct(
    normalized_new_equals_parent_holder_ignore_ascii_case: bool,
) -> (result: bool)
    ensures
        result == spec_delegation_holder_distinct(
            normalized_new_equals_parent_holder_ignore_ascii_case,
        ),
        normalized_new_equals_parent_holder_ignore_ascii_case ==> !result,
{
    !normalized_new_equals_parent_holder_ignore_ascii_case
}

pub open spec fn spec_delegated_child_issuer_valid(
    child_has_parent: bool,
    child_issuer_equals_parent_holder: bool,
) -> bool {
    !child_has_parent || child_issuer_equals_parent_holder
}

pub fn delegated_child_issuer_valid(
    child_has_parent: bool,
    child_issuer_equals_parent_holder: bool,
) -> (result: bool)
    ensures
        result == spec_delegated_child_issuer_valid(
            child_has_parent,
            child_issuer_equals_parent_holder,
        ),
        child_has_parent && result ==> child_issuer_equals_parent_holder,
{
    !child_has_parent || child_issuer_equals_parent_holder
}

pub open spec fn spec_holder_expectation_satisfied(
    normalized_holder_equals_expected: bool,
) -> bool {
    normalized_holder_equals_expected
}

pub fn holder_expectation_satisfied(
    normalized_holder_equals_expected: bool,
) -> (result: bool)
    ensures
        result == spec_holder_expectation_satisfied(normalized_holder_equals_expected),
{
    normalized_holder_equals_expected
}

pub proof fn lemma_self_delegation_is_rejected()
    ensures !spec_delegation_holder_distinct(true),
{
}

pub proof fn lemma_distinct_holder_is_allowed()
    ensures spec_delegation_holder_distinct(false),
{
}

pub proof fn lemma_root_token_issuer_is_unconstrained(
    child_issuer_equals_parent_holder: bool,
)
    ensures spec_delegated_child_issuer_valid(false, child_issuer_equals_parent_holder),
{
}

pub proof fn lemma_delegated_child_requires_parent_holder_issuer()
    ensures !spec_delegated_child_issuer_valid(true, false),
{
}

pub proof fn lemma_matching_holder_expectation_is_required()
    ensures
        spec_holder_expectation_satisfied(true),
        !spec_holder_expectation_satisfied(false),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_identity_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
