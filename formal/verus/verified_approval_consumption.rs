// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified approval-consumption guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-approval/src/verified_approval_consumption.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_approval_consumption.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_approval_status_allows_consumption(approval_is_approved: bool) -> bool {
    approval_is_approved
}

pub fn approval_status_allows_consumption(approval_is_approved: bool) -> (result: bool)
    ensures
        result == spec_approval_status_allows_consumption(approval_is_approved),
        !approval_is_approved ==> !result,
        approval_is_approved ==> result,
{
    approval_is_approved
}

pub open spec fn spec_approval_binding_allows_consumption(
    approval_has_action_fingerprint_binding: bool,
    request_scope_matches_binding: bool,
) -> bool {
    approval_has_action_fingerprint_binding && request_scope_matches_binding
}

pub fn approval_binding_allows_consumption(
    approval_has_action_fingerprint_binding: bool,
    request_scope_matches_binding: bool,
) -> (result: bool)
    ensures
        result
            == spec_approval_binding_allows_consumption(
                approval_has_action_fingerprint_binding,
                request_scope_matches_binding,
            ),
        !approval_has_action_fingerprint_binding ==> !result,
        approval_has_action_fingerprint_binding && !request_scope_matches_binding ==> !result,
        approval_has_action_fingerprint_binding && request_scope_matches_binding ==> result,
{
    approval_has_action_fingerprint_binding && request_scope_matches_binding
}

pub open spec fn spec_approval_consumption_permitted(
    approval_is_approved: bool,
    approval_has_action_fingerprint_binding: bool,
    request_scope_matches_binding: bool,
) -> bool {
    spec_approval_status_allows_consumption(approval_is_approved)
        && spec_approval_binding_allows_consumption(
            approval_has_action_fingerprint_binding,
            request_scope_matches_binding,
        )
}

pub fn approval_consumption_permitted(
    approval_is_approved: bool,
    approval_has_action_fingerprint_binding: bool,
    request_scope_matches_binding: bool,
) -> (result: bool)
    ensures
        result
            == spec_approval_consumption_permitted(
                approval_is_approved,
                approval_has_action_fingerprint_binding,
                request_scope_matches_binding,
            ),
        !approval_is_approved ==> !result,
        !approval_has_action_fingerprint_binding ==> !result,
        !request_scope_matches_binding ==> !result,
        approval_is_approved
            && approval_has_action_fingerprint_binding
            && request_scope_matches_binding ==> result,
{
    approval_status_allows_consumption(approval_is_approved)
        && approval_binding_allows_consumption(
            approval_has_action_fingerprint_binding,
            request_scope_matches_binding,
        )
}

pub proof fn lemma_consumption_requires_approved_bound_matching_scope()
    ensures
        !spec_approval_consumption_permitted(false, true, true),
        !spec_approval_consumption_permitted(true, false, true),
        !spec_approval_consumption_permitted(true, true, false),
        spec_approval_consumption_permitted(true, true, true),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::approval_consumption_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
