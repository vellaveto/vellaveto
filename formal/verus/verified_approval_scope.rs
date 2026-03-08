// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified approval scope-binding guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-approval/src/verified_approval_scope.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_approval_scope.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_approval_session_binding_satisfied(
    approval_has_session_binding: bool,
    request_has_session: bool,
    request_matches_bound_session: bool,
) -> bool {
    !approval_has_session_binding || (request_has_session && request_matches_bound_session)
}

pub fn approval_session_binding_satisfied(
    approval_has_session_binding: bool,
    request_has_session: bool,
    request_matches_bound_session: bool,
) -> (result: bool)
    ensures
        result
            == spec_approval_session_binding_satisfied(
                approval_has_session_binding,
                request_has_session,
                request_matches_bound_session,
            ),
        approval_has_session_binding && !request_has_session ==> !result,
        approval_has_session_binding && request_has_session && !request_matches_bound_session ==> !result,
        approval_has_session_binding && request_has_session && request_matches_bound_session ==> result,
{
    !approval_has_session_binding || (request_has_session && request_matches_bound_session)
}

pub open spec fn spec_approval_fingerprint_binding_satisfied(
    approval_has_action_fingerprint_binding: bool,
    request_has_action_fingerprint: bool,
    request_matches_bound_fingerprint: bool,
) -> bool {
    !approval_has_action_fingerprint_binding
        || (request_has_action_fingerprint && request_matches_bound_fingerprint)
}

pub fn approval_fingerprint_binding_satisfied(
    approval_has_action_fingerprint_binding: bool,
    request_has_action_fingerprint: bool,
    request_matches_bound_fingerprint: bool,
) -> (result: bool)
    ensures
        result
            == spec_approval_fingerprint_binding_satisfied(
                approval_has_action_fingerprint_binding,
                request_has_action_fingerprint,
                request_matches_bound_fingerprint,
            ),
        approval_has_action_fingerprint_binding && !request_has_action_fingerprint ==> !result,
        approval_has_action_fingerprint_binding
            && request_has_action_fingerprint
            && !request_matches_bound_fingerprint ==> !result,
        approval_has_action_fingerprint_binding
            && request_has_action_fingerprint
            && request_matches_bound_fingerprint ==> result,
{
    !approval_has_action_fingerprint_binding
        || (request_has_action_fingerprint && request_matches_bound_fingerprint)
}

pub open spec fn spec_approval_scope_binding_satisfied(
    approval_has_session_binding: bool,
    request_has_session: bool,
    request_matches_bound_session: bool,
    approval_has_action_fingerprint_binding: bool,
    request_has_action_fingerprint: bool,
    request_matches_bound_fingerprint: bool,
) -> bool {
    spec_approval_session_binding_satisfied(
        approval_has_session_binding,
        request_has_session,
        request_matches_bound_session,
    ) && spec_approval_fingerprint_binding_satisfied(
        approval_has_action_fingerprint_binding,
        request_has_action_fingerprint,
        request_matches_bound_fingerprint,
    )
}

pub fn approval_scope_binding_satisfied(
    approval_has_session_binding: bool,
    request_has_session: bool,
    request_matches_bound_session: bool,
    approval_has_action_fingerprint_binding: bool,
    request_has_action_fingerprint: bool,
    request_matches_bound_fingerprint: bool,
) -> (result: bool)
    ensures
        result
            == spec_approval_scope_binding_satisfied(
                approval_has_session_binding,
                request_has_session,
                request_matches_bound_session,
                approval_has_action_fingerprint_binding,
                request_has_action_fingerprint,
                request_matches_bound_fingerprint,
            ),
        !spec_approval_session_binding_satisfied(
            approval_has_session_binding,
            request_has_session,
            request_matches_bound_session,
        ) ==> !result,
        !spec_approval_fingerprint_binding_satisfied(
            approval_has_action_fingerprint_binding,
            request_has_action_fingerprint,
            request_matches_bound_fingerprint,
        ) ==> !result,
{
    approval_session_binding_satisfied(
        approval_has_session_binding,
        request_has_session,
        request_matches_bound_session,
    ) && approval_fingerprint_binding_satisfied(
        approval_has_action_fingerprint_binding,
        request_has_action_fingerprint,
        request_matches_bound_fingerprint,
    )
}

pub proof fn lemma_bound_session_binding_requires_present_match()
    ensures
        !spec_approval_session_binding_satisfied(true, false, false),
        !spec_approval_session_binding_satisfied(true, true, false),
        spec_approval_session_binding_satisfied(true, true, true),
{
}

pub proof fn lemma_bound_fingerprint_binding_requires_present_match()
    ensures
        !spec_approval_fingerprint_binding_satisfied(true, false, false),
        !spec_approval_fingerprint_binding_satisfied(true, true, false),
        spec_approval_fingerprint_binding_satisfied(true, true, true),
{
}

pub proof fn lemma_scope_requires_all_bound_dimensions()
    ensures
        spec_approval_scope_binding_satisfied(false, false, false, false, false, false),
        spec_approval_scope_binding_satisfied(true, true, true, true, true, true),
        !spec_approval_scope_binding_satisfied(true, false, false, false, false, false),
        !spec_approval_scope_binding_satisfied(false, false, false, true, false, false),
        !spec_approval_scope_binding_satisfied(true, true, true, true, true, false),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::approval_scope_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
