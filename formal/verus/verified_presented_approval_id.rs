// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified presented-approval-id validation guards.
//!
//! This file proves the extracted predicates in
//! `vellaveto-approval/src/verified_presented_approval_id.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_presented_approval_id.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_max_presented_approval_id_len() -> nat {
    256
}

pub open spec fn spec_presented_approval_id_length_valid(len: nat) -> bool {
    len <= spec_max_presented_approval_id_len()
}

pub fn presented_approval_id_length_valid(len: usize) -> (result: bool)
    ensures
        result == spec_presented_approval_id_length_valid(len as nat),
        len as nat > spec_max_presented_approval_id_len() ==> !result,
        len as nat <= spec_max_presented_approval_id_len() ==> result,
{
    len <= 256
}

pub open spec fn spec_presented_approval_id_value_accepted(
    length_valid: bool,
    contains_dangerous_chars: bool,
) -> bool {
    length_valid && !contains_dangerous_chars
}

pub fn presented_approval_id_value_accepted(
    length_valid: bool,
    contains_dangerous_chars: bool,
) -> (result: bool)
    ensures
        result
            == spec_presented_approval_id_value_accepted(
                length_valid,
                contains_dangerous_chars,
            ),
        !length_valid ==> !result,
        contains_dangerous_chars ==> !result,
        length_valid && !contains_dangerous_chars ==> result,
{
    length_valid && !contains_dangerous_chars
}

pub proof fn lemma_presented_approval_id_requires_safe_bounded_value()
    ensures
        spec_presented_approval_id_length_valid(0),
        spec_presented_approval_id_length_valid(1),
        spec_presented_approval_id_length_valid(spec_max_presented_approval_id_len()),
        !spec_presented_approval_id_length_valid(spec_max_presented_approval_id_len() + 1),
        spec_presented_approval_id_value_accepted(true, false),
        !spec_presented_approval_id_value_accepted(false, false),
        !spec_presented_approval_id_value_accepted(true, true),
        !spec_presented_approval_id_value_accepted(false, true),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::presented_approval_id_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
