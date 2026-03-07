// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified cross-call DLP tracker state kernel.
//!
//! This file proves the pure field-capacity/update decisions extracted into
//! `vellaveto-mcp/src/inspection/verified_cross_call_dlp.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_cross_call_dlp.rs`

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub const USIZE_MAX_VALUE: usize = usize::MAX;

pub open spec fn spec_should_emit_capacity_exhausted_finding(
    field_exists: bool,
    tracked_fields: nat,
    max_fields: nat,
) -> bool {
    !field_exists && tracked_fields >= max_fields
}

pub fn should_emit_capacity_exhausted_finding(
    field_exists: bool,
    tracked_fields: usize,
    max_fields: usize,
) -> (result: bool)
    ensures
        result == spec_should_emit_capacity_exhausted_finding(
            field_exists,
            tracked_fields as nat,
            max_fields as nat,
        ),
        field_exists ==> !result,
        !field_exists && (tracked_fields as nat) >= (max_fields as nat) ==> result,
{
    !field_exists && tracked_fields >= max_fields
}

pub open spec fn spec_should_update_buffer(
    field_exists: bool,
    tracked_fields: nat,
    max_fields: nat,
    current_bytes: nat,
    new_buffer_bytes: nat,
    max_total_bytes: nat,
) -> bool {
    field_exists || (
        tracked_fields < max_fields
        && current_bytes + new_buffer_bytes <= max_total_bytes
        && current_bytes + new_buffer_bytes <= USIZE_MAX_VALUE as nat
    )
}

pub fn should_update_buffer(
    field_exists: bool,
    tracked_fields: usize,
    max_fields: usize,
    current_bytes: usize,
    new_buffer_bytes: usize,
    max_total_bytes: usize,
) -> (result: bool)
    ensures
        result == spec_should_update_buffer(
            field_exists,
            tracked_fields as nat,
            max_fields as nat,
            current_bytes as nat,
            new_buffer_bytes as nat,
            max_total_bytes as nat,
        ),
        field_exists ==> result,
        !field_exists && (tracked_fields as nat) >= (max_fields as nat) ==> !result,
{
    if field_exists {
        true
    } else {
        match current_bytes.checked_add(new_buffer_bytes) {
            Some(total) => tracked_fields < max_fields && total <= max_total_bytes,
            None => false,
        }
    }
}

pub proof fn lemma_existing_field_never_emits_capacity_finding(
    tracked_fields: nat,
    max_fields: nat,
)
    ensures !spec_should_emit_capacity_exhausted_finding(true, tracked_fields, max_fields),
{
}

pub proof fn lemma_existing_field_always_updates(
    tracked_fields: nat,
    max_fields: nat,
    current_bytes: nat,
    new_buffer_bytes: nat,
    max_total_bytes: nat,
)
    ensures spec_should_update_buffer(
        true,
        tracked_fields,
        max_fields,
        current_bytes,
        new_buffer_bytes,
        max_total_bytes,
    ),
{
}

pub proof fn lemma_new_field_at_capacity_emits_and_blocks_update(
    tracked_fields: nat,
    max_fields: nat,
    current_bytes: nat,
    new_buffer_bytes: nat,
    max_total_bytes: nat,
)
    requires tracked_fields >= max_fields,
    ensures
        spec_should_emit_capacity_exhausted_finding(false, tracked_fields, max_fields),
        !spec_should_update_buffer(
            false,
            tracked_fields,
            max_fields,
            current_bytes,
            new_buffer_bytes,
            max_total_bytes,
        ),
{
}

pub proof fn lemma_new_field_below_capacity_with_budget_updates(
    tracked_fields: nat,
    max_fields: nat,
    current_bytes: nat,
    new_buffer_bytes: nat,
    max_total_bytes: nat,
)
    requires
        tracked_fields < max_fields,
        current_bytes + new_buffer_bytes <= max_total_bytes,
        current_bytes + new_buffer_bytes <= USIZE_MAX_VALUE as nat,
    ensures
        spec_should_update_buffer(
            false,
            tracked_fields,
            max_fields,
            current_bytes,
            new_buffer_bytes,
            max_total_bytes,
        ),
{
}

pub proof fn lemma_capacity_finding_implies_update_blocked(
    tracked_fields: nat,
    max_fields: nat,
    current_bytes: nat,
    new_buffer_bytes: nat,
    max_total_bytes: nat,
)
    ensures
        spec_should_emit_capacity_exhausted_finding(false, tracked_fields, max_fields) ==>
            !spec_should_update_buffer(
                false,
                tracked_fields,
                max_fields,
                current_bytes,
                new_buffer_bytes,
                max_total_bytes,
            ),
{
    if spec_should_emit_capacity_exhausted_finding(false, tracked_fields, max_fields) {
        assert(tracked_fields >= max_fields);
    }
}

fn main() {}

} // verus!
