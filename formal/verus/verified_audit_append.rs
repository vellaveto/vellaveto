// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified audit append/recovery counter kernel.
//!
//! This file proves the pure counter transitions extracted into
//! `vellaveto-audit/src/verified_audit_append.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_audit_append.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub const U64_MAX_VALUE: u64 = u64::MAX;

pub open spec fn spec_entry_count_after_rotation() -> nat {
    0
}

pub fn entry_count_after_rotation() -> (result: u64)
    ensures result as nat == spec_entry_count_after_rotation(),
{
    0
}

pub open spec fn spec_assigned_sequence(global_sequence: nat) -> nat {
    global_sequence
}

pub fn assigned_sequence(global_sequence: u64) -> (result: u64)
    ensures result as nat == spec_assigned_sequence(global_sequence as nat),
{
    global_sequence
}

pub open spec fn spec_next_entry_count(current_entry_count: nat) -> nat {
    if current_entry_count >= U64_MAX_VALUE as nat {
        U64_MAX_VALUE as nat
    } else {
        current_entry_count + 1
    }
}

pub fn next_entry_count(current_entry_count: u64) -> (result: u64)
    ensures
        result as nat == spec_next_entry_count(current_entry_count as nat),
        (current_entry_count as nat) < U64_MAX_VALUE as nat ==> result as nat == (current_entry_count as nat) + 1,
        (current_entry_count as nat) >= U64_MAX_VALUE as nat ==> result == U64_MAX_VALUE,
{
    current_entry_count.saturating_add(1)
}

pub open spec fn spec_next_global_sequence(current_global_sequence: nat) -> nat {
    if current_global_sequence >= U64_MAX_VALUE as nat {
        U64_MAX_VALUE as nat
    } else {
        current_global_sequence + 1
    }
}

pub fn next_global_sequence(current_global_sequence: u64) -> (result: u64)
    ensures
        result as nat == spec_next_global_sequence(current_global_sequence as nat),
        (current_global_sequence as nat) < U64_MAX_VALUE as nat ==> result as nat == (current_global_sequence as nat) + 1,
        (current_global_sequence as nat) >= U64_MAX_VALUE as nat ==> result == U64_MAX_VALUE,
{
    current_global_sequence.saturating_add(1)
}

pub open spec fn spec_next_sequence_after_recovery(max_observed_sequence: nat) -> nat {
    if max_observed_sequence >= U64_MAX_VALUE as nat {
        U64_MAX_VALUE as nat
    } else {
        max_observed_sequence + 1
    }
}

pub fn next_sequence_after_recovery(max_observed_sequence: u64) -> (result: u64)
    ensures
        result as nat == spec_next_sequence_after_recovery(max_observed_sequence as nat),
        (max_observed_sequence as nat) < U64_MAX_VALUE as nat ==> result as nat == (max_observed_sequence as nat) + 1,
        (max_observed_sequence as nat) >= U64_MAX_VALUE as nat ==> result == U64_MAX_VALUE,
{
    max_observed_sequence.saturating_add(1)
}

pub proof fn lemma_rotation_resets_entry_count()
    ensures spec_entry_count_after_rotation() == 0,
{
}

pub proof fn lemma_rotation_then_append_yields_one()
    ensures spec_next_entry_count(spec_entry_count_after_rotation()) == 1,
{
}

pub proof fn lemma_assigned_sequence_is_identity(global_sequence: nat)
    ensures spec_assigned_sequence(global_sequence) == global_sequence,
{
}

pub proof fn lemma_entry_count_increments_when_not_saturated(current_entry_count: nat)
    requires current_entry_count < U64_MAX_VALUE as nat
    ensures spec_next_entry_count(current_entry_count) == current_entry_count + 1,
{
}

pub proof fn lemma_entry_count_saturates_at_u64_max()
    ensures spec_next_entry_count(U64_MAX_VALUE as nat) == U64_MAX_VALUE as nat,
{
}

pub proof fn lemma_global_sequence_increments_when_not_saturated(current_global_sequence: nat)
    requires current_global_sequence < U64_MAX_VALUE as nat
    ensures spec_next_global_sequence(current_global_sequence) == current_global_sequence + 1,
{
}

pub proof fn lemma_global_sequence_saturates_at_u64_max()
    ensures spec_next_global_sequence(U64_MAX_VALUE as nat) == U64_MAX_VALUE as nat,
{
}

pub proof fn lemma_assigned_sequence_precedes_next_global_sequence(current_global_sequence: nat)
    requires current_global_sequence <= U64_MAX_VALUE as nat
    ensures spec_assigned_sequence(current_global_sequence) <= spec_next_global_sequence(current_global_sequence),
{
}

pub proof fn lemma_recovery_sequence_advances_when_not_saturated(max_observed_sequence: nat)
    requires max_observed_sequence < U64_MAX_VALUE as nat
    ensures spec_next_sequence_after_recovery(max_observed_sequence) == max_observed_sequence + 1,
{
}

pub proof fn lemma_recovery_sequence_saturates_at_u64_max()
    ensures spec_next_sequence_after_recovery(U64_MAX_VALUE as nat) == U64_MAX_VALUE as nat,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::audit_append_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
