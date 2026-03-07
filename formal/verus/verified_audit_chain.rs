// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified audit-chain verification kernel.
//!
//! This file proves the pure fail-closed guards extracted into
//! `vellaveto-audit/src/verified_audit_chain.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_audit_chain.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_timestamp_guard(is_utc: bool, timestamps_nondecreasing: bool) -> bool {
    is_utc && timestamps_nondecreasing
}

pub fn timestamp_guard(is_utc: bool, timestamps_nondecreasing: bool) -> (result: bool)
    ensures
        result == spec_timestamp_guard(is_utc, timestamps_nondecreasing),
        result ==> is_utc,
        result ==> timestamps_nondecreasing,
{
    is_utc && timestamps_nondecreasing
}

pub open spec fn spec_sequence_monotonic(
    has_prev_sequence: bool,
    prev_sequence: nat,
    current_sequence: nat,
) -> bool {
    current_sequence == 0 || !has_prev_sequence || current_sequence > prev_sequence
}

pub fn sequence_monotonic(
    has_prev_sequence: bool,
    prev_sequence: u64,
    current_sequence: u64,
) -> (result: bool)
    ensures
        result == spec_sequence_monotonic(
            has_prev_sequence,
            prev_sequence as nat,
            current_sequence as nat,
        ),
{
    current_sequence == 0 || !has_prev_sequence || current_sequence > prev_sequence
}

pub open spec fn spec_hash_presence_valid(
    seen_hashed_entry: bool,
    entry_has_hash: bool,
) -> bool {
    entry_has_hash || !seen_hashed_entry
}

pub fn hash_presence_valid(seen_hashed_entry: bool, entry_has_hash: bool) -> (result: bool)
    ensures
        result == spec_hash_presence_valid(seen_hashed_entry, entry_has_hash),
        seen_hashed_entry && !entry_has_hash ==> !result,
{
    entry_has_hash || !seen_hashed_entry
}

pub open spec fn spec_audit_chain_step_valid(
    timestamp_guard_ok: bool,
    sequence_guard_ok: bool,
    hash_presence_guard_ok: bool,
    entry_has_hash: bool,
    prev_hash_matches: bool,
    entry_hash_matches: bool,
) -> bool {
    timestamp_guard_ok
        && sequence_guard_ok
        && hash_presence_guard_ok
        && (!entry_has_hash || (prev_hash_matches && entry_hash_matches))
}

pub fn audit_chain_step_valid(
    timestamp_guard_ok: bool,
    sequence_guard_ok: bool,
    hash_presence_guard_ok: bool,
    entry_has_hash: bool,
    prev_hash_matches: bool,
    entry_hash_matches: bool,
) -> (result: bool)
    ensures
        result == spec_audit_chain_step_valid(
            timestamp_guard_ok,
            sequence_guard_ok,
            hash_presence_guard_ok,
            entry_has_hash,
            prev_hash_matches,
            entry_hash_matches,
        ),
        result ==> timestamp_guard_ok,
        result ==> sequence_guard_ok,
        result ==> hash_presence_guard_ok,
        entry_has_hash && result ==> prev_hash_matches,
        entry_has_hash && result ==> entry_hash_matches,
{
    timestamp_guard_ok
        && sequence_guard_ok
        && hash_presence_guard_ok
        && (!entry_has_hash || (prev_hash_matches && entry_hash_matches))
}

pub open spec fn spec_next_seen_hashed_entry(
    seen_hashed_entry: bool,
    entry_has_hash: bool,
) -> bool {
    seen_hashed_entry || entry_has_hash
}

pub fn next_seen_hashed_entry(seen_hashed_entry: bool, entry_has_hash: bool) -> (result: bool)
    ensures result == spec_next_seen_hashed_entry(seen_hashed_entry, entry_has_hash),
{
    seen_hashed_entry || entry_has_hash
}

pub open spec fn spec_next_prev_sequence(prev_sequence: nat, current_sequence: nat) -> nat {
    if current_sequence > 0 {
        current_sequence
    } else {
        prev_sequence
    }
}

pub fn next_prev_sequence(prev_sequence: u64, current_sequence: u64) -> (result: u64)
    ensures result as nat == spec_next_prev_sequence(prev_sequence as nat, current_sequence as nat),
{
    if current_sequence > 0 {
        current_sequence
    } else {
        prev_sequence
    }
}

pub proof fn lemma_non_utc_timestamp_rejected(timestamps_nondecreasing: bool)
    ensures !spec_timestamp_guard(false, timestamps_nondecreasing),
{
}

pub proof fn lemma_timestamp_regression_rejected(is_utc: bool)
    ensures !spec_timestamp_guard(is_utc, false),
{
}

pub proof fn lemma_legacy_zero_sequence_is_accepted(
    has_prev_sequence: bool,
    prev_sequence: nat,
)
    ensures spec_sequence_monotonic(has_prev_sequence, prev_sequence, 0),
{
}

pub proof fn lemma_sequence_regression_rejected(prev_sequence: nat, current_sequence: nat)
    requires current_sequence > 0, current_sequence <= prev_sequence
    ensures !spec_sequence_monotonic(true, prev_sequence, current_sequence),
{
}

pub proof fn lemma_unhashed_after_hashed_rejected()
    ensures !spec_hash_presence_valid(true, false),
{
}

pub proof fn lemma_legacy_prefix_unhashed_allowed()
    ensures spec_hash_presence_valid(false, false),
{
}

pub proof fn lemma_hashed_step_requires_link_and_hash(
    timestamp_guard_ok: bool,
    sequence_guard_ok: bool,
    hash_presence_guard_ok: bool,
    prev_hash_matches: bool,
    entry_hash_matches: bool,
)
    ensures
        spec_audit_chain_step_valid(
            timestamp_guard_ok,
            sequence_guard_ok,
            hash_presence_guard_ok,
            true,
            prev_hash_matches,
            entry_hash_matches,
        ) ==> prev_hash_matches && entry_hash_matches,
{
}

pub proof fn lemma_unhashed_step_ignores_hash_booleans(
    timestamp_guard_ok: bool,
    sequence_guard_ok: bool,
    hash_presence_guard_ok: bool,
    prev_hash_matches: bool,
    entry_hash_matches: bool,
)
    ensures
        spec_audit_chain_step_valid(
            timestamp_guard_ok,
            sequence_guard_ok,
            hash_presence_guard_ok,
            false,
            prev_hash_matches,
            entry_hash_matches,
        ) == (timestamp_guard_ok && sequence_guard_ok && hash_presence_guard_ok),
{
}

pub proof fn lemma_seen_hashed_latches_true(entry_has_hash: bool)
    ensures spec_next_seen_hashed_entry(true, entry_has_hash),
{
}

pub proof fn lemma_next_prev_sequence_preserves_legacy_zero(prev_sequence: nat)
    ensures spec_next_prev_sequence(prev_sequence, 0) == prev_sequence,
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::audit_chain_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
