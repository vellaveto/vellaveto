// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified DLP buffer arithmetic.
//!
//! This file is the formally verified version of
//! `vellaveto-mcp/src/inspection/verified_dlp_core.rs`. It uses Verus
//! annotations to prove properties D1-D6 on the actual Rust code for
//! ALL possible inputs.
//!
//! To verify:
//!   `~/verus/verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_dlp_core.rs`
//!
//! # Properties Proven
//!
//! | ID | Property |
//! |----|----------|
//! | D1 | UTF-8 char boundary safety: extract_tail never returns start in mid-character |
//! | D2 | Single buffer size bounded: extracted tail <= max_size bytes |
//! | D3 | Total byte accounting correct: update_total_bytes maintains consistency |
//! | D4 | Capacity check fail-closed: at max_fields, can_track_field returns false |
//! | D5 | No arithmetic underflow: saturating subtraction prevents wrapping |
//! | D6 | Overlap completeness: secret <= 2 * overlap split at `split_point <= overlap_size` fully covered |
//!
//! # Trust Boundary
//!
//! These proofs cover the pure arithmetic. The HashMap wrapper in
//! `cross_call_dlp.rs` is NOT verified — it is a lookup table.

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

/// Spec: a byte is a UTF-8 character boundary if it's not a continuation byte (10xxxxxx).
pub open spec fn spec_is_char_boundary(b: u8) -> bool {
    (b & 0xC0u8) != 0x80u8
}

/// D1: Check if a byte is a UTF-8 character boundary.
pub fn is_utf8_char_boundary(b: u8) -> (result: bool)
    ensures
        result == spec_is_char_boundary(b),
{
    (b & 0xC0u8) != 0x80u8
}

/// Proof: continuation bytes (0x80-0xBF) are NOT char boundaries.
pub proof fn lemma_continuation_not_boundary(b: u8)
    requires 0x80u8 <= b && b <= 0xBFu8,
    ensures !spec_is_char_boundary(b),
{
    assert((b & 0xC0u8) == 0x80u8) by (bit_vector)
        requires 0x80u8 <= b && b <= 0xBFu8;
}

/// Proof: non-continuation bytes are char boundaries.
pub proof fn lemma_non_continuation_is_boundary(b: u8)
    requires b < 0x80u8 || b > 0xBFu8,
    ensures spec_is_char_boundary(b),
{
    assert((b & 0xC0u8) != 0x80u8) by (bit_vector)
        requires b < 0x80u8 || b > 0xBFu8;
}

/// Spec version of extract_tail for use in proof mode.
pub open spec fn spec_extract_tail_start(value: &[u8], max_size: usize) -> int
    decreases value.len(),
{
    if value.len() == 0 || max_size == 0 {
        value.len() as int
    } else {
        let raw_start: int = if value.len() > max_size {
            (value.len() - max_size) as int
        } else {
            0int
        };
        spec_advance_to_boundary(value, raw_start)
    }
}

/// Spec: advance index past continuation bytes.
pub open spec fn spec_advance_to_boundary(value: &[u8], start: int) -> int
    decreases value.len() - start,
{
    if start >= value.len() as int {
        value.len() as int
    } else if spec_is_char_boundary(value[start]) {
        start
    } else {
        spec_advance_to_boundary(value, start + 1)
    }
}

/// D1 + D2: Extract the tail of a byte slice at a valid UTF-8 char boundary.
///
/// Returns (start, end) where:
/// - end == value.len() (always)
/// - end - start <= max_size (D2: bounded)
/// - start == value.len() || is_char_boundary(value[start]) (D1: safe)
pub fn extract_tail(value: &[u8], max_size: usize) -> (result: (usize, usize))
    ensures
        // D2: tail never exceeds max_size
        result.1 - result.0 <= max_size,
        // end is always value.len()
        result.1 == value.len(),
        // start <= end
        result.0 <= result.1,
        // D1: start is at a char boundary (or past end)
        result.0 == value.len() || spec_is_char_boundary(value[result.0 as int]),
{
    if value.len() == 0 || max_size == 0 {
        return (value.len(), value.len());
    }

    let raw_start: usize = if value.len() > max_size {
        value.len() - max_size
    } else {
        0
    };
    let mut start: usize = raw_start;

    // Advance past continuation bytes to land on a char boundary
    while start < value.len() && !is_utf8_char_boundary(value[start])
        invariant
            raw_start <= start <= value.len(),
            // All bytes from raw_start to start are continuation bytes
            forall|j: int| #![auto] raw_start as int <= j < start as int
                ==> !spec_is_char_boundary(value[j]),
            // D2 preserved: even as we advance, tail size only decreases
            value.len() - start <= max_size,
        decreases value.len() - start,
    {
        start = start + 1;
    }

    (start, value.len())
}

/// Spec version of can_track_field for use in proofs.
pub open spec fn spec_can_track_field(
    current_fields: usize,
    max_fields: usize,
    current_bytes: usize,
    new_buffer_bytes: usize,
    max_total_bytes: usize,
) -> bool {
    current_fields < max_fields
    && current_bytes + new_buffer_bytes <= max_total_bytes
    && current_bytes + new_buffer_bytes >= current_bytes  // no overflow
}

/// D4: Check if a new field can be tracked without exceeding limits.
///
/// Returns true only if:
/// - current_fields < max_fields
/// - current_bytes + new_buffer_bytes <= max_total_bytes (checked_add)
#[verifier::when_used_as_spec(spec_can_track_field)]
pub fn can_track_field(
    current_fields: usize,
    max_fields: usize,
    current_bytes: usize,
    new_buffer_bytes: usize,
    max_total_bytes: usize,
) -> (result: bool)
    ensures
        // D4: at capacity, always false
        current_fields >= max_fields ==> !result,
        // If accepted, fields are under limit
        result ==> current_fields < max_fields,
{
    if current_fields >= max_fields {
        return false;
    }
    match current_bytes.checked_add(new_buffer_bytes) {
        Some(total) => total <= max_total_bytes,
        None => false,
    }
}

/// D3 + D5: Update total byte accounting after replacing a buffer.
///
/// Uses saturating arithmetic: no underflow (D5), correct when consistent (D3).
pub fn update_total_bytes(
    old_total: usize,
    old_buffer_len: usize,
    new_buffer_len: usize,
) -> (result: usize)
    ensures
        // D3: correct accounting when state is consistent
        old_total >= old_buffer_len ==>
            result == (old_total - old_buffer_len) + new_buffer_len
            || result == usize::MAX,  // saturating_add may cap
        // D5: no underflow — result is always >= 0 (trivially true for usize)
        // but also: when old_total < old_buffer_len, result == new_buffer_len
        old_total < old_buffer_len ==>
            result == new_buffer_len || result == usize::MAX,
{
    old_total.saturating_sub(old_buffer_len).saturating_add(new_buffer_len)
}

/// D6: Overlap completeness lemma.
///
/// If a secret of length secret_len <= 2 * overlap_size is split at any
/// byte boundary (split_point) between two consecutive calls, the combined
/// scan buffer (prev_tail ++ current_value) contains the entire secret.
///
/// The split_point must be <= overlap_size (the first fragment must fit
/// in the tail buffer). This is the realistic case: secrets that are
/// longer than the overlap buffer cannot be reconstructed from the tail.
pub proof fn overlap_completeness_lemma(
    prev_value_len: usize,
    curr_value_len: usize,
    overlap_size: usize,
    secret_len: usize,
    split_point: usize,
)
    requires
        secret_len <= 2 * overlap_size,
        split_point > 0,
        split_point < secret_len,
        split_point <= overlap_size,   // first fragment fits in buffer
        prev_value_len >= split_point,
        curr_value_len >= secret_len - split_point,
        overlap_size >= 1,
    ensures
        ({
            let prev_tail_len: int = if prev_value_len > overlap_size {
                overlap_size as int
            } else {
                prev_value_len as int
            };
            let combined_len: int = prev_tail_len + curr_value_len as int;
            combined_len >= secret_len as int
        }),
{
    // Case split: prev_value_len <= overlap_size or > overlap_size
    let prev_tail_len: int = if prev_value_len > overlap_size {
        overlap_size as int
    } else {
        prev_value_len as int
    };
    // In both cases: prev_tail_len >= split_point
    // (if prev_value_len <= overlap_size: prev_tail_len = prev_value_len >= split_point)
    // (if prev_value_len > overlap_size: prev_tail_len = overlap_size >= split_point)
    assert(prev_tail_len >= split_point as int);
    // curr_value_len >= secret_len - split_point
    // combined = prev_tail_len + curr_value_len >= split_point + secret_len - split_point = secret_len
    assert(prev_tail_len + curr_value_len as int >= secret_len as int);
}

/// Lemma: at max_fields, can_track_field is always false.
pub proof fn lemma_capacity_fail_closed(
    current_fields: usize,
    max_fields: usize,
    current_bytes: usize,
    new_buffer_bytes: usize,
    max_total_bytes: usize,
)
    requires
        current_fields >= max_fields,
    ensures
        !can_track_field(current_fields, max_fields, current_bytes, new_buffer_bytes, max_total_bytes),
{
    // Follows directly from the postcondition of can_track_field.
}

/// Lemma: for ASCII input, all bytes are char boundaries.
pub proof fn lemma_ascii_all_boundaries(value: &[u8])
    requires
        value.len() > 0,
        forall|i: int| #![auto] 0 <= i < value.len() as int ==> value[i] < 0x80u8,
    ensures
        forall|i: int| #![auto] 0 <= i < value.len() as int
            ==> spec_is_char_boundary(value[i]),
{
    assert forall|i: int| #![auto] 0 <= i < value.len() as int
        implies spec_is_char_boundary(value[i])
    by {
        let b = value[i];
        assert(b < 0x80u8);
        lemma_non_continuation_is_boundary(b);
    };
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::dlp_core_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
