// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability-token verification precheck boundary.
//!
//! This file proves the pure fail-closed guards extracted into
//! `vellaveto-mcp/src/verified_capability_verification.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_verification.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub open spec fn spec_capability_not_expired(now_before_expires: bool) -> bool {
    now_before_expires
}

pub fn capability_not_expired(now_before_expires: bool) -> (result: bool)
    ensures result == spec_capability_not_expired(now_before_expires),
{
    now_before_expires
}

pub open spec fn spec_capability_issued_at_within_skew(
    issued_at_skew_secs: int,
    max_issued_at_skew_secs: int,
) -> bool {
    issued_at_skew_secs <= max_issued_at_skew_secs
}

pub fn capability_issued_at_within_skew(
    issued_at_skew_secs: i64,
    max_issued_at_skew_secs: i64,
) -> (result: bool)
    ensures
        result == spec_capability_issued_at_within_skew(
            issued_at_skew_secs as int,
            max_issued_at_skew_secs as int,
        ),
{
    issued_at_skew_secs <= max_issued_at_skew_secs
}

pub open spec fn spec_capability_expected_public_key_matches(
    expected_key_equals_token_key: bool,
) -> bool {
    expected_key_equals_token_key
}

pub fn capability_expected_public_key_matches(
    expected_key_equals_token_key: bool,
) -> (result: bool)
    ensures
        result
            == spec_capability_expected_public_key_matches(expected_key_equals_token_key),
{
    expected_key_equals_token_key
}

pub open spec fn spec_capability_public_key_length_valid(public_key_len: nat) -> bool {
    public_key_len == 32
}

pub fn capability_public_key_length_valid(public_key_len: usize) -> (result: bool)
    ensures
        result == spec_capability_public_key_length_valid(public_key_len as nat),
{
    public_key_len == 32
}

pub open spec fn spec_capability_signature_length_valid(signature_len: nat) -> bool {
    signature_len == 64
}

pub fn capability_signature_length_valid(signature_len: usize) -> (result: bool)
    ensures
        result == spec_capability_signature_length_valid(signature_len as nat),
{
    signature_len == 64
}

pub proof fn lemma_expired_tokens_are_rejected()
    ensures !spec_capability_not_expired(false),
{
}

pub proof fn lemma_unexpired_tokens_are_allowed()
    ensures spec_capability_not_expired(true),
{
}

pub proof fn lemma_future_issued_at_beyond_skew_is_rejected(
    issued_at_skew_secs: int,
    max_issued_at_skew_secs: int,
)
    requires issued_at_skew_secs > max_issued_at_skew_secs,
    ensures
        !spec_capability_issued_at_within_skew(
            issued_at_skew_secs,
            max_issued_at_skew_secs,
        ),
{
}

pub proof fn lemma_issued_at_within_skew_is_allowed(
    issued_at_skew_secs: int,
    max_issued_at_skew_secs: int,
)
    requires issued_at_skew_secs <= max_issued_at_skew_secs,
    ensures
        spec_capability_issued_at_within_skew(
            issued_at_skew_secs,
            max_issued_at_skew_secs,
        ),
{
}

pub proof fn lemma_public_key_expectation_is_identity()
    ensures
        spec_capability_expected_public_key_matches(true),
        !spec_capability_expected_public_key_matches(false),
{
}

pub proof fn lemma_public_key_length_must_match_exactly(public_key_len: nat)
    ensures
        spec_capability_public_key_length_valid(public_key_len) == (public_key_len == 32),
{
}

pub proof fn lemma_signature_length_must_match_exactly(signature_len: nat)
    ensures
        spec_capability_signature_length_valid(signature_len) == (signature_len == 64),
{
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_verification_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
