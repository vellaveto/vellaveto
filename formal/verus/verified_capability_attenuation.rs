// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified capability attenuation arithmetic kernel.
//!
//! This file proves the delegation depth decrement and expiry clamp extracted
//! into `vellaveto-mcp/src/verified_capability_attenuation.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_capability_attenuation.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub const U64_MAX_VALUE: u64 = 0xffff_ffff_ffff_ffffu64;

pub open spec fn spec_can_attenuate_depth(parent_remaining_depth: nat) -> bool {
    parent_remaining_depth > 0
}

pub open spec fn spec_attenuated_remaining_depth_value(parent_remaining_depth: nat) -> nat {
    if parent_remaining_depth == 0 {
        0
    } else {
        (parent_remaining_depth - 1) as nat
    }
}

pub fn attenuated_remaining_depth(parent_remaining_depth: u8) -> (result: Option<u8>)
    ensures
        result.is_some() == spec_can_attenuate_depth(parent_remaining_depth as nat),
        match result {
            Some(depth) => depth as nat == spec_attenuated_remaining_depth_value(parent_remaining_depth as nat),
            None => true,
        },
{
    if parent_remaining_depth == 0 {
        None
    } else {
        Some(parent_remaining_depth - 1)
    }
}

pub open spec fn spec_can_attenuate_expiry(
    parent_expires_at_epoch: nat,
    now_epoch: nat,
    ttl_secs: nat,
    max_ttl_secs: nat,
) -> bool {
    ttl_secs <= max_ttl_secs
        && now_epoch < parent_expires_at_epoch
        && now_epoch + ttl_secs <= U64_MAX_VALUE as nat
}

pub open spec fn spec_attenuated_expiry_epoch_value(
    parent_expires_at_epoch: nat,
    now_epoch: nat,
    ttl_secs: nat,
) -> nat {
    if now_epoch + ttl_secs <= parent_expires_at_epoch {
        now_epoch + ttl_secs
    } else {
        parent_expires_at_epoch
    }
}

pub fn attenuated_expiry_epoch(
    parent_expires_at_epoch: u64,
    now_epoch: u64,
    ttl_secs: u64,
    max_ttl_secs: u64,
) -> (result: Option<u64>)
    ensures
        result.is_some() == spec_can_attenuate_expiry(
            parent_expires_at_epoch as nat,
            now_epoch as nat,
            ttl_secs as nat,
            max_ttl_secs as nat,
        ),
        match result {
            Some(expiry_epoch) => expiry_epoch as nat == spec_attenuated_expiry_epoch_value(
                parent_expires_at_epoch as nat,
                now_epoch as nat,
                ttl_secs as nat,
            ),
            None => true,
        },
{
    if ttl_secs > max_ttl_secs || now_epoch >= parent_expires_at_epoch {
        return None;
    }

    match now_epoch.checked_add(ttl_secs) {
        Some(requested_expires) => Some(if requested_expires <= parent_expires_at_epoch {
            requested_expires
        } else {
            parent_expires_at_epoch
        }),
        None => None,
    }
}

pub proof fn lemma_depth_strictly_decreases(parent_remaining_depth: nat)
    requires spec_can_attenuate_depth(parent_remaining_depth),
    ensures spec_attenuated_remaining_depth_value(parent_remaining_depth) < parent_remaining_depth,
{
}

pub proof fn lemma_depth_transitive(parent_remaining_depth: nat)
    requires parent_remaining_depth > 1,
    ensures
        spec_can_attenuate_depth(parent_remaining_depth),
        spec_can_attenuate_depth(spec_attenuated_remaining_depth_value(parent_remaining_depth)),
        spec_attenuated_remaining_depth_value(
            spec_attenuated_remaining_depth_value(parent_remaining_depth),
        ) < spec_attenuated_remaining_depth_value(parent_remaining_depth),
        spec_attenuated_remaining_depth_value(
            spec_attenuated_remaining_depth_value(parent_remaining_depth),
        ) < parent_remaining_depth,
{
}

pub proof fn lemma_expiry_never_exceeds_parent(
    parent_expires_at_epoch: nat,
    now_epoch: nat,
    ttl_secs: nat,
    max_ttl_secs: nat,
)
    requires spec_can_attenuate_expiry(parent_expires_at_epoch, now_epoch, ttl_secs, max_ttl_secs),
    ensures spec_attenuated_expiry_epoch_value(parent_expires_at_epoch, now_epoch, ttl_secs) <= parent_expires_at_epoch,
{
}

pub proof fn lemma_expiry_stays_within_requested_window(
    parent_expires_at_epoch: nat,
    now_epoch: nat,
    ttl_secs: nat,
    max_ttl_secs: nat,
)
    requires spec_can_attenuate_expiry(parent_expires_at_epoch, now_epoch, ttl_secs, max_ttl_secs),
    ensures spec_attenuated_expiry_epoch_value(parent_expires_at_epoch, now_epoch, ttl_secs) <= now_epoch + ttl_secs,
{
}

pub proof fn lemma_parent_expiry_is_fail_closed(
    parent_expires_at_epoch: nat,
    now_epoch: nat,
    ttl_secs: nat,
    max_ttl_secs: nat,
)
    requires now_epoch >= parent_expires_at_epoch,
    ensures !spec_can_attenuate_expiry(parent_expires_at_epoch, now_epoch, ttl_secs, max_ttl_secs),
{
}

pub proof fn lemma_ttl_limit_is_fail_closed(
    parent_expires_at_epoch: nat,
    now_epoch: nat,
    ttl_secs: nat,
    max_ttl_secs: nat,
)
    requires ttl_secs > max_ttl_secs,
    ensures !spec_can_attenuate_expiry(parent_expires_at_epoch, now_epoch, ttl_secs, max_ttl_secs),
{
}

pub proof fn lemma_expiry_transitive_nonincreasing(
    root_expires_at_epoch: nat,
    now_epoch: nat,
    ttl_secs: nat,
    next_now_epoch: nat,
    next_ttl_secs: nat,
    max_ttl_secs: nat,
)
    requires
        spec_can_attenuate_expiry(root_expires_at_epoch, now_epoch, ttl_secs, max_ttl_secs),
        spec_can_attenuate_expiry(
            spec_attenuated_expiry_epoch_value(root_expires_at_epoch, now_epoch, ttl_secs),
            next_now_epoch,
            next_ttl_secs,
            max_ttl_secs,
        ),
    ensures
        spec_attenuated_expiry_epoch_value(
            spec_attenuated_expiry_epoch_value(root_expires_at_epoch, now_epoch, ttl_secs),
            next_now_epoch,
            next_ttl_secs,
        ) <= spec_attenuated_expiry_epoch_value(root_expires_at_epoch, now_epoch, ttl_secs),
        spec_attenuated_expiry_epoch_value(
            spec_attenuated_expiry_epoch_value(root_expires_at_epoch, now_epoch, ttl_secs),
            next_now_epoch,
            next_ttl_secs,
        ) <= root_expires_at_epoch,
{
    lemma_expiry_never_exceeds_parent(
        root_expires_at_epoch,
        now_epoch,
        ttl_secs,
        max_ttl_secs,
    );
    lemma_expiry_never_exceeds_parent(
        spec_attenuated_expiry_epoch_value(root_expires_at_epoch, now_epoch, ttl_secs),
        next_now_epoch,
        next_ttl_secs,
        max_ttl_secs,
    );
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::capability_attenuation_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
