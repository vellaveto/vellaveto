// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified fixed-point entropy alert kernel.
//!
//! This file proves the integer-only alert gating extracted into
//! `vellaveto-engine/src/verified_entropy_gate.rs`.
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_entropy_gate.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub const U32_MAX_VALUE: u32 = 0xffff_ffffu32;

#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum EntropyAlertLevel {
    Medium,
    High,
}

pub open spec fn spec_is_high_entropy_millibits(observation_millibits: nat, threshold_millibits: nat) -> bool {
    observation_millibits >= threshold_millibits
}

pub fn is_high_entropy_millibits(observation_millibits: u16, threshold_millibits: u16) -> (result: bool)
    ensures
        result == spec_is_high_entropy_millibits(observation_millibits as nat, threshold_millibits as nat),
        result ==> (observation_millibits as nat) >= (threshold_millibits as nat),
        !result ==> (observation_millibits as nat) < (threshold_millibits as nat),
{
    observation_millibits >= threshold_millibits
}

pub open spec fn spec_should_alert_on_high_entropy_count(
    high_entropy_count: nat,
    min_entropy_observations: nat,
) -> bool {
    high_entropy_count >= min_entropy_observations
}

pub fn should_alert_on_high_entropy_count(high_entropy_count: u32, min_entropy_observations: u32) -> (result: bool)
    ensures
        result == spec_should_alert_on_high_entropy_count(high_entropy_count as nat, min_entropy_observations as nat),
        result ==> (high_entropy_count as nat) >= (min_entropy_observations as nat),
        !result ==> (high_entropy_count as nat) < (min_entropy_observations as nat),
{
    high_entropy_count >= min_entropy_observations
}

pub open spec fn spec_high_severity_entropy_threshold(min_entropy_observations: nat) -> nat {
    if min_entropy_observations > (U32_MAX_VALUE as nat) / 2 {
        U32_MAX_VALUE as nat
    } else {
        min_entropy_observations * 2
    }
}

pub fn high_severity_entropy_threshold(min_entropy_observations: u32) -> (result: u32)
    ensures
        result as nat == spec_high_severity_entropy_threshold(min_entropy_observations as nat),
        (min_entropy_observations as nat) <= (U32_MAX_VALUE as nat) / 2 ==> result as nat == (min_entropy_observations as nat) * 2,
        (min_entropy_observations as nat) > (U32_MAX_VALUE as nat) / 2 ==> result == 0xffff_ffffu32,
{
    if min_entropy_observations > u32::MAX / 2 {
        u32::MAX
    } else {
        min_entropy_observations * 2
    }
}

pub open spec fn spec_entropy_alert_level(
    high_entropy_count: nat,
    min_entropy_observations: nat,
) -> EntropyAlertLevel {
    if high_entropy_count >= spec_high_severity_entropy_threshold(min_entropy_observations) {
        EntropyAlertLevel::High
    } else {
        EntropyAlertLevel::Medium
    }
}

pub fn entropy_alert_level(high_entropy_count: u32, min_entropy_observations: u32) -> (result: EntropyAlertLevel)
    ensures
        result == spec_entropy_alert_level(high_entropy_count as nat, min_entropy_observations as nat),
        (high_entropy_count as nat) >= spec_high_severity_entropy_threshold(min_entropy_observations as nat)
            ==> result == EntropyAlertLevel::High,
        (high_entropy_count as nat) < spec_high_severity_entropy_threshold(min_entropy_observations as nat)
            ==> result == EntropyAlertLevel::Medium,
{
    if high_entropy_count >= high_severity_entropy_threshold(min_entropy_observations) {
        EntropyAlertLevel::High
    } else {
        EntropyAlertLevel::Medium
    }
}

pub open spec fn spec_entropy_alert_severity(
    high_entropy_count: nat,
    min_entropy_observations: nat,
) -> Option<EntropyAlertLevel> {
    if spec_should_alert_on_high_entropy_count(high_entropy_count, min_entropy_observations) {
        Some(spec_entropy_alert_level(high_entropy_count, min_entropy_observations))
    } else {
        None
    }
}

pub fn entropy_alert_severity(high_entropy_count: u32, min_entropy_observations: u32) -> (result: Option<EntropyAlertLevel>)
    ensures
        result == spec_entropy_alert_severity(high_entropy_count as nat, min_entropy_observations as nat),
        (high_entropy_count as nat) < (min_entropy_observations as nat) ==> result.is_none(),
        (high_entropy_count as nat) >= (min_entropy_observations as nat) ==> result.is_some(),
{
    if should_alert_on_high_entropy_count(high_entropy_count, min_entropy_observations) {
        Some(entropy_alert_level(
            high_entropy_count,
            min_entropy_observations,
        ))
    } else {
        None
    }
}

pub proof fn lemma_no_alert_below_threshold(high_entropy_count: nat, min_entropy_observations: nat)
    requires high_entropy_count < min_entropy_observations,
    ensures spec_entropy_alert_severity(high_entropy_count, min_entropy_observations).is_none(),
{
}

pub proof fn lemma_threshold_alerts_medium(min_entropy_observations: nat)
    requires
        min_entropy_observations > 0,
        min_entropy_observations <= (U32_MAX_VALUE as nat) / 2,
    ensures spec_entropy_alert_severity(min_entropy_observations, min_entropy_observations)
        == Some(EntropyAlertLevel::Medium),
{
    assert(min_entropy_observations < spec_high_severity_entropy_threshold(min_entropy_observations)) by {
        assert(spec_high_severity_entropy_threshold(min_entropy_observations) == min_entropy_observations * 2);
        assert(min_entropy_observations < min_entropy_observations * 2);
    };
}

pub proof fn lemma_high_severity_threshold_alerts_high(min_entropy_observations: nat)
    requires min_entropy_observations <= U32_MAX_VALUE as nat,
    ensures spec_entropy_alert_severity(
        spec_high_severity_entropy_threshold(min_entropy_observations),
        min_entropy_observations,
    ) == Some(EntropyAlertLevel::High),
{
    assert(spec_should_alert_on_high_entropy_count(
        spec_high_severity_entropy_threshold(min_entropy_observations),
        min_entropy_observations,
    ));
    assert(spec_entropy_alert_level(
        spec_high_severity_entropy_threshold(min_entropy_observations),
        min_entropy_observations,
    ) == EntropyAlertLevel::High);
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::entropy_gate_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
