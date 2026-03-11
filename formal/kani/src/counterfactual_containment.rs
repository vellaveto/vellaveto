// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Extracted lightweight counterfactual-containment scoring rules.

use crate::output_contracts::ContextChannel;
use crate::trust_containment::{minimum_trust_tier_for_sink, SinkClass, TrustTier};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticTaint {
    Sanitized,
    Sensitive,
    Untrusted,
    CrossAgent,
    MixedProvenance,
    Replayed,
    IntegrityFailed,
    Quarantined,
}

pub const fn sink_is_privileged(sink_class: SinkClass) -> bool {
    !matches!(sink_class, SinkClass::ReadOnly)
}

pub const fn is_security_relevant_taint(taint: SemanticTaint) -> bool {
    matches!(
        taint,
        SemanticTaint::Untrusted
            | SemanticTaint::CrossAgent
            | SemanticTaint::MixedProvenance
            | SemanticTaint::Replayed
            | SemanticTaint::IntegrityFailed
            | SemanticTaint::Quarantined
    )
}

pub const fn taint_semantic_risk_weight(taint: SemanticTaint) -> u8 {
    match taint {
        SemanticTaint::Sanitized => 0,
        SemanticTaint::Sensitive => 10,
        SemanticTaint::Untrusted => 15,
        SemanticTaint::CrossAgent => 15,
        SemanticTaint::MixedProvenance => 20,
        SemanticTaint::Replayed => 20,
        SemanticTaint::IntegrityFailed => 25,
        SemanticTaint::Quarantined => 30,
    }
}

pub const fn counterfactual_attribution_weight(channel: ContextChannel) -> u8 {
    match channel {
        ContextChannel::Data => 0,
        ContextChannel::ToolOutput => 10,
        ContextChannel::ResourceContent => 10,
        ContextChannel::FreeText => 15,
        ContextChannel::Memory => 15,
        ContextChannel::Url => 20,
        ContextChannel::CommandLike => 35,
        ContextChannel::ApprovalPrompt => 35,
    }
}

pub const fn recommended_counterfactual_attribution_score(
    sink_class: SinkClass,
    observed_trust_tier: TrustTier,
    taint: Option<SemanticTaint>,
    channel: Option<ContextChannel>,
) -> u8 {
    if !sink_is_privileged(sink_class) {
        return 0;
    }

    let taint_risk = match taint {
        Some(taint) if is_security_relevant_taint(taint) => taint_semantic_risk_weight(taint),
        _ => 0,
    };
    if taint_risk == 0 {
        return 0;
    }

    let required_trust_tier = minimum_trust_tier_for_sink(sink_class);
    let trust_gap = required_trust_tier
        .rank()
        .saturating_sub(observed_trust_tier.rank())
        .saturating_mul(6);
    let lineage_signal = match channel {
        Some(channel) => counterfactual_attribution_weight(channel),
        None => 0,
    };
    let decision_driving_bonus = if matches!(
        (taint, channel),
        (
            Some(SemanticTaint::IntegrityFailed | SemanticTaint::Quarantined),
            Some(ContextChannel::CommandLike | ContextChannel::ApprovalPrompt)
        )
    ) {
        20
    } else {
        0
    };
    let raw_score = trust_gap
        .saturating_add(taint_risk)
        .saturating_add(lineage_signal)
        .saturating_add(decision_driving_bonus);

    if raw_score > 100 { 100 } else { raw_score }
}

pub const fn requires_counterfactual_gate(
    sink_class: SinkClass,
    observed_trust_tier: TrustTier,
    taint: Option<SemanticTaint>,
    channel: Option<ContextChannel>,
) -> bool {
    sink_is_privileged(sink_class)
        && recommended_counterfactual_attribution_score(
            sink_class,
            observed_trust_tier,
            taint,
            channel,
        ) >= 70
}
