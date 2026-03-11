// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Extracted trust-containment helpers from `vellaveto-types::provenance`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTier {
    Unknown,
    Untrusted,
    Low,
    Medium,
    High,
    Verified,
    Quarantined,
}

impl TrustTier {
    pub const fn rank(self) -> u8 {
        match self {
            Self::Quarantined => 0,
            Self::Unknown => 1,
            Self::Untrusted => 2,
            Self::Low => 3,
            Self::Medium => 4,
            Self::High => 5,
            Self::Verified => 6,
        }
    }

    pub const fn at_least_as_trusted_as(self, other: Self) -> bool {
        self.rank() >= other.rank()
    }

    pub const fn can_flow_to(
        self,
        required_trust_tier: Self,
        explicitly_declassified: bool,
    ) -> bool {
        explicitly_declassified || self.at_least_as_trusted_as(required_trust_tier)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkClass {
    ReadOnly,
    LowRiskWrite,
    FilesystemWrite,
    NetworkEgress,
    CodeExecution,
    MemoryWrite,
    ApprovalUi,
    CredentialAccess,
    PolicyMutation,
}

pub const fn minimum_trust_tier_for_sink(sink_class: SinkClass) -> TrustTier {
    match sink_class {
        SinkClass::ReadOnly => TrustTier::Unknown,
        SinkClass::LowRiskWrite => TrustTier::Low,
        SinkClass::FilesystemWrite | SinkClass::NetworkEgress => TrustTier::Medium,
        SinkClass::MemoryWrite | SinkClass::ApprovalUi => TrustTier::High,
        SinkClass::CodeExecution | SinkClass::CredentialAccess | SinkClass::PolicyMutation => {
            TrustTier::Verified
        }
    }
}

pub const fn requires_explicit_gate_for_sink(
    observed_trust_tier: TrustTier,
    sink_class: SinkClass,
) -> bool {
    !observed_trust_tier.can_flow_to(minimum_trust_tier_for_sink(sink_class), false)
}
