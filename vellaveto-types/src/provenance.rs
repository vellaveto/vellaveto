// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Provenance and semantic-containment types shared across crates.

use crate::has_dangerous_chars;
use crate::minja::TaintLabel;
use serde::{Deserialize, Serialize};

const MAX_OPTIONAL_FIELD_LEN: usize = 256;
const MAX_SIGNATURE_LEN: usize = 4096;
const MAX_HASH_LEN: usize = 128;
const MAX_LINEAGE_REFS: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureVerificationStatus {
    #[default]
    Missing,
    Verified,
    Invalid,
    Expired,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadBindingStatus {
    #[default]
    Unknown,
    Bound,
    Missing,
    Mismatch,
    Unverified,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionKeyScope {
    #[default]
    Unknown,
    EphemeralExecution,
    EphemeralSession,
    PersistedClient,
    PersistedService,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    #[default]
    NotChecked,
    Fresh,
    ReplayDetected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    #[default]
    Unknown,
    Untrusted,
    Low,
    Medium,
    High,
    Verified,
    Quarantined,
}

impl TrustTier {
    /// Returns the total-order rank used for fail-closed flow checks.
    ///
    /// `Quarantined` and `Unknown` are intentionally ranked below
    /// `Untrusted` so that incomplete or explicitly contained provenance never
    /// qualifies for higher-trust flows without an explicit policy override.
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

    /// Returns true when `self` is at least as trusted as `other`.
    pub const fn at_least_as_trusted_as(self, other: Self) -> bool {
        self.rank() >= other.rank()
    }

    /// Least upper bound in the trust lattice.
    pub const fn join(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// Greatest lower bound in the trust lattice.
    pub const fn meet(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    /// Returns true when data at `self` may flow to a target requiring
    /// `required_trust_tier`, or when explicit declassification is present.
    pub const fn can_flow_to(
        self,
        required_trust_tier: Self,
        explicitly_declassified: bool,
    ) -> bool {
        explicitly_declassified || self.at_least_as_trusted_as(required_trust_tier)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SinkClass {
    #[default]
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

impl SinkClass {
    /// Returns the total-order rank from lowest to highest privilege.
    pub const fn rank(self) -> u8 {
        match self {
            Self::ReadOnly => 0,
            Self::LowRiskWrite => 1,
            Self::FilesystemWrite => 2,
            Self::NetworkEgress => 3,
            Self::CodeExecution => 4,
            Self::MemoryWrite => 5,
            Self::ApprovalUi => 6,
            Self::CredentialAccess => 7,
            Self::PolicyMutation => 8,
        }
    }

    /// Returns true when `self` is at least as privileged as `other`.
    pub const fn at_least_as_privileged_as(self, other: Self) -> bool {
        self.rank() >= other.rank()
    }

    /// Least upper bound in the sink-privilege lattice.
    pub const fn join(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// Greatest lower bound in the sink-privilege lattice.
    pub const fn meet(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    pub fn is_privileged(self) -> bool {
        matches!(
            self,
            Self::LowRiskWrite
                | Self::FilesystemWrite
                | Self::NetworkEgress
                | Self::CodeExecution
                | Self::MemoryWrite
                | Self::ApprovalUi
                | Self::CredentialAccess
                | Self::PolicyMutation
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContextChannel {
    #[default]
    Data,
    FreeText,
    Url,
    CommandLike,
    ToolOutput,
    ResourceContent,
    ApprovalPrompt,
    Memory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentMode {
    #[default]
    Disabled,
    Observe,
    Enforce,
    Sanitize,
    Quarantine,
    RequireApproval,
}

pub type SemanticTaint = TaintLabel;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSecurityContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_provenance: Option<ClientProvenance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub semantic_taint: Vec<SemanticTaint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_trust_tier: Option<TrustTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_class: Option<SinkClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage_refs: Vec<LineageRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_mode: Option<ContainmentMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_risk_score: Option<SemanticRiskScore>,
}

impl RuntimeSecurityContext {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref provenance) = self.client_provenance {
            provenance.validate()?;
        }
        validate_lineage_refs(&self.lineage_refs)?;
        if let Some(ref risk_score) = self.semantic_risk_score {
            risk_score.validate()?;
        }
        Ok(())
    }

    /// Returns the lowest trust tier present in the effective context.
    pub fn most_restrictive_trust_tier(&self) -> Option<TrustTier> {
        let lineage_floor = self
            .lineage_refs
            .iter()
            .filter_map(|lineage| lineage.trust_tier)
            .reduce(TrustTier::meet);

        match (self.effective_trust_tier, lineage_floor) {
            (Some(explicit), Some(lineage)) => Some(explicit.meet(lineage)),
            (Some(explicit), None) => Some(explicit),
            (None, Some(lineage)) => Some(lineage),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RequestSignature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl RequestSignature {
    pub fn validate(&self) -> Result<(), String> {
        validate_optional_field(&self.key_id, "request_signature.key_id")?;
        validate_optional_field(&self.algorithm, "request_signature.algorithm")?;
        validate_optional_field(&self.nonce, "request_signature.nonce")?;
        validate_optional_field(&self.created_at, "request_signature.created_at")?;
        if let Some(ref signature) = self.signature {
            if signature.len() > MAX_SIGNATURE_LEN {
                return Err("request_signature.signature exceeds maximum length".into());
            }
            if has_dangerous_chars(signature) {
                return Err("request_signature.signature contains dangerous characters".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub workload_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_level: Option<String>,
}

impl WorkloadIdentity {
    pub fn validate(&self) -> Result<(), String> {
        if self.workload_id.is_empty() {
            return Err("workload_identity.workload_id must not be empty".into());
        }
        validate_bounded_field(
            &self.workload_id,
            "workload_identity.workload_id",
            MAX_OPTIONAL_FIELD_LEN,
        )?;
        validate_optional_field(&self.platform, "workload_identity.platform")?;
        validate_optional_field(&self.namespace, "workload_identity.namespace")?;
        validate_optional_field(&self.service_account, "workload_identity.service_account")?;
        validate_optional_field(&self.process_identity, "workload_identity.process_identity")?;
        validate_optional_field(
            &self.attestation_level,
            "workload_identity.attestation_level",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ClientProvenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_signature: Option<RequestSignature>,
    #[serde(default)]
    pub signature_status: SignatureVerificationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_id: Option<String>,
    #[serde(default)]
    pub session_key_scope: SessionKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
    #[serde(default)]
    pub workload_binding_status: WorkloadBindingStatus,
    #[serde(default)]
    pub replay_status: ReplayStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_request_hash: Option<String>,
    #[serde(default)]
    pub execution_is_ephemeral: bool,
}

impl ClientProvenance {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref sig) = self.request_signature {
            sig.validate()?;
        }
        validate_optional_field(&self.client_key_id, "client_provenance.client_key_id")?;
        if let Some(ref workload) = self.workload_identity {
            workload.validate()?;
        }
        if let Some(ref hash) = self.canonical_request_hash {
            validate_bounded_field(
                hash,
                "client_provenance.canonical_request_hash",
                MAX_HASH_LEN,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LineageRef {
    pub id: String,
    pub channel: ContextChannel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
}

impl LineageRef {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("lineage_ref.id must not be empty".into());
        }
        validate_bounded_field(&self.id, "lineage_ref.id", MAX_OPTIONAL_FIELD_LEN)?;
        if let Some(ref hash) = self.content_hash {
            validate_bounded_field(hash, "lineage_ref.content_hash", MAX_HASH_LEN)?;
        }
        validate_optional_field(&self.source, "lineage_ref.source")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(deny_unknown_fields)]
pub struct SemanticRiskScore {
    pub value: u8,
}

impl SemanticRiskScore {
    pub fn new(value: u8) -> Result<Self, String> {
        if value > 100 {
            return Err("semantic_risk_score must be <= 100".into());
        }
        Ok(Self { value })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.value > 100 {
            return Err("semantic_risk_score must be <= 100".into());
        }
        Ok(())
    }
}

pub fn is_security_relevant_taint(taint: SemanticTaint) -> bool {
    matches!(
        taint,
        TaintLabel::Untrusted
            | TaintLabel::Quarantined
            | TaintLabel::CrossAgent
            | TaintLabel::Replayed
            | TaintLabel::MixedProvenance
            | TaintLabel::IntegrityFailed
    )
}

pub fn validate_lineage_refs(lineage_refs: &[LineageRef]) -> Result<(), String> {
    if lineage_refs.len() > MAX_LINEAGE_REFS {
        return Err("lineage_refs exceeds maximum count".into());
    }
    for lineage_ref in lineage_refs {
        lineage_ref.validate()?;
    }
    Ok(())
}

fn validate_optional_field(value: &Option<String>, field: &str) -> Result<(), String> {
    if let Some(ref value) = *value {
        validate_bounded_field(value, field, MAX_OPTIONAL_FIELD_LEN)?;
    }
    Ok(())
}

fn validate_bounded_field(value: &str, field: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!("{field} exceeds maximum length"));
    }
    if has_dangerous_chars(value) {
        return Err(format!("{field} contains dangerous characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_risk_score_bounds() {
        assert!(SemanticRiskScore::new(0).is_ok());
        assert!(SemanticRiskScore::new(100).is_ok());
    }

    #[test]
    fn test_workload_identity_requires_id() {
        let workload = WorkloadIdentity::default();
        let err = workload.validate().unwrap_err();
        assert!(err.contains("workload_id must not be empty"));
    }

    #[test]
    fn test_lineage_ref_requires_id() {
        let lineage = LineageRef {
            id: String::new(),
            channel: ContextChannel::FreeText,
            content_hash: None,
            source: None,
            trust_tier: None,
        };
        let err = lineage.validate().unwrap_err();
        assert!(err.contains("lineage_ref.id must not be empty"));
    }

    #[test]
    fn test_security_relevant_taint_subset() {
        assert!(is_security_relevant_taint(TaintLabel::Untrusted));
        assert!(!is_security_relevant_taint(TaintLabel::Sanitized));
    }

    #[test]
    fn test_trust_tier_ordering_is_fail_closed() {
        assert!(TrustTier::Verified.at_least_as_trusted_as(TrustTier::High));
        assert!(TrustTier::High.at_least_as_trusted_as(TrustTier::Low));
        assert!(TrustTier::Untrusted.at_least_as_trusted_as(TrustTier::Unknown));
        assert!(!TrustTier::Unknown.at_least_as_trusted_as(TrustTier::Untrusted));
        assert!(!TrustTier::Unknown.at_least_as_trusted_as(TrustTier::Low));
        assert!(!TrustTier::Quarantined.at_least_as_trusted_as(TrustTier::Unknown));
    }

    #[test]
    fn test_trust_tier_join_and_meet() {
        assert_eq!(TrustTier::Low.join(TrustTier::High), TrustTier::High);
        assert_eq!(
            TrustTier::Verified.join(TrustTier::Medium),
            TrustTier::Verified
        );
        assert_eq!(TrustTier::Low.meet(TrustTier::High), TrustTier::Low);
        assert_eq!(
            TrustTier::Quarantined.meet(TrustTier::Verified),
            TrustTier::Quarantined
        );
    }

    #[test]
    fn test_sink_class_join_and_meet() {
        assert!(SinkClass::PolicyMutation.at_least_as_privileged_as(SinkClass::ApprovalUi));
        assert!(SinkClass::NetworkEgress.at_least_as_privileged_as(SinkClass::ReadOnly));
        assert_eq!(
            SinkClass::ReadOnly.join(SinkClass::CredentialAccess),
            SinkClass::CredentialAccess
        );
        assert_eq!(
            SinkClass::CodeExecution.meet(SinkClass::PolicyMutation),
            SinkClass::CodeExecution
        );
    }

    #[test]
    fn test_trust_tier_flow_requires_declassification_for_lower_trust_sources() {
        assert!(TrustTier::High.can_flow_to(TrustTier::Medium, false));
        assert!(!TrustTier::Low.can_flow_to(TrustTier::High, false));
        assert!(TrustTier::Low.can_flow_to(TrustTier::High, true));
        assert!(!TrustTier::Unknown.can_flow_to(TrustTier::Low, false));
    }

    #[test]
    fn test_runtime_security_context_uses_most_restrictive_trust_tier() {
        let ctx = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::High),
            lineage_refs: vec![
                LineageRef {
                    id: "trusted".into(),
                    channel: ContextChannel::Data,
                    content_hash: None,
                    source: None,
                    trust_tier: Some(TrustTier::Verified),
                },
                LineageRef {
                    id: "mixed".into(),
                    channel: ContextChannel::ToolOutput,
                    content_hash: None,
                    source: None,
                    trust_tier: Some(TrustTier::Low),
                },
            ],
            ..RuntimeSecurityContext::default()
        };

        assert_eq!(ctx.most_restrictive_trust_tier(), Some(TrustTier::Low));
    }
}
