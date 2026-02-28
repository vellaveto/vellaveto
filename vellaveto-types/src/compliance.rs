// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Compliance framework types shared across crates.
//!
//! These types live in vellaveto-types (leaf crate) so both vellaveto-config
//! and vellaveto-audit can reference them without circular dependencies.

use serde::{Deserialize, Serialize};

// ── EU AI Act Risk Classification ────────────────────────────────────────────

/// Risk classification per EU AI Act Article 6.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiActRiskClass {
    /// Minimal risk — no obligations beyond transparency.
    Minimal,
    /// Limited risk — transparency obligations only (Art 50).
    #[default]
    Limited,
    /// High-risk — full Chapter III obligations (Art 6–15, 43).
    HighRisk,
    /// Unacceptable risk — prohibited (Art 5).
    Unacceptable,
}

impl std::fmt::Display for AiActRiskClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minimal => write!(f, "Minimal"),
            Self::Limited => write!(f, "Limited"),
            Self::HighRisk => write!(f, "High-Risk"),
            Self::Unacceptable => write!(f, "Unacceptable"),
        }
    }
}

// ── SOC 2 Trust Services Category ────────────────────────────────────────────

/// SOC 2 Trust Services Category (TSC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustServicesCategory {
    /// CC1: Control Environment
    CC1,
    /// CC2: Communication and Information
    CC2,
    /// CC3: Risk Assessment
    CC3,
    /// CC4: Monitoring Activities
    CC4,
    /// CC5: Control Activities
    CC5,
    /// CC6: Logical and Physical Access Controls
    CC6,
    /// CC7: System Operations
    CC7,
    /// CC8: Change Management
    CC8,
    /// CC9: Risk Mitigation
    CC9,
}

impl std::fmt::Display for TrustServicesCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CC1 => write!(f, "CC1: Control Environment"),
            Self::CC2 => write!(f, "CC2: Communication and Information"),
            Self::CC3 => write!(f, "CC3: Risk Assessment"),
            Self::CC4 => write!(f, "CC4: Monitoring Activities"),
            Self::CC5 => write!(f, "CC5: Control Activities"),
            Self::CC6 => write!(f, "CC6: Logical and Physical Access Controls"),
            Self::CC7 => write!(f, "CC7: System Operations"),
            Self::CC8 => write!(f, "CC8: Change Management"),
            Self::CC9 => write!(f, "CC9: Risk Mitigation"),
        }
    }
}

// ── Phase 24: Art 50(2) Explanation Verbosity ────────────────────────────────

/// Controls the verbosity of per-verdict decision explanations (Art 50(2)).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationVerbosity {
    /// No explanation injected (default — backward compatible).
    #[default]
    None,
    /// Summary: verdict, reason, counts, duration. No policy details.
    Summary,
    /// Full: includes per-policy match details and failed constraints.
    Full,
}

impl std::fmt::Display for ExplanationVerbosity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Summary => write!(f, "summary"),
            Self::Full => write!(f, "full"),
        }
    }
}

// ── Phase 24: Art 10 Data Governance Types ───────────────────────────────────

/// Classification of data processed by a tool (Art 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    /// Training data used to build or fine-tune models.
    Training,
    /// Input data provided to the AI system.
    Input,
    /// Output data produced by the AI system.
    Output,
    /// Testing or validation data.
    Testing,
    /// Operational/system data.
    Operational,
    /// Personal data (GDPR-relevant).
    Personal,
    /// Non-personal data.
    NonPersonal,
}

impl std::fmt::Display for DataClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Training => write!(f, "training"),
            Self::Input => write!(f, "input"),
            Self::Output => write!(f, "output"),
            Self::Testing => write!(f, "testing"),
            Self::Operational => write!(f, "operational"),
            Self::Personal => write!(f, "personal"),
            Self::NonPersonal => write!(f, "non_personal"),
        }
    }
}

/// Purpose of data processing by a tool (Art 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingPurpose {
    /// Executing a tool call on behalf of an AI agent.
    ToolExecution,
    /// Recording security audit events.
    SecurityAudit,
    /// Generating compliance evidence.
    ComplianceEvidence,
    /// Evaluating policies against actions.
    PolicyEvaluation,
    /// Model inference or generation.
    ModelInference,
}

impl std::fmt::Display for ProcessingPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolExecution => write!(f, "tool_execution"),
            Self::SecurityAudit => write!(f, "security_audit"),
            Self::ComplianceEvidence => write!(f, "compliance_evidence"),
            Self::PolicyEvaluation => write!(f, "policy_evaluation"),
            Self::ModelInference => write!(f, "model_inference"),
        }
    }
}

/// Data governance record for a tool (Art 10).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DataGovernanceRecord {
    /// Tool name or pattern this record applies to.
    pub tool: String,
    /// Data classifications applicable to this tool.
    pub classifications: Vec<DataClassification>,
    /// Purpose of data processing.
    pub purpose: ProcessingPurpose,
    /// Data provenance description (e.g., "user-provided", "system-generated").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    /// Retention period in days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

impl DataGovernanceRecord {
    /// Maximum length for `tool` field (bytes).
    const MAX_TOOL_LEN: usize = 256;
    /// Maximum length for `provenance` field (bytes).
    const MAX_PROVENANCE_LEN: usize = 512;
    /// Maximum number of classifications per record.
    const MAX_CLASSIFICATIONS: usize = 64;

    /// Validate structural bounds on fields.
    ///
    /// SECURITY (FIND-R53-P3-001): Prevents memory exhaustion and control character
    /// injection from untrusted `DataGovernanceRecord` payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.tool.is_empty() {
            return Err("DataGovernanceRecord tool must not be empty".to_string());
        }
        if self.tool.len() > Self::MAX_TOOL_LEN {
            return Err(format!(
                "DataGovernanceRecord tool length {} exceeds max {}",
                self.tool.len(),
                Self::MAX_TOOL_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.tool) {
            return Err(
                "DataGovernanceRecord tool contains control or format characters".to_string(),
            );
        }
        if self.classifications.len() > Self::MAX_CLASSIFICATIONS {
            return Err(format!(
                "DataGovernanceRecord classifications count {} exceeds max {}",
                self.classifications.len(),
                Self::MAX_CLASSIFICATIONS,
            ));
        }
        if let Some(ref prov) = self.provenance {
            if prov.len() > Self::MAX_PROVENANCE_LEN {
                return Err(format!(
                    "DataGovernanceRecord provenance length {} exceeds max {}",
                    prov.len(),
                    Self::MAX_PROVENANCE_LEN,
                ));
            }
            if prov
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(
                    "DataGovernanceRecord provenance contains control or format characters"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

// ── Phase 38: SOC 2 Type II Access Review Types ─────────────────────────────

/// Status of a reviewer's attestation on an access review report.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    /// Report has not yet been reviewed.
    #[default]
    Pending,
    /// Reviewer has approved the access review.
    Approved,
    /// Reviewer approved with noted findings.
    FindingsNoted,
    /// Reviewer has rejected the access review.
    Rejected,
}

impl std::fmt::Display for AttestationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::FindingsNoted => write!(f, "findings_noted"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

/// Reviewer attestation on an access review report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewerAttestation {
    /// Name of the reviewer.
    pub reviewer_name: String,
    /// Title/role of the reviewer.
    pub reviewer_title: String,
    /// ISO 8601 timestamp when the review was completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
    /// Reviewer notes or observations.
    #[serde(default)]
    pub notes: String,
    /// Attestation status.
    #[serde(default)]
    pub status: AttestationStatus,
}

impl ReviewerAttestation {
    /// Maximum length for `reviewer_name` (bytes).
    const MAX_NAME_LEN: usize = 256;
    /// Maximum length for `reviewer_title` (bytes).
    const MAX_TITLE_LEN: usize = 256;
    /// Maximum length for `reviewed_at` ISO 8601 timestamp (bytes).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `notes` (bytes).
    const MAX_NOTES_LEN: usize = 4096;

    /// Validate structural bounds on fields.
    ///
    /// SECURITY (FIND-R53-P3-005): Prevents memory exhaustion and control character
    /// injection from untrusted `ReviewerAttestation` payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.reviewer_name.is_empty() {
            return Err("ReviewerAttestation reviewer_name must not be empty".to_string());
        }
        if self.reviewer_name.len() > Self::MAX_NAME_LEN {
            return Err(format!(
                "ReviewerAttestation reviewer_name length {} exceeds max {}",
                self.reviewer_name.len(),
                Self::MAX_NAME_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.reviewer_name) {
            return Err(
                "ReviewerAttestation reviewer_name contains control or format characters"
                    .to_string(),
            );
        }
        if self.reviewer_title.is_empty() {
            return Err("ReviewerAttestation reviewer_title must not be empty".to_string());
        }
        if self.reviewer_title.len() > Self::MAX_TITLE_LEN {
            return Err(format!(
                "ReviewerAttestation reviewer_title length {} exceeds max {}",
                self.reviewer_title.len(),
                Self::MAX_TITLE_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.reviewer_title) {
            return Err(
                "ReviewerAttestation reviewer_title contains control or format characters"
                    .to_string(),
            );
        }
        if let Some(ref ts) = self.reviewed_at {
            if ts.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "ReviewerAttestation reviewed_at length {} exceeds max {}",
                    ts.len(),
                    Self::MAX_TIMESTAMP_LEN,
                ));
            }
            // SECURITY (FIND-R157-005): Reject control/format chars in reviewed_at
            // timestamp to prevent log injection.
            if crate::core::has_dangerous_chars(ts) {
                return Err(
                    "ReviewerAttestation reviewed_at contains control or format characters"
                        .to_string(),
                );
            }
        }
        if self.notes.len() > Self::MAX_NOTES_LEN {
            return Err(format!(
                "ReviewerAttestation notes length {} exceeds max {}",
                self.notes.len(),
                Self::MAX_NOTES_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.notes) {
            return Err(
                "ReviewerAttestation notes contains control or format characters".to_string(),
            );
        }
        Ok(())
    }
}

/// Per-agent access review entry for SOC 2 Type II reporting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccessReviewEntry {
    /// Agent identifier.
    pub agent_id: String,
    /// Session IDs observed for this agent during the review period.
    pub session_ids: Vec<String>,
    /// ISO 8601 timestamp of first observed access.
    pub first_access: String,
    /// ISO 8601 timestamp of last observed access.
    pub last_access: String,
    /// Total number of policy evaluations.
    pub total_evaluations: u64,
    /// Number of Allow verdicts.
    pub allow_count: u64,
    /// Number of Deny verdicts.
    pub deny_count: u64,
    /// Number of RequireApproval verdicts.
    pub require_approval_count: u64,
    /// Distinct tools accessed.
    pub tools_accessed: Vec<String>,
    /// Distinct functions called.
    pub functions_called: Vec<String>,
    /// Number of permissions granted (from least-agency data).
    pub permissions_granted: usize,
    /// Number of permissions actually used.
    pub permissions_used: usize,
    /// Permission usage ratio (0.0–1.0).
    pub usage_ratio: f64,
    /// Unused permission IDs.
    pub unused_permissions: Vec<String>,
    /// Agency recommendation based on usage ratio.
    pub agency_recommendation: String,
}

impl AccessReviewEntry {
    /// Maximum number of session IDs per entry.
    pub const MAX_SESSION_IDS: usize = 10_000;
    /// Maximum number of tools accessed per entry.
    pub const MAX_TOOLS_ACCESSED: usize = 10_000;
    /// Maximum number of functions called per entry.
    pub const MAX_FUNCTIONS_CALLED: usize = 10_000;
    /// Maximum number of unused permissions per entry.
    pub const MAX_UNUSED_PERMISSIONS: usize = 10_000;
    /// Maximum length for ISO 8601 timestamp fields (bytes).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `agent_id` field (bytes).
    ///
    /// SECURITY (FIND-R159-002): Bound agent_id to prevent memory exhaustion
    /// from attacker-controlled deserialized input.
    const MAX_AGENT_ID_LEN: usize = 256;
    /// Maximum length for individual string entries in Vec<String> fields (bytes).
    ///
    /// SECURITY (FIND-R159-001): Per-entry length bound on session_ids,
    /// tools_accessed, functions_called, and unused_permissions to prevent
    /// memory exhaustion and control/format character injection.
    const MAX_ENTRY_VALUE_LEN: usize = 256;

    /// Validate structural invariants: finite scores, range checks, collection bounds.
    ///
    /// SECURITY (FIND-R49-003): Non-finite floats can cause unexpected behavior
    /// in comparisons, serialization, and downstream reporting logic.
    /// SECURITY (FIND-R53-003): usage_ratio must be in [0.0, 1.0] to prevent
    /// negative or >1.0 values from bypassing threshold checks.
    /// SECURITY (FIND-R53-006): Unbounded Vec fields can cause OOM from
    /// attacker-controlled deserialized input.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R159-002): Bound agent_id length to prevent memory exhaustion.
        if self.agent_id.is_empty() {
            return Err("AccessReviewEntry agent_id must not be empty".to_string());
        }
        if self.agent_id.len() > Self::MAX_AGENT_ID_LEN {
            return Err(format!(
                "AccessReviewEntry agent_id length {} exceeds max {}",
                self.agent_id.len(),
                Self::MAX_AGENT_ID_LEN,
            ));
        }
        // SECURITY (FIND-R115-002): Reject control/format chars in identity fields
        // to prevent zero-width space or bidi override bypasses.
        if crate::core::has_dangerous_chars(&self.agent_id) {
            return Err(format!(
                "AccessReviewEntry agent_id '{}' contains control or format characters",
                self.agent_id,
            ));
        }
        if crate::core::has_dangerous_chars(&self.agency_recommendation) {
            return Err(format!(
                "AccessReviewEntry for agent '{}' agency_recommendation contains control or format characters",
                self.agent_id,
            ));
        }
        // SECURITY (FIND-R157-006): Validate first_access/last_access timestamp
        // length and reject control/format characters to prevent log injection.
        if self.first_access.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "AccessReviewEntry for agent '{}' first_access length {} exceeds max {}",
                self.agent_id,
                self.first_access.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.first_access) {
            return Err(format!(
                "AccessReviewEntry for agent '{}' first_access contains control or format characters",
                self.agent_id,
            ));
        }
        if self.last_access.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "AccessReviewEntry for agent '{}' last_access length {} exceeds max {}",
                self.agent_id,
                self.last_access.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.last_access) {
            return Err(format!(
                "AccessReviewEntry for agent '{}' last_access contains control or format characters",
                self.agent_id,
            ));
        }
        if !self.usage_ratio.is_finite() {
            return Err(format!(
                "AccessReviewEntry for agent '{}' has non-finite usage_ratio: {}",
                self.agent_id, self.usage_ratio,
            ));
        }
        if self.usage_ratio < 0.0 || self.usage_ratio > 1.0 {
            return Err(format!(
                "AccessReviewEntry for agent '{}' usage_ratio must be in [0.0, 1.0], got {}",
                self.agent_id, self.usage_ratio,
            ));
        }
        if self.session_ids.len() > Self::MAX_SESSION_IDS {
            return Err(format!(
                "AccessReviewEntry for agent '{}' has {} session_ids (max {})",
                self.agent_id,
                self.session_ids.len(),
                Self::MAX_SESSION_IDS,
            ));
        }
        // SECURITY (FIND-R159-001): Per-entry validation on session_ids.
        for item in &self.session_ids {
            if item.len() > Self::MAX_ENTRY_VALUE_LEN {
                return Err(format!(
                    "AccessReviewEntry for agent '{}' session_ids entry length {} exceeds max {}",
                    self.agent_id,
                    item.len(),
                    Self::MAX_ENTRY_VALUE_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(item) {
                return Err(format!(
                    "AccessReviewEntry for agent '{}' session_ids entry contains control or format characters",
                    self.agent_id,
                ));
            }
        }
        if self.tools_accessed.len() > Self::MAX_TOOLS_ACCESSED {
            return Err(format!(
                "AccessReviewEntry for agent '{}' has {} tools_accessed (max {})",
                self.agent_id,
                self.tools_accessed.len(),
                Self::MAX_TOOLS_ACCESSED,
            ));
        }
        // SECURITY (FIND-R159-001): Per-entry validation on tools_accessed.
        for item in &self.tools_accessed {
            if item.len() > Self::MAX_ENTRY_VALUE_LEN {
                return Err(format!(
                    "AccessReviewEntry for agent '{}' tools_accessed entry length {} exceeds max {}",
                    self.agent_id,
                    item.len(),
                    Self::MAX_ENTRY_VALUE_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(item) {
                return Err(format!(
                    "AccessReviewEntry for agent '{}' tools_accessed entry contains control or format characters",
                    self.agent_id,
                ));
            }
        }
        if self.functions_called.len() > Self::MAX_FUNCTIONS_CALLED {
            return Err(format!(
                "AccessReviewEntry for agent '{}' has {} functions_called (max {})",
                self.agent_id,
                self.functions_called.len(),
                Self::MAX_FUNCTIONS_CALLED,
            ));
        }
        // SECURITY (FIND-R159-001): Per-entry validation on functions_called.
        for item in &self.functions_called {
            if item.len() > Self::MAX_ENTRY_VALUE_LEN {
                return Err(format!(
                    "AccessReviewEntry for agent '{}' functions_called entry length {} exceeds max {}",
                    self.agent_id,
                    item.len(),
                    Self::MAX_ENTRY_VALUE_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(item) {
                return Err(format!(
                    "AccessReviewEntry for agent '{}' functions_called entry contains control or format characters",
                    self.agent_id,
                ));
            }
        }
        if self.unused_permissions.len() > Self::MAX_UNUSED_PERMISSIONS {
            return Err(format!(
                "AccessReviewEntry for agent '{}' has {} unused_permissions (max {})",
                self.agent_id,
                self.unused_permissions.len(),
                Self::MAX_UNUSED_PERMISSIONS,
            ));
        }
        // SECURITY (FIND-R159-001): Per-entry validation on unused_permissions.
        for item in &self.unused_permissions {
            if item.len() > Self::MAX_ENTRY_VALUE_LEN {
                return Err(format!(
                    "AccessReviewEntry for agent '{}' unused_permissions entry length {} exceeds max {}",
                    self.agent_id,
                    item.len(),
                    Self::MAX_ENTRY_VALUE_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(item) {
                return Err(format!(
                    "AccessReviewEntry for agent '{}' unused_permissions entry contains control or format characters",
                    self.agent_id,
                ));
            }
        }
        Ok(())
    }

    /// Deprecated alias for [`AccessReviewEntry::validate()`].
    #[deprecated(since = "4.0.1", note = "renamed to validate()")]
    pub fn validate_finite(&self) -> Result<(), String> {
        self.validate()
    }
}

/// CC6 (Logical and Physical Access Controls) evidence summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Cc6Evidence {
    /// CC6.1: Logical access security over protected assets.
    pub cc6_1_evidence: String,
    /// CC6.2: Prior to issuing system credentials and granting access.
    pub cc6_2_evidence: String,
    /// CC6.3: Based on authorization, access to protected information assets is removed.
    pub cc6_3_evidence: String,
    /// Number of agents classified as "Optimal" (>80% usage).
    pub optimal_count: usize,
    /// Number of agents classified as "ReviewGrants" (50–80% usage).
    pub review_grants_count: usize,
    /// Number of agents classified as "NarrowScope" (20–50% usage).
    pub narrow_scope_count: usize,
    /// Number of agents classified as "Critical" (<20% usage).
    pub critical_count: usize,
}

/// SOC 2 Type II access review report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccessReviewReport {
    /// ISO 8601 timestamp when the report was generated.
    pub generated_at: String,
    /// Organization name for the report header.
    pub organization_name: String,
    /// Review period start (ISO 8601).
    pub period_start: String,
    /// Review period end (ISO 8601).
    pub period_end: String,
    /// Total distinct agents observed.
    pub total_agents: usize,
    /// Total policy evaluations during the period.
    pub total_evaluations: u64,
    /// Per-agent access review entries.
    pub entries: Vec<AccessReviewEntry>,
    /// CC6 evidence summary.
    pub cc6_evidence: Cc6Evidence,
    /// Reviewer attestation (empty/pending by default).
    pub attestation: ReviewerAttestation,
}

impl AccessReviewReport {
    /// Maximum length for ISO 8601 timestamp fields (bytes).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `organization_name` (bytes).
    const MAX_ORG_NAME_LEN: usize = 512;
    /// Maximum number of entries in a single report.
    ///
    /// Matches the runtime cap in `vellaveto-audit/src/access_review.rs` (10K agents).
    const MAX_ENTRIES: usize = 10_000;

    /// Validate all fields in the report: string bounds, collection bounds,
    /// control character rejection, and nested entry validation.
    ///
    /// SECURITY (FIND-R53-P4-001): The previous implementation only validated
    /// nested `AccessReviewEntry` fields but skipped bounds checks on the
    /// report's own string fields (`generated_at`, `organization_name`,
    /// `period_start`, `period_end`) and the `entries` collection size. An
    /// attacker-controlled deserialized report could contain multi-megabyte
    /// strings or unbounded entry lists, causing memory exhaustion.
    pub fn validate(&self) -> Result<(), String> {
        // ── Timestamp fields ────────────────────────────────────────────
        if self.generated_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "AccessReviewReport generated_at length {} exceeds max {}",
                self.generated_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.generated_at) {
            return Err(
                "AccessReviewReport generated_at contains control or format characters".to_string(),
            );
        }
        if self.period_start.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "AccessReviewReport period_start length {} exceeds max {}",
                self.period_start.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.period_start) {
            return Err(
                "AccessReviewReport period_start contains control or format characters".to_string(),
            );
        }
        if self.period_end.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "AccessReviewReport period_end length {} exceeds max {}",
                self.period_end.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.period_end) {
            return Err(
                "AccessReviewReport period_end contains control or format characters".to_string(),
            );
        }

        // ── Organization name ───────────────────────────────────────────
        if self.organization_name.is_empty() {
            return Err("AccessReviewReport organization_name must not be empty".to_string());
        }
        if self.organization_name.len() > Self::MAX_ORG_NAME_LEN {
            return Err(format!(
                "AccessReviewReport organization_name length {} exceeds max {}",
                self.organization_name.len(),
                Self::MAX_ORG_NAME_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.organization_name) {
            return Err(
                "AccessReviewReport organization_name contains control or format characters"
                    .to_string(),
            );
        }

        // ── Collection bounds ───────────────────────────────────────────
        if self.entries.len() > Self::MAX_ENTRIES {
            return Err(format!(
                "AccessReviewReport entries count {} exceeds max {}",
                self.entries.len(),
                Self::MAX_ENTRIES,
            ));
        }

        // ── Nested entry validation ─────────────────────────────────────
        for entry in &self.entries {
            entry.validate()?;
        }

        // ── Nested attestation validation ───────────────────────────────
        // Only validate attestation if the reviewer has filled in their name
        // (pending attestations have empty reviewer_name by design).
        if !self.attestation.reviewer_name.is_empty() {
            self.attestation.validate()?;
        }

        Ok(())
    }
}

/// Schedule for automated access review report generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSchedule {
    /// Generate a report every day.
    Daily,
    /// Generate a report every week.
    Weekly,
    /// Generate a report every month.
    Monthly,
}

impl std::fmt::Display for ReviewSchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Daily => write!(f, "daily"),
            Self::Weekly => write!(f, "weekly"),
            Self::Monthly => write!(f, "monthly"),
        }
    }
}

/// Export format for access review reports.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportExportFormat {
    /// JSON format (default).
    #[default]
    Json,
    /// Self-contained HTML format.
    Html,
}

impl std::fmt::Display for ReportExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Html => write!(f, "html"),
        }
    }
}
