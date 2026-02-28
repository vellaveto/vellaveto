// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Policy lifecycle management types.
//!
//! Provides versioned policy lifecycle with status transitions:
//! `Draft → Staging → Active → Archived`
//!
//! Used by Phase 47 for policy approval workflows, staging shadow evaluation,
//! structural diffs, and rollback.

use serde::{Deserialize, Serialize};

use crate::has_dangerous_chars;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum number of versions stored per policy.
pub const MAX_VERSIONS_PER_POLICY: usize = 100;

/// Maximum total versions across all policies.
pub const MAX_TOTAL_VERSIONS: usize = 10_000;

/// Maximum number of required approvers for a version promotion.
pub const MAX_REQUIRED_APPROVERS: usize = 20;

/// Maximum length of a version comment.
pub const MAX_VERSION_COMMENT_LEN: usize = 4_096;

/// Maximum length of lifecycle identity strings (created_by, approved_by).
pub const MAX_LIFECYCLE_IDENTITY_LEN: usize = 256;

/// Maximum number of approvals per version.
pub const MAX_APPROVALS_PER_VERSION: usize = 50;

/// Maximum number of staging report divergence entries.
pub const MAX_STAGING_REPORT_ENTRIES: usize = 10_000;

/// Maximum number of diff changes.
pub const MAX_DIFF_CHANGES: usize = 100;

/// Maximum length for tool/function name strings in staging comparison entries.
/// Matches MAX_NAME_LEN (256) used in core.rs for Action tool/function validation.
pub const MAX_STAGING_NAME_LEN: usize = 256;

/// Maximum length for verdict strings in staging comparison entries.
pub const MAX_VERDICT_STRING_LEN: usize = 128;

/// Maximum length for individual diff change description strings.
pub const MAX_DIFF_CHANGE_LEN: usize = 4_096;

/// Maximum length for policy_id in PolicyVersionDiff.
pub const MAX_DIFF_POLICY_ID_LEN: usize = 256;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Status of a policy version in its lifecycle.
///
/// Transitions: Draft → Staging → Active → Archived
/// - `Draft`: Initial state, can be edited and approved
/// - `Staging`: Shadow evaluation mode, no enforcement impact
/// - `Active`: Live enforcement, only one active version per policy
/// - `Archived`: Historical record, immutable
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PolicyVersionStatus {
    Draft,
    Staging,
    Active,
    Archived,
}

impl std::fmt::Display for PolicyVersionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Staging => write!(f, "staging"),
            Self::Active => write!(f, "active"),
            Self::Archived => write!(f, "archived"),
        }
    }
}

/// An approval record for a policy version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyApproval {
    /// Identity of the approver.
    pub approved_by: String,
    /// ISO 8601 timestamp of when the approval was recorded.
    pub approved_at: String,
    /// Optional comment from the approver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl PolicyApproval {
    /// Validate approval fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.approved_by.is_empty() || self.approved_by.trim().is_empty() {
            return Err("approved_by must be non-empty".to_string());
        }
        if self.approved_by.len() > MAX_LIFECYCLE_IDENTITY_LEN {
            return Err(format!(
                "approved_by exceeds {} chars",
                MAX_LIFECYCLE_IDENTITY_LEN
            ));
        }
        if has_dangerous_chars(&self.approved_by) {
            return Err("approved_by contains invalid characters".to_string());
        }
        if self.approved_at.is_empty() {
            return Err("approved_at must be non-empty".to_string());
        }
        if has_dangerous_chars(&self.approved_at) {
            return Err("approved_at contains invalid characters".to_string());
        }
        // Validate timestamp format
        crate::time_util::parse_iso8601_secs(&self.approved_at)
            .map_err(|e| format!("approved_at: {}", e))?;
        if let Some(ref c) = self.comment {
            if c.len() > MAX_VERSION_COMMENT_LEN {
                return Err(format!(
                    "approval comment exceeds {} chars",
                    MAX_VERSION_COMMENT_LEN
                ));
            }
            if has_dangerous_chars(c) {
                return Err("approval comment contains invalid characters".to_string());
            }
        }
        Ok(())
    }
}

/// A versioned policy record with lifecycle status and approval tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyVersion {
    /// Unique identifier for this version (e.g., UUID).
    pub version_id: String,
    /// Policy ID this version belongs to.
    pub policy_id: String,
    /// Monotonically increasing version number within this policy.
    pub version: u64,
    /// The full policy definition at this version.
    pub policy: crate::Policy,
    /// Identity of the user who created this version.
    pub created_by: String,
    /// ISO 8601 timestamp of creation.
    pub created_at: String,
    /// Current lifecycle status.
    pub status: PolicyVersionStatus,
    /// Optional comment describing the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Approvals collected for this version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<PolicyApproval>,
    /// Number of approvals required before promotion.
    #[serde(default)]
    pub required_approvals: u32,
    /// Link to the previous version (for rollback chain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version_id: Option<String>,

    /// ISO 8601 timestamp of when this version entered Staging status.
    /// Set automatically when promoting Draft → Staging.
    /// Used to enforce `staging_period_secs` before allowing Staging → Active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_at: Option<String>,
}

impl PolicyVersion {
    /// Validate all fields of this version.
    pub fn validate(&self) -> Result<(), String> {
        // version_id
        if self.version_id.is_empty() {
            return Err("version_id must be non-empty".to_string());
        }
        if self.version_id.len() > MAX_LIFECYCLE_IDENTITY_LEN {
            return Err(format!(
                "version_id exceeds {} chars",
                MAX_LIFECYCLE_IDENTITY_LEN
            ));
        }
        if has_dangerous_chars(&self.version_id) {
            return Err("version_id contains invalid characters".to_string());
        }
        // policy_id
        if self.policy_id.is_empty() {
            return Err("policy_id must be non-empty".to_string());
        }
        // MAX_POLICY_ID_LEN = 256 (matches core.rs Policy::validate())
        if self.policy_id.len() > 256 {
            return Err("policy_id exceeds 256 chars".to_string());
        }
        if has_dangerous_chars(&self.policy_id) {
            return Err("policy_id contains invalid characters".to_string());
        }
        // version
        if self.version == 0 {
            return Err("version must be >= 1".to_string());
        }
        // policy
        self.policy
            .validate()
            .map_err(|e| format!("policy: {}", e))?;
        // created_by
        if self.created_by.is_empty() || self.created_by.trim().is_empty() {
            return Err("created_by must be non-empty".to_string());
        }
        if self.created_by.len() > MAX_LIFECYCLE_IDENTITY_LEN {
            return Err(format!(
                "created_by exceeds {} chars",
                MAX_LIFECYCLE_IDENTITY_LEN
            ));
        }
        if has_dangerous_chars(&self.created_by) {
            return Err("created_by contains invalid characters".to_string());
        }
        // created_at
        if self.created_at.is_empty() {
            return Err("created_at must be non-empty".to_string());
        }
        if has_dangerous_chars(&self.created_at) {
            return Err("created_at contains invalid characters".to_string());
        }
        crate::time_util::parse_iso8601_secs(&self.created_at)
            .map_err(|e| format!("created_at: {}", e))?;
        // comment
        if let Some(ref c) = self.comment {
            if c.len() > MAX_VERSION_COMMENT_LEN {
                return Err(format!("comment exceeds {} chars", MAX_VERSION_COMMENT_LEN));
            }
            if has_dangerous_chars(c) {
                return Err("comment contains invalid characters".to_string());
            }
        }
        // approvals
        if self.approvals.len() > MAX_APPROVALS_PER_VERSION {
            return Err(format!(
                "approvals count {} exceeds max {}",
                self.approvals.len(),
                MAX_APPROVALS_PER_VERSION
            ));
        }
        for (i, a) in self.approvals.iter().enumerate() {
            a.validate()
                .map_err(|e| format!("approval[{}]: {}", i, e))?;
        }
        // required_approvals
        if self.required_approvals as usize > MAX_REQUIRED_APPROVERS {
            return Err(format!(
                "required_approvals {} exceeds max {}",
                self.required_approvals, MAX_REQUIRED_APPROVERS
            ));
        }
        // staged_at
        if let Some(ref ts) = self.staged_at {
            if ts.is_empty() {
                return Err("staged_at must be non-empty when present".to_string());
            }
            if has_dangerous_chars(ts) {
                return Err("staged_at contains invalid characters".to_string());
            }
            crate::time_util::parse_iso8601_secs(ts).map_err(|e| format!("staged_at: {}", e))?;
        }
        // previous_version_id
        if let Some(ref prev) = self.previous_version_id {
            if prev.len() > MAX_LIFECYCLE_IDENTITY_LEN {
                return Err(format!(
                    "previous_version_id exceeds {} chars",
                    MAX_LIFECYCLE_IDENTITY_LEN
                ));
            }
            if has_dangerous_chars(prev) {
                return Err("previous_version_id contains invalid characters".to_string());
            }
        }
        Ok(())
    }
}

/// Structural diff between two policy versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyVersionDiff {
    /// Policy ID being compared.
    pub policy_id: String,
    /// Source version number.
    pub from_version: u64,
    /// Target version number.
    pub to_version: u64,
    /// List of human-readable changes.
    pub changes: Vec<String>,
}

impl PolicyVersionDiff {
    /// Validate diff fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_id.is_empty() {
            return Err("policy_id must be non-empty".to_string());
        }
        if self.policy_id.len() > MAX_DIFF_POLICY_ID_LEN {
            return Err(format!(
                "policy_id exceeds {} chars",
                MAX_DIFF_POLICY_ID_LEN
            ));
        }
        if has_dangerous_chars(&self.policy_id) {
            return Err("policy_id contains invalid characters".to_string());
        }
        if self.changes.len() > MAX_DIFF_CHANGES {
            return Err(format!(
                "changes count {} exceeds max {}",
                self.changes.len(),
                MAX_DIFF_CHANGES
            ));
        }
        // SECURITY (FIND-R205-004): Validate individual change strings
        // to prevent unbounded allocation and dangerous character injection.
        for (i, change) in self.changes.iter().enumerate() {
            if change.len() > MAX_DIFF_CHANGE_LEN {
                return Err(format!(
                    "changes[{}] exceeds {} chars",
                    i, MAX_DIFF_CHANGE_LEN
                ));
            }
            if has_dangerous_chars(change) {
                return Err(format!("changes[{}] contains invalid characters", i));
            }
        }
        Ok(())
    }
}

/// A single staging comparison entry recording a divergence between
/// active and staging policy evaluation results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagingComparisonEntry {
    /// ISO 8601 timestamp of the evaluation.
    pub timestamp: String,
    /// Tool name from the action.
    pub tool: String,
    /// Function name from the action.
    pub function: String,
    /// Verdict from the active policy set.
    pub active_verdict: String,
    /// Verdict from the staging policy set.
    pub staging_verdict: String,
}

impl StagingComparisonEntry {
    /// Validate all fields of this staging comparison entry.
    ///
    /// SECURITY (FIND-R205-002): Each string field is checked for dangerous
    /// characters and bounded by length. The timestamp is validated as ISO 8601.
    pub fn validate(&self) -> Result<(), String> {
        // timestamp
        if self.timestamp.is_empty() {
            return Err("timestamp must be non-empty".to_string());
        }
        if has_dangerous_chars(&self.timestamp) {
            return Err("timestamp contains invalid characters".to_string());
        }
        crate::time_util::parse_iso8601_secs(&self.timestamp)
            .map_err(|e| format!("timestamp: {}", e))?;
        // tool
        if self.tool.is_empty() {
            return Err("tool must be non-empty".to_string());
        }
        if self.tool.len() > MAX_STAGING_NAME_LEN {
            return Err(format!("tool exceeds {} chars", MAX_STAGING_NAME_LEN));
        }
        if has_dangerous_chars(&self.tool) {
            return Err("tool contains invalid characters".to_string());
        }
        // function
        if self.function.is_empty() {
            return Err("function must be non-empty".to_string());
        }
        if self.function.len() > MAX_STAGING_NAME_LEN {
            return Err(format!("function exceeds {} chars", MAX_STAGING_NAME_LEN));
        }
        if has_dangerous_chars(&self.function) {
            return Err("function contains invalid characters".to_string());
        }
        // active_verdict
        if self.active_verdict.is_empty() {
            return Err("active_verdict must be non-empty".to_string());
        }
        if self.active_verdict.len() > MAX_VERDICT_STRING_LEN {
            return Err(format!(
                "active_verdict exceeds {} chars",
                MAX_VERDICT_STRING_LEN
            ));
        }
        if has_dangerous_chars(&self.active_verdict) {
            return Err("active_verdict contains invalid characters".to_string());
        }
        // staging_verdict
        if self.staging_verdict.is_empty() {
            return Err("staging_verdict must be non-empty".to_string());
        }
        if self.staging_verdict.len() > MAX_VERDICT_STRING_LEN {
            return Err(format!(
                "staging_verdict exceeds {} chars",
                MAX_VERDICT_STRING_LEN
            ));
        }
        if has_dangerous_chars(&self.staging_verdict) {
            return Err("staging_verdict contains invalid characters".to_string());
        }
        Ok(())
    }
}

/// Report summarizing staging shadow evaluation results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagingReport {
    /// Policy ID being staged.
    pub policy_id: String,
    /// Version number in staging.
    pub staging_version: u64,
    /// Total evaluations observed during staging.
    pub total_evaluations: u64,
    /// Number of evaluations where staging differed from active.
    pub divergent_evaluations: u64,
    /// Detailed divergence entries (bounded by MAX_STAGING_REPORT_ENTRIES).
    pub divergences: Vec<StagingComparisonEntry>,
    /// ISO 8601 timestamp when staging began.
    pub staging_started_at: String,
}

impl StagingReport {
    /// Validate report fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_id.is_empty() {
            return Err("policy_id must be non-empty".to_string());
        }
        // SECURITY (FIND-R209-004): Enforce length bound on policy_id,
        // matching PolicyVersionDiff::validate() which uses MAX_DIFF_POLICY_ID_LEN.
        if self.policy_id.len() > MAX_DIFF_POLICY_ID_LEN {
            return Err(format!(
                "policy_id exceeds {} chars",
                MAX_DIFF_POLICY_ID_LEN
            ));
        }
        if has_dangerous_chars(&self.policy_id) {
            return Err("policy_id contains invalid characters".to_string());
        }
        // SECURITY (FIND-R224-004): Reject divergent_evaluations exceeding total_evaluations.
        // This invariant must always hold; a violation indicates data corruption or tampering.
        if self.divergent_evaluations > self.total_evaluations {
            return Err(format!(
                "divergent_evaluations ({}) exceeds total_evaluations ({})",
                self.divergent_evaluations, self.total_evaluations
            ));
        }
        if self.divergences.len() > MAX_STAGING_REPORT_ENTRIES {
            return Err(format!(
                "divergences count {} exceeds max {}",
                self.divergences.len(),
                MAX_STAGING_REPORT_ENTRIES
            ));
        }
        // SECURITY (FIND-R205-002): Validate each divergence entry.
        for (i, entry) in self.divergences.iter().enumerate() {
            entry
                .validate()
                .map_err(|e| format!("divergences[{}]: {}", i, e))?;
        }
        // IMP-R206-010: Validate staging_started_at timestamp (parity
        // with PolicyApproval::validate and PolicyVersion::validate).
        if self.staging_started_at.is_empty() {
            return Err("staging_started_at must be non-empty".to_string());
        }
        if has_dangerous_chars(&self.staging_started_at) {
            return Err("staging_started_at contains invalid characters".to_string());
        }
        crate::time_util::parse_iso8601_secs(&self.staging_started_at)
            .map_err(|e| format!("staging_started_at: {}", e))?;
        Ok(())
    }
}

/// Status summary of the policy lifecycle subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleStatus {
    /// Whether policy lifecycle management is enabled.
    pub enabled: bool,
    /// Number of policies with version tracking.
    pub tracked_policies: usize,
    /// Total number of versions across all policies.
    pub total_versions: usize,
    /// Number of policies currently in staging.
    pub staging_count: usize,
    /// Whether approval workflow is required (required_approvals > 0).
    pub approval_workflow_enabled: bool,
}

impl PolicyLifecycleStatus {
    /// Validate structural invariants on deserialized status data.
    ///
    /// SECURITY (FIND-R224-007): Prevents inconsistent or oversized status values
    /// from untrusted deserialized payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.total_versions > MAX_TOTAL_VERSIONS {
            return Err(format!(
                "total_versions ({}) exceeds MAX_TOTAL_VERSIONS ({})",
                self.total_versions, MAX_TOTAL_VERSIONS
            ));
        }
        if self.staging_count > self.tracked_policies {
            return Err(format!(
                "staging_count ({}) exceeds tracked_policies ({})",
                self.staging_count, self.tracked_policies
            ));
        }
        Ok(())
    }
}
