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

/// Per-agent access review entry for SOC 2 Type II reporting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// Validate that `usage_ratio` is a finite number (not NaN or infinity).
    ///
    /// SECURITY (FIND-R49-003): Non-finite floats can cause unexpected behavior
    /// in comparisons, serialization, and downstream reporting logic.
    pub fn validate_finite(&self) -> Result<(), String> {
        if !self.usage_ratio.is_finite() {
            return Err(format!(
                "AccessReviewEntry for agent '{}' has non-finite usage_ratio: {}",
                self.agent_id, self.usage_ratio,
            ));
        }
        Ok(())
    }
}

/// CC6 (Logical and Physical Access Controls) evidence summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// Validate all entries in the report.
    ///
    /// Calls `validate_finite()` on each `AccessReviewEntry` to ensure no
    /// non-finite `usage_ratio` values are present.
    pub fn validate(&self) -> Result<(), String> {
        for entry in &self.entries {
            entry.validate_finite()?;
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
