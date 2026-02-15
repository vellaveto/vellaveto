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
