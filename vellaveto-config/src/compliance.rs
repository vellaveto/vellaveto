//! Compliance evidence generation configuration.
//!
//! Configures EU AI Act and SOC 2 compliance reporting parameters.
//! Shared enums (`AiActRiskClass`, `TrustServicesCategory`) live in
//! `vellaveto-types` so both config and audit crates can use them.

use serde::{Deserialize, Serialize};
pub use vellaveto_types::compliance::{
    AccessReviewEntry, AccessReviewReport, AiActRiskClass, AttestationStatus, Cc6Evidence,
    DataClassification, ExplanationVerbosity, ProcessingPurpose, ReportExportFormat,
    ReviewSchedule, ReviewerAttestation, TrustServicesCategory,
};

// ── Validation Constants ──────────────────────────────────────────────────────

/// Maximum number of human oversight tool patterns.
pub const MAX_HUMAN_OVERSIGHT_TOOLS: usize = 500;

/// Minimum record retention in days (Art 12 floor).
pub const MIN_RETENTION_DAYS: u32 = 30;

/// Maximum SOC 2 tracked categories.
pub const MAX_SOC2_CATEGORIES: usize = 9;

// ── EU AI Act Configuration ───────────────────────────────────────────────────

/// EU AI Act compliance configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EuAiActConfig {
    /// Enable EU AI Act compliance evidence generation.
    #[serde(default = "super::default_true")]
    pub enabled: bool,

    /// Risk classification of the AI system (Art 6).
    #[serde(default)]
    pub risk_class: AiActRiskClass,

    /// Name of the deployer organization.
    #[serde(default)]
    pub deployer_name: String,

    /// Unique identifier for the AI system.
    #[serde(default)]
    pub system_id: String,

    /// Whether AI-mediated content is marked per Art 50(1).
    #[serde(default)]
    pub transparency_marking: bool,

    /// Tool patterns subject to human oversight (Art 14).
    #[serde(default)]
    pub human_oversight_tools: Vec<String>,

    /// Audit record retention in days (Art 12). Default: 365.
    #[serde(default = "default_retention_days")]
    pub record_retention_days: u32,

    /// Whether conformity assessment is claimed (Art 43).
    #[serde(default)]
    pub conformity_assessment: bool,

    /// Whether to compress rotated audit logs. Default: true.
    #[serde(default = "super::default_true")]
    pub compress_archives: bool,

    /// Art 50(2) decision explanation verbosity. Default: None.
    #[serde(default)]
    pub explanation_verbosity: ExplanationVerbosity,
}

fn default_retention_days() -> u32 {
    365
}

impl Default for EuAiActConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            risk_class: AiActRiskClass::default(),
            deployer_name: String::new(),
            system_id: String::new(),
            transparency_marking: false,
            human_oversight_tools: Vec::new(),
            record_retention_days: default_retention_days(),
            conformity_assessment: false,
            compress_archives: true,
            explanation_verbosity: ExplanationVerbosity::default(),
        }
    }
}

// ── SOC 2 Configuration ──────────────────────────────────────────────────────

/// SOC 2 compliance configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Soc2Config {
    /// Enable SOC 2 compliance evidence generation.
    #[serde(default)]
    pub enabled: bool,

    /// Organization name for the SOC 2 report.
    #[serde(default)]
    pub organization_name: String,

    /// Audit period start (ISO 8601 date).
    #[serde(default)]
    pub period_start: String,

    /// Audit period end (ISO 8601 date).
    #[serde(default)]
    pub period_end: String,

    /// Trust Services Categories to track. Empty = all 9.
    #[serde(default)]
    pub tracked_categories: Vec<TrustServicesCategory>,

    /// Phase 38: SOC 2 Type II access review configuration.
    #[serde(default)]
    pub access_review: Soc2AccessReviewConfig,
}

// ── Phase 38: SOC 2 Type II Access Review Configuration ─────────────────────

/// Maximum number of designated reviewers.
pub const MAX_ACCESS_REVIEW_REVIEWERS: usize = 50;

/// Maximum period for access review reports in days.
pub const MAX_ACCESS_REVIEW_PERIOD_DAYS: u32 = 366;

/// Maximum reviewer name length.
pub const MAX_REVIEWER_NAME_LEN: usize = 256;

/// Configuration for automated SOC 2 Type II access review report generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soc2AccessReviewConfig {
    /// Enable access review report generation.
    #[serde(default)]
    pub enabled: bool,

    /// Automated report generation schedule. None = manual only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<ReviewSchedule>,

    /// Default review period in days (used when no explicit period is provided).
    #[serde(default = "default_access_review_period_days")]
    pub default_period_days: u32,

    /// Designated reviewer names for attestation.
    #[serde(default)]
    pub reviewers: Vec<String>,
}

fn default_access_review_period_days() -> u32 {
    30
}

impl Default for Soc2AccessReviewConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: None,
            default_period_days: default_access_review_period_days(),
            reviewers: Vec::new(),
        }
    }
}

// ── Data Governance Configuration (Art 10) ────────────────────────────────────

/// Per-tool data governance mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDataMapping {
    /// Tool name or glob pattern.
    pub tool_pattern: String,
    /// Data classifications for this tool.
    pub classifications: Vec<DataClassification>,
    /// Processing purpose.
    pub purpose: ProcessingPurpose,
    /// Data provenance description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    /// Override retention period in days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

/// Art 10 data governance configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataGovernanceConfig {
    /// Enable data governance record keeping.
    #[serde(default)]
    pub enabled: bool,
    /// Per-tool data classification mappings.
    #[serde(default)]
    pub tool_mappings: Vec<ToolDataMapping>,
    /// Default retention period in days. Default: 365.
    #[serde(default = "default_governance_retention")]
    pub default_retention_days: u32,
}

fn default_governance_retention() -> u32 {
    365
}

impl Default for DataGovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tool_mappings: Vec::new(),
            default_retention_days: default_governance_retention(),
        }
    }
}

// ── Top-Level Compliance Configuration ────────────────────────────────────────

/// Top-level compliance evidence configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// EU AI Act compliance configuration.
    #[serde(default)]
    pub eu_ai_act: EuAiActConfig,

    /// SOC 2 compliance configuration.
    #[serde(default)]
    pub soc2: Soc2Config,

    /// Art 10 data governance configuration.
    #[serde(default)]
    pub data_governance: DataGovernanceConfig,
}

impl ComplianceConfig {
    /// Validate compliance configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.eu_ai_act.human_oversight_tools.len() > MAX_HUMAN_OVERSIGHT_TOOLS {
            return Err(format!(
                "eu_ai_act.human_oversight_tools has {} entries, max is {}",
                self.eu_ai_act.human_oversight_tools.len(),
                MAX_HUMAN_OVERSIGHT_TOOLS,
            ));
        }
        if self.eu_ai_act.record_retention_days < MIN_RETENTION_DAYS {
            return Err(format!(
                "eu_ai_act.record_retention_days is {}, minimum is {}",
                self.eu_ai_act.record_retention_days, MIN_RETENTION_DAYS,
            ));
        }
        if self.soc2.tracked_categories.len() > MAX_SOC2_CATEGORIES {
            return Err(format!(
                "soc2.tracked_categories has {} entries, max is {}",
                self.soc2.tracked_categories.len(),
                MAX_SOC2_CATEGORIES,
            ));
        }
        // Phase 38: Access review config validation
        let ar = &self.soc2.access_review;
        if ar.default_period_days == 0 || ar.default_period_days > MAX_ACCESS_REVIEW_PERIOD_DAYS {
            return Err(format!(
                "soc2.access_review.default_period_days must be 1–{}, got {}",
                MAX_ACCESS_REVIEW_PERIOD_DAYS, ar.default_period_days,
            ));
        }
        if ar.reviewers.len() > MAX_ACCESS_REVIEW_REVIEWERS {
            return Err(format!(
                "soc2.access_review.reviewers has {} entries, max is {}",
                ar.reviewers.len(),
                MAX_ACCESS_REVIEW_REVIEWERS,
            ));
        }
        for (i, name) in ar.reviewers.iter().enumerate() {
            if name.len() > MAX_REVIEWER_NAME_LEN {
                return Err(format!(
                    "soc2.access_review.reviewers[{}] exceeds max length ({} > {})",
                    i,
                    name.len(),
                    MAX_REVIEWER_NAME_LEN,
                ));
            }
            if name.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "soc2.access_review.reviewers[{}] contains control characters",
                    i,
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_defaults() {
        let config = ComplianceConfig::default();
        assert!(config.eu_ai_act.enabled);
        assert!(!config.soc2.enabled);
        assert_eq!(config.eu_ai_act.record_retention_days, 365);
        assert_eq!(config.eu_ai_act.risk_class, AiActRiskClass::Limited);
        assert!(config.eu_ai_act.compress_archives);
        assert_eq!(
            config.eu_ai_act.explanation_verbosity,
            ExplanationVerbosity::None
        );
        assert!(!config.data_governance.enabled);
        assert_eq!(config.data_governance.default_retention_days, 365);
    }

    #[test]
    fn test_validation_passes_defaults() {
        let config = ComplianceConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_too_many_oversight_tools() {
        let mut config = ComplianceConfig::default();
        config.eu_ai_act.human_oversight_tools = (0..501).map(|i| format!("tool_{}", i)).collect();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_retention_below_minimum() {
        let mut config = ComplianceConfig::default();
        config.eu_ai_act.record_retention_days = 10;
        let err = config.validate().unwrap_err();
        assert!(err.contains("minimum is 30"));
    }

    #[test]
    fn test_validation_too_many_soc2_categories() {
        let mut config = ComplianceConfig::default();
        config.soc2.tracked_categories = vec![
            TrustServicesCategory::CC1,
            TrustServicesCategory::CC2,
            TrustServicesCategory::CC3,
            TrustServicesCategory::CC4,
            TrustServicesCategory::CC5,
            TrustServicesCategory::CC6,
            TrustServicesCategory::CC7,
            TrustServicesCategory::CC8,
            TrustServicesCategory::CC9,
            TrustServicesCategory::CC1, // 10th — over limit
        ];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_risk_class_display() {
        assert_eq!(AiActRiskClass::HighRisk.to_string(), "High-Risk");
        assert_eq!(AiActRiskClass::Minimal.to_string(), "Minimal");
    }

    #[test]
    fn test_soc2_category_display() {
        assert_eq!(
            TrustServicesCategory::CC6.to_string(),
            "CC6: Logical and Physical Access Controls"
        );
    }

    #[test]
    fn test_serde_roundtrip_json() {
        let config = ComplianceConfig {
            eu_ai_act: EuAiActConfig {
                enabled: true,
                risk_class: AiActRiskClass::HighRisk,
                deployer_name: "Acme Corp".into(),
                system_id: "vellaveto-001".into(),
                transparency_marking: true,
                human_oversight_tools: vec!["shell_*".into()],
                record_retention_days: 730,
                conformity_assessment: true,
                compress_archives: true,
                explanation_verbosity: ExplanationVerbosity::Summary,
            },
            soc2: Soc2Config {
                enabled: true,
                organization_name: "Acme".into(),
                period_start: "2026-01-01".into(),
                period_end: "2026-12-31".into(),
                tracked_categories: vec![TrustServicesCategory::CC1, TrustServicesCategory::CC6],
                access_review: Soc2AccessReviewConfig::default(),
            },
            data_governance: DataGovernanceConfig::default(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ComplianceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.eu_ai_act.risk_class, AiActRiskClass::HighRisk);
        assert_eq!(deserialized.soc2.tracked_categories.len(), 2);
        assert_eq!(
            deserialized.eu_ai_act.explanation_verbosity,
            ExplanationVerbosity::Summary
        );
    }

    #[test]
    fn test_toml_parsing() {
        let toml_str = r#"
[eu_ai_act]
enabled = true
risk_class = "high_risk"
deployer_name = "Test"
record_retention_days = 365

[soc2]
enabled = false
"#;
        let config: ComplianceConfig = toml::from_str(toml_str).unwrap();
        assert!(config.eu_ai_act.enabled);
        assert_eq!(config.eu_ai_act.risk_class, AiActRiskClass::HighRisk);
    }

    #[test]
    fn test_toml_parsing_with_explanation_verbosity() {
        let toml_str = r#"
[eu_ai_act]
enabled = true
explanation_verbosity = "full"

[soc2]
enabled = false
"#;
        let config: ComplianceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.eu_ai_act.explanation_verbosity,
            ExplanationVerbosity::Full
        );
    }

    #[test]
    fn test_data_governance_config_serde() {
        let config = DataGovernanceConfig {
            enabled: true,
            tool_mappings: vec![ToolDataMapping {
                tool_pattern: "filesystem.*".to_string(),
                classifications: vec![DataClassification::Input, DataClassification::Output],
                purpose: ProcessingPurpose::ToolExecution,
                provenance: Some("user-provided".to_string()),
                retention_days: Some(730),
            }],
            default_retention_days: 365,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DataGovernanceConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.enabled);
        assert_eq!(deserialized.tool_mappings.len(), 1);
        assert_eq!(
            deserialized.tool_mappings[0].purpose,
            ProcessingPurpose::ToolExecution
        );
    }

    #[test]
    fn test_data_governance_default_retention() {
        let config = DataGovernanceConfig::default();
        assert_eq!(config.default_retention_days, 365);
        assert!(config.tool_mappings.is_empty());
    }

    // ── Phase 38: Access Review Config Tests ────────────────────────────────

    #[test]
    fn test_access_review_config_defaults() {
        let config = Soc2AccessReviewConfig::default();
        assert!(!config.enabled);
        assert!(config.schedule.is_none());
        assert_eq!(config.default_period_days, 30);
        assert!(config.reviewers.is_empty());
    }

    #[test]
    fn test_access_review_config_serde_roundtrip() {
        let config = Soc2AccessReviewConfig {
            enabled: true,
            schedule: Some(ReviewSchedule::Weekly),
            default_period_days: 90,
            reviewers: vec!["Alice Auditor".to_string(), "Bob Reviewer".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Soc2AccessReviewConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.enabled);
        assert_eq!(deserialized.schedule, Some(ReviewSchedule::Weekly));
        assert_eq!(deserialized.default_period_days, 90);
        assert_eq!(deserialized.reviewers.len(), 2);
    }

    #[test]
    fn test_access_review_toml_parsing() {
        let toml_str = r#"
[eu_ai_act]
enabled = true

[soc2]
enabled = true

[soc2.access_review]
enabled = true
schedule = "daily"
default_period_days = 7
reviewers = ["Alice"]
"#;
        let config: ComplianceConfig = toml::from_str(toml_str).unwrap();
        assert!(config.soc2.access_review.enabled);
        assert_eq!(
            config.soc2.access_review.schedule,
            Some(ReviewSchedule::Daily)
        );
        assert_eq!(config.soc2.access_review.default_period_days, 7);
    }

    #[test]
    fn test_access_review_validation_period_zero() {
        let mut config = ComplianceConfig::default();
        config.soc2.access_review.default_period_days = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("default_period_days"));
    }

    #[test]
    fn test_access_review_validation_period_too_large() {
        let mut config = ComplianceConfig::default();
        config.soc2.access_review.default_period_days = 367;
        let err = config.validate().unwrap_err();
        assert!(err.contains("default_period_days"));
    }

    #[test]
    fn test_access_review_validation_too_many_reviewers() {
        let mut config = ComplianceConfig::default();
        config.soc2.access_review.reviewers = (0..51).map(|i| format!("reviewer_{}", i)).collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("reviewers"));
    }

    #[test]
    fn test_access_review_validation_reviewer_name_too_long() {
        let mut config = ComplianceConfig::default();
        config.soc2.access_review.reviewers = vec!["a".repeat(257)];
        let err = config.validate().unwrap_err();
        assert!(err.contains("exceeds max length"));
    }

    #[test]
    fn test_access_review_validation_reviewer_control_chars() {
        let mut config = ComplianceConfig::default();
        config.soc2.access_review.reviewers = vec!["Alice\x00Bob".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_soc2_config_with_access_review_defaults() {
        let config = ComplianceConfig::default();
        // access_review should default to disabled
        assert!(!config.soc2.access_review.enabled);
        // Overall validation should still pass
        assert!(config.validate().is_ok());
    }
}
