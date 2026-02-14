//! Compliance evidence generation configuration.
//!
//! Configures EU AI Act and SOC 2 compliance reporting parameters.
//! Shared enums (`AiActRiskClass`, `TrustServicesCategory`) live in
//! `sentinel-types` so both config and audit crates can use them.

pub use sentinel_types::compliance::{AiActRiskClass, TrustServicesCategory};
use serde::{Deserialize, Serialize};

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
                system_id: "sentinel-001".into(),
                transparency_marking: true,
                human_oversight_tools: vec!["shell_*".into()],
                record_retention_days: 730,
                conformity_assessment: true,
            },
            soc2: Soc2Config {
                enabled: true,
                organization_name: "Acme".into(),
                period_start: "2026-01-01".into(),
                period_end: "2026-12-31".into(),
                tracked_categories: vec![TrustServicesCategory::CC1, TrustServicesCategory::CC6],
            },
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ComplianceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.eu_ai_act.risk_class, AiActRiskClass::HighRisk);
        assert_eq!(deserialized.soc2.tracked_categories.len(), 2);
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
}
