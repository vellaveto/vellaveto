// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! ISO/IEC 27090 AI Cybersecurity preparation module.
//!
//! ISO/IEC 27090 is the emerging international standard for AI-specific cybersecurity
//! guidance, extending the ISO 27001/27002 framework for AI systems. This module
//! maps Vellaveto capabilities to the expected control domains and provides readiness
//! assessment for future certification.
//!
//! Control domains based on ISO 27090 draft structure:
//! - Data Security (AI training and inference data protection)
//! - Model Security (model integrity, access control, lifecycle)
//! - Operational Security (deployment, monitoring, incident response)
//! - Supply Chain Security (third-party AI components)
//! - Privacy & Ethics (bias, transparency, accountability)
//!
//! Reference: ISO/IEC JTC 1/SC 42 AI Standards

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ISO 27090 control domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlDomain {
    /// Protection of AI training and inference data
    DataSecurity,
    /// Model integrity, access control, and lifecycle management
    ModelSecurity,
    /// Deployment, monitoring, and incident response
    OperationalSecurity,
    /// Third-party AI components and dependencies
    SupplyChainSecurity,
    /// Bias detection, transparency, and accountability
    PrivacyEthics,
}

impl std::fmt::Display for ControlDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlDomain::DataSecurity => write!(f, "Data Security"),
            ControlDomain::ModelSecurity => write!(f, "Model Security"),
            ControlDomain::OperationalSecurity => write!(f, "Operational Security"),
            ControlDomain::SupplyChainSecurity => write!(f, "Supply Chain Security"),
            ControlDomain::PrivacyEthics => write!(f, "Privacy & Ethics"),
        }
    }
}

/// Control identifier (e.g., "DS.1", "MS.2.3").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ControlId(pub String);

impl ControlId {
    pub fn new(domain: ControlDomain, category: u8, control: Option<u8>) -> Self {
        let prefix = match domain {
            ControlDomain::DataSecurity => "DS",
            ControlDomain::ModelSecurity => "MS",
            ControlDomain::OperationalSecurity => "OS",
            ControlDomain::SupplyChainSecurity => "SC",
            ControlDomain::PrivacyEthics => "PE",
        };

        if let Some(c) = control {
            Self(format!("{prefix}.{category}.{c}"))
        } else {
            Self(format!("{prefix}.{category}"))
        }
    }

    pub fn domain(&self) -> Option<ControlDomain> {
        let prefix = self.0.split('.').next()?;
        match prefix {
            "DS" => Some(ControlDomain::DataSecurity),
            "MS" => Some(ControlDomain::ModelSecurity),
            "OS" => Some(ControlDomain::OperationalSecurity),
            "SC" => Some(ControlDomain::SupplyChainSecurity),
            "PE" => Some(ControlDomain::PrivacyEthics),
            _ => None,
        }
    }
}

impl std::fmt::Display for ControlId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Expected ISO 27090 control with description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedControl {
    pub id: ControlId,
    pub domain: ControlDomain,
    pub name: String,
    pub description: String,
    pub objective: String,
}

/// Vellaveto capability that addresses ISO 27090 controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityCapability {
    // Data Security
    DataLeakagePrevention,
    InputValidation,
    OutputSanitization,
    DataClassification,
    EncryptionAtRest,
    EncryptionInTransit,

    // Model Security
    ModelAccessControl,
    SchemaIntegrityChecking,
    VersionTracking,
    AnomalyDetection,
    AdversarialInputDetection,

    // Operational Security
    AuditLogging,
    RealTimeMonitoring,
    IncidentResponse,
    CircuitBreaker,
    KillSwitch,
    PolicyEnforcement,

    // Supply Chain Security
    ThirdPartyValidation,
    ToolAttestation,
    DependencyScanning,
    RugPullDetection,
    ToolSquattingDetection,

    // Privacy & Ethics
    ConsentManagement,
    BiasDetection,
    ExplainabilitySupport,
    HumanOversight,
    TransparencyReporting,
}

impl std::fmt::Display for SecurityCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Readiness level for a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReadinessLevel {
    /// No implementation
    NotStarted,
    /// Some groundwork in place
    Initial,
    /// Partially implemented
    Developing,
    /// Mostly complete, needs refinement
    Defined,
    /// Fully implemented, actively managed
    Managed,
    /// Continuously optimized
    Optimizing,
}

impl ReadinessLevel {
    pub fn score(&self) -> u8 {
        match self {
            ReadinessLevel::NotStarted => 0,
            ReadinessLevel::Initial => 1,
            ReadinessLevel::Developing => 2,
            ReadinessLevel::Defined => 3,
            ReadinessLevel::Managed => 4,
            ReadinessLevel::Optimizing => 5,
        }
    }
}

impl std::fmt::Display for ReadinessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadinessLevel::NotStarted => write!(f, "Not Started (0)"),
            ReadinessLevel::Initial => write!(f, "Initial (1)"),
            ReadinessLevel::Developing => write!(f, "Developing (2)"),
            ReadinessLevel::Defined => write!(f, "Defined (3)"),
            ReadinessLevel::Managed => write!(f, "Managed (4)"),
            ReadinessLevel::Optimizing => write!(f, "Optimizing (5)"),
        }
    }
}

/// Mapping between a Vellaveto capability and an ISO 27090 control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMapping {
    pub control_id: ControlId,
    pub capability: SecurityCapability,
    pub readiness: ReadinessLevel,
    pub evidence: Option<String>,
    pub gaps: Vec<String>,
}

/// ISO 27090 readiness registry.
#[derive(Debug, Default)]
pub struct Iso27090Registry {
    controls: HashMap<ControlId, ExpectedControl>,
    mappings: Vec<ControlMapping>,
}

impl Iso27090Registry {
    /// Create a new registry with expected controls and Vellaveto mappings.
    pub fn new() -> Self {
        let mut registry = Self::default();
        registry.populate_controls();
        registry.populate_mappings();
        registry
    }

    fn populate_controls(&mut self) {
        // Data Security controls
        self.add_control(
            ControlDomain::DataSecurity,
            1,
            None,
            "Data Classification",
            "Classification scheme for AI training and inference data",
            "Ensure all data used in AI systems is classified according to sensitivity",
        );

        self.add_control(
            ControlDomain::DataSecurity,
            2,
            None,
            "Data Leakage Prevention",
            "Controls to prevent unauthorized data exfiltration",
            "Prevent sensitive data from being leaked through AI inputs or outputs",
        );

        self.add_control(
            ControlDomain::DataSecurity,
            3,
            None,
            "Input Validation",
            "Validation of all inputs to AI systems",
            "Ensure all inputs are validated before processing by AI models",
        );

        self.add_control(
            ControlDomain::DataSecurity,
            4,
            None,
            "Output Sanitization",
            "Sanitization of AI system outputs",
            "Ensure outputs do not contain sensitive or harmful content",
        );

        self.add_control(
            ControlDomain::DataSecurity,
            5,
            None,
            "Data Encryption",
            "Encryption of data at rest and in transit",
            "Protect AI data through cryptographic controls",
        );

        // Model Security controls
        self.add_control(
            ControlDomain::ModelSecurity,
            1,
            None,
            "Model Access Control",
            "Access control for AI models and configurations",
            "Restrict access to AI models based on authorization",
        );

        self.add_control(
            ControlDomain::ModelSecurity,
            2,
            None,
            "Model Integrity",
            "Integrity verification of AI models",
            "Detect unauthorized modifications to AI models",
        );

        self.add_control(
            ControlDomain::ModelSecurity,
            3,
            None,
            "Model Versioning",
            "Version control for AI models",
            "Track and manage changes to AI models over time",
        );

        self.add_control(
            ControlDomain::ModelSecurity,
            4,
            None,
            "Adversarial Defense",
            "Protection against adversarial inputs",
            "Detect and mitigate adversarial attacks on AI models",
        );

        self.add_control(
            ControlDomain::ModelSecurity,
            5,
            None,
            "Anomaly Detection",
            "Detection of anomalous model behavior",
            "Identify when AI models exhibit unexpected behavior",
        );

        // Operational Security controls
        self.add_control(
            ControlDomain::OperationalSecurity,
            1,
            None,
            "Audit Logging",
            "Comprehensive logging of AI system activities",
            "Maintain tamper-evident audit trails of all AI operations",
        );

        self.add_control(
            ControlDomain::OperationalSecurity,
            2,
            None,
            "Real-time Monitoring",
            "Continuous monitoring of AI system behavior",
            "Detect security events and anomalies in real-time",
        );

        self.add_control(
            ControlDomain::OperationalSecurity,
            3,
            None,
            "Incident Response",
            "Response procedures for AI security incidents",
            "Enable rapid response to AI-related security incidents",
        );

        self.add_control(
            ControlDomain::OperationalSecurity,
            4,
            None,
            "Policy Enforcement",
            "Enforcement of security policies on AI operations",
            "Ensure AI operations comply with organizational policies",
        );

        self.add_control(
            ControlDomain::OperationalSecurity,
            5,
            None,
            "Emergency Controls",
            "Emergency shutdown and recovery capabilities",
            "Ability to quickly disable AI systems when needed",
        );

        // Supply Chain Security controls
        self.add_control(
            ControlDomain::SupplyChainSecurity,
            1,
            None,
            "Third-party Validation",
            "Validation of third-party AI components",
            "Verify the security of AI components from external sources",
        );

        self.add_control(
            ControlDomain::SupplyChainSecurity,
            2,
            None,
            "Tool Attestation",
            "Attestation of AI tool authenticity",
            "Verify that AI tools are from legitimate sources",
        );

        self.add_control(
            ControlDomain::SupplyChainSecurity,
            3,
            None,
            "Dependency Management",
            "Management of AI system dependencies",
            "Track and secure dependencies in AI systems",
        );

        self.add_control(
            ControlDomain::SupplyChainSecurity,
            4,
            None,
            "Supply Chain Threats",
            "Detection of supply chain attacks",
            "Identify rug pulls, tool squatting, and other supply chain threats",
        );

        // Privacy & Ethics controls
        self.add_control(
            ControlDomain::PrivacyEthics,
            1,
            None,
            "Consent Management",
            "Management of data subject consent",
            "Ensure proper consent is obtained for AI data processing",
        );

        self.add_control(
            ControlDomain::PrivacyEthics,
            2,
            None,
            "Bias Detection",
            "Detection of bias in AI systems",
            "Identify and mitigate bias in AI decision-making",
        );

        self.add_control(
            ControlDomain::PrivacyEthics,
            3,
            None,
            "Explainability",
            "Explainability of AI decisions",
            "Provide explanations for AI system decisions",
        );

        self.add_control(
            ControlDomain::PrivacyEthics,
            4,
            None,
            "Human Oversight",
            "Human oversight of AI systems",
            "Ensure human review and approval of critical AI decisions",
        );

        self.add_control(
            ControlDomain::PrivacyEthics,
            5,
            None,
            "Transparency",
            "Transparency reporting for AI systems",
            "Report on AI system behavior and decisions",
        );
    }

    fn add_control(
        &mut self,
        domain: ControlDomain,
        category: u8,
        control: Option<u8>,
        name: &str,
        description: &str,
        objective: &str,
    ) {
        let id = ControlId::new(domain, category, control);
        self.controls.insert(
            id.clone(),
            ExpectedControl {
                id,
                domain,
                name: name.to_string(),
                description: description.to_string(),
                objective: objective.to_string(),
            },
        );
    }

    fn populate_mappings(&mut self) {
        // Data Security mappings
        self.add_mapping(
            "DS.1",
            SecurityCapability::DataClassification,
            ReadinessLevel::Developing,
            Some("PII scanner classifies sensitive data types"),
            vec!["No formal data classification taxonomy".to_string()],
        );

        self.add_mapping(
            "DS.2",
            SecurityCapability::DataLeakagePrevention,
            ReadinessLevel::Managed,
            Some("DLP scanning with 5-layer decode, cross-request flow tracking"),
            vec![],
        );

        self.add_mapping(
            "DS.3",
            SecurityCapability::InputValidation,
            ReadinessLevel::Managed,
            Some("Injection detection, parameter constraints, path/network rules"),
            vec![],
        );

        self.add_mapping(
            "DS.4",
            SecurityCapability::OutputSanitization,
            ReadinessLevel::Managed,
            Some("Output validation, schema registry, steganography detection"),
            vec![],
        );

        self.add_mapping(
            "DS.5",
            SecurityCapability::EncryptionInTransit,
            ReadinessLevel::Managed,
            Some("TLS required for all external communications"),
            vec![],
        );

        // Model Security mappings
        self.add_mapping(
            "MS.1",
            SecurityCapability::ModelAccessControl,
            ReadinessLevel::Managed,
            Some("OAuth 2.1, JWT validation, agent attestation"),
            vec![],
        );

        self.add_mapping(
            "MS.2",
            SecurityCapability::SchemaIntegrityChecking,
            ReadinessLevel::Managed,
            Some("Schema lineage tracking, mutation detection, poisoning alerts"),
            vec![],
        );

        self.add_mapping(
            "MS.3",
            SecurityCapability::VersionTracking,
            ReadinessLevel::Developing,
            Some("Tool registry with version tracking"),
            vec!["No model versioning in proxy mode".to_string()],
        );

        self.add_mapping(
            "MS.4",
            SecurityCapability::AdversarialInputDetection,
            ReadinessLevel::Managed,
            Some("Injection detection, token smuggling, semantic analysis"),
            vec![],
        );

        self.add_mapping(
            "MS.5",
            SecurityCapability::AnomalyDetection,
            ReadinessLevel::Managed,
            Some("Behavioral anomaly detection, goal drift, shadow agents"),
            vec![],
        );

        // Operational Security mappings
        self.add_mapping(
            "OS.1",
            SecurityCapability::AuditLogging,
            ReadinessLevel::Optimizing,
            Some("Tamper-evident audit log with SHA-256 chain, Ed25519 checkpoints"),
            vec![],
        );

        self.add_mapping(
            "OS.2",
            SecurityCapability::RealTimeMonitoring,
            ReadinessLevel::Managed,
            Some("Prometheus metrics, behavioral tracking, workflow monitoring"),
            vec![],
        );

        self.add_mapping(
            "OS.3",
            SecurityCapability::IncidentResponse,
            ReadinessLevel::Managed,
            Some("Circuit breaker, kill switch, audit export to SIEM"),
            vec![],
        );

        self.add_mapping(
            "OS.4",
            SecurityCapability::PolicyEnforcement,
            ReadinessLevel::Optimizing,
            Some("Policy engine with hot reload, context conditions, parameter constraints"),
            vec![],
        );

        self.add_mapping(
            "OS.5",
            SecurityCapability::KillSwitch,
            ReadinessLevel::Managed,
            Some("Emergency kill switch for immediate session termination"),
            vec![],
        );

        // Supply Chain Security mappings
        self.add_mapping(
            "SC.1",
            SecurityCapability::ThirdPartyValidation,
            ReadinessLevel::Managed,
            Some("Tool registry with trust scoring, schema validation"),
            vec![],
        );

        self.add_mapping(
            "SC.2",
            SecurityCapability::ToolAttestation,
            ReadinessLevel::Managed,
            Some("Agent identity attestation via signed JWTs"),
            vec![],
        );

        self.add_mapping(
            "SC.3",
            SecurityCapability::DependencyScanning,
            ReadinessLevel::Developing,
            Some("cargo audit in CI"),
            vec!["No runtime dependency validation".to_string()],
        );

        self.add_mapping(
            "SC.4",
            SecurityCapability::RugPullDetection,
            ReadinessLevel::Managed,
            Some("Rug pull detection with annotation/schema mutation tracking"),
            vec![],
        );

        self.add_mapping(
            "SC.4",
            SecurityCapability::ToolSquattingDetection,
            ReadinessLevel::Managed,
            Some("Levenshtein + homoglyph detection for tool squatting"),
            vec![],
        );

        // Privacy & Ethics mappings
        self.add_mapping(
            "PE.1",
            SecurityCapability::ConsentManagement,
            ReadinessLevel::Initial,
            Some("Human approval flow for sensitive operations"),
            vec![
                "No formal consent tracking".to_string(),
                "No data subject rights management".to_string(),
            ],
        );

        self.add_mapping(
            "PE.2",
            SecurityCapability::BiasDetection,
            ReadinessLevel::NotStarted,
            None,
            vec![
                "Bias detection not implemented".to_string(),
                "Out of scope for security proxy".to_string(),
            ],
        );

        self.add_mapping(
            "PE.3",
            SecurityCapability::ExplainabilitySupport,
            ReadinessLevel::Developing,
            Some("Detailed deny reasons in verdicts, audit metadata"),
            vec!["No formal explainability framework".to_string()],
        );

        self.add_mapping(
            "PE.4",
            SecurityCapability::HumanOversight,
            ReadinessLevel::Managed,
            Some("Human-in-the-loop approvals with deduplication"),
            vec![],
        );

        self.add_mapping(
            "PE.5",
            SecurityCapability::TransparencyReporting,
            ReadinessLevel::Developing,
            Some("Audit log export, metrics dashboard"),
            vec!["No automated compliance reporting".to_string()],
        );
    }

    fn add_mapping(
        &mut self,
        control_id: &str,
        capability: SecurityCapability,
        readiness: ReadinessLevel,
        evidence: Option<&str>,
        gaps: Vec<String>,
    ) {
        self.mappings.push(ControlMapping {
            control_id: ControlId(control_id.to_string()),
            capability,
            readiness,
            evidence: evidence.map(String::from),
            gaps,
        });
    }

    /// Get all controls.
    pub fn controls(&self) -> impl Iterator<Item = &ExpectedControl> {
        self.controls.values()
    }

    /// Get control by ID.
    pub fn get_control(&self, id: &ControlId) -> Option<&ExpectedControl> {
        self.controls.get(id)
    }

    /// Get all mappings for a control.
    pub fn mappings_for_control(&self, control_id: &ControlId) -> Vec<&ControlMapping> {
        self.mappings
            .iter()
            .filter(|m| &m.control_id == control_id)
            .collect()
    }

    /// Get all mappings for a capability.
    pub fn mappings_for_capability(&self, capability: SecurityCapability) -> Vec<&ControlMapping> {
        self.mappings
            .iter()
            .filter(|m| m.capability == capability)
            .collect()
    }

    /// Calculate readiness score for a domain.
    pub fn domain_readiness(&self, domain: ControlDomain) -> DomainReadiness {
        let domain_controls: Vec<_> = self
            .controls
            .values()
            .filter(|c| c.domain == domain)
            .collect();

        let mut total_score = 0u32;
        let mut max_score = 0u32;
        let mut gaps = Vec::new();

        for control in &domain_controls {
            let mappings = self.mappings_for_control(&control.id);
            max_score += 5; // Max readiness level

            if mappings.is_empty() {
                gaps.push(format!("{}: No mapping", control.id));
            } else {
                // Use highest readiness among mappings for this control
                let best = mappings
                    .iter()
                    .map(|m| m.readiness.score())
                    .max()
                    .unwrap_or(0);
                total_score += best as u32;

                // Collect gaps from all mappings
                for mapping in &mappings {
                    for gap in &mapping.gaps {
                        gaps.push(format!("{}: {}", control.id, gap));
                    }
                }
            }
        }

        let percentage = if max_score > 0 {
            (total_score as f32 / max_score as f32) * 100.0
        } else {
            0.0
        };

        DomainReadiness {
            domain,
            total_controls: domain_controls.len(),
            readiness_score: total_score,
            max_score,
            readiness_percentage: percentage,
            gaps,
        }
    }

    /// Generate a readiness assessment report.
    pub fn generate_assessment(&self) -> ReadinessAssessment {
        let domains = [
            ControlDomain::DataSecurity,
            ControlDomain::ModelSecurity,
            ControlDomain::OperationalSecurity,
            ControlDomain::SupplyChainSecurity,
            ControlDomain::PrivacyEthics,
        ];

        let domain_scores: HashMap<ControlDomain, DomainReadiness> = domains
            .iter()
            .map(|d| (*d, self.domain_readiness(*d)))
            .collect();

        let total_score: u32 = domain_scores.values().map(|d| d.readiness_score).sum();
        let max_score: u32 = domain_scores.values().map(|d| d.max_score).sum();
        let overall_percentage = if max_score > 0 {
            (total_score as f32 / max_score as f32) * 100.0
        } else {
            0.0
        };

        let all_gaps: Vec<_> = domain_scores
            .values()
            .flat_map(|d| d.gaps.clone())
            .collect();

        let certification_ready = overall_percentage >= 80.0
            && domain_scores
                .values()
                .all(|d| d.readiness_percentage >= 60.0);

        ReadinessAssessment {
            generated_at: chrono::Utc::now().to_rfc3339(),
            overall_score: total_score,
            overall_max_score: max_score,
            overall_percentage,
            domain_scores,
            total_gaps: all_gaps.len(),
            critical_gaps: all_gaps
                .iter()
                .filter(|g| g.contains("No mapping") || g.contains("not implemented"))
                .cloned()
                .collect(),
            certification_ready,
        }
    }
}

/// Readiness assessment for a single domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReadiness {
    pub domain: ControlDomain,
    pub total_controls: usize,
    pub readiness_score: u32,
    pub max_score: u32,
    pub readiness_percentage: f32,
    pub gaps: Vec<String>,
}

/// Full ISO 27090 readiness assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessAssessment {
    pub generated_at: String,
    pub overall_score: u32,
    pub overall_max_score: u32,
    pub overall_percentage: f32,
    pub domain_scores: HashMap<ControlDomain, DomainReadiness>,
    pub total_gaps: usize,
    pub critical_gaps: Vec<String>,
    pub certification_ready: bool,
}

impl ReadinessAssessment {
    /// Convert to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Generate a summary report.
    pub fn summary(&self) -> String {
        let mut output = String::new();
        output.push_str("ISO/IEC 27090 Readiness Assessment\n");
        output.push_str("===================================\n\n");
        output.push_str(&format!("Generated: {}\n", self.generated_at));
        output.push_str(&format!(
            "Overall Readiness: {:.1}% ({}/{})\n",
            self.overall_percentage, self.overall_score, self.overall_max_score
        ));
        output.push_str(&format!(
            "Certification Ready: {}\n\n",
            if self.certification_ready {
                "Yes"
            } else {
                "No"
            }
        ));

        output.push_str("Domain Scores:\n");
        for domain in [
            ControlDomain::DataSecurity,
            ControlDomain::ModelSecurity,
            ControlDomain::OperationalSecurity,
            ControlDomain::SupplyChainSecurity,
            ControlDomain::PrivacyEthics,
        ] {
            if let Some(score) = self.domain_scores.get(&domain) {
                output.push_str(&format!(
                    "  {}: {:.1}% ({}/{})\n",
                    domain, score.readiness_percentage, score.readiness_score, score.max_score
                ));
            }
        }

        let total_gaps = self.total_gaps;
        output.push_str(&format!("\nTotal Gaps: {total_gaps}\n"));
        if !self.critical_gaps.is_empty() {
            output.push_str("Critical Gaps:\n");
            for gap in &self.critical_gaps {
                output.push_str(&format!("  - {gap}\n"));
            }
        }

        output
    }

    /// Get recommendations for improving readiness.
    pub fn recommendations(&self) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Identify domains with low scores
        for (domain, score) in &self.domain_scores {
            if score.readiness_percentage < 60.0 {
                recommendations.push(Recommendation {
                    priority: Priority::High,
                    domain: *domain,
                    description: format!(
                        "Improve {} readiness from {:.0}% to at least 60%",
                        domain, score.readiness_percentage
                    ),
                    suggested_actions: score.gaps.clone(),
                });
            } else if score.readiness_percentage < 80.0 {
                recommendations.push(Recommendation {
                    priority: Priority::Medium,
                    domain: *domain,
                    description: format!(
                        "Enhance {} readiness from {:.0}% to 80%+",
                        domain, score.readiness_percentage
                    ),
                    suggested_actions: score.gaps.clone(),
                });
            }
        }

        // Add specific recommendations for critical gaps
        for gap in &self.critical_gaps {
            let domain = if gap.starts_with("DS") {
                ControlDomain::DataSecurity
            } else if gap.starts_with("MS") {
                ControlDomain::ModelSecurity
            } else if gap.starts_with("OS") {
                ControlDomain::OperationalSecurity
            } else if gap.starts_with("SC") {
                ControlDomain::SupplyChainSecurity
            } else {
                ControlDomain::PrivacyEthics
            };

            recommendations.push(Recommendation {
                priority: Priority::Critical,
                domain,
                description: format!("Address critical gap: {gap}"),
                suggested_actions: vec![gap.clone()],
            });
        }

        // Sort by priority
        recommendations.sort_by(|a, b| a.priority.cmp(&b.priority));
        recommendations
    }
}

/// Priority level for recommendations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::Critical => write!(f, "CRITICAL"),
            Priority::High => write!(f, "HIGH"),
            Priority::Medium => write!(f, "MEDIUM"),
            Priority::Low => write!(f, "LOW"),
        }
    }
}

/// Recommendation for improving readiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: Priority,
    pub domain: ControlDomain,
    pub description: String,
    pub suggested_actions: Vec<String>,
}

/// Add ISO 27090 metadata to an audit event.
pub fn add_iso27090_metadata(
    metadata: &mut serde_json::Value,
    capability: SecurityCapability,
    registry: &Iso27090Registry,
) {
    let mappings = registry.mappings_for_capability(capability);
    if !mappings.is_empty() {
        let controls: Vec<String> = mappings.iter().map(|m| m.control_id.0.clone()).collect();

        if let serde_json::Value::Object(ref mut map) = metadata {
            map.insert("iso27090_controls".to_string(), serde_json::json!(controls));
            map.insert(
                "iso27090_capability".to_string(),
                serde_json::json!(capability.to_string()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = Iso27090Registry::new();
        assert!(!registry.controls.is_empty());
        assert!(!registry.mappings.is_empty());
    }

    #[test]
    fn test_control_id_parsing() {
        let id = ControlId::new(ControlDomain::DataSecurity, 2, None);
        assert_eq!(id.0, "DS.2");
        assert_eq!(id.domain(), Some(ControlDomain::DataSecurity));

        let id2 = ControlId::new(ControlDomain::ModelSecurity, 1, Some(3));
        assert_eq!(id2.0, "MS.1.3");
        assert_eq!(id2.domain(), Some(ControlDomain::ModelSecurity));
    }

    #[test]
    fn test_domain_display() {
        assert_eq!(format!("{}", ControlDomain::DataSecurity), "Data Security");
        assert_eq!(
            format!("{}", ControlDomain::OperationalSecurity),
            "Operational Security"
        );
    }

    #[test]
    fn test_readiness_level_score() {
        assert_eq!(ReadinessLevel::NotStarted.score(), 0);
        assert_eq!(ReadinessLevel::Initial.score(), 1);
        assert_eq!(ReadinessLevel::Managed.score(), 4);
        assert_eq!(ReadinessLevel::Optimizing.score(), 5);
    }

    #[test]
    fn test_domain_readiness() {
        let registry = Iso27090Registry::new();
        let readiness = registry.domain_readiness(ControlDomain::OperationalSecurity);

        assert!(readiness.total_controls > 0);
        assert!(readiness.readiness_score > 0);
        assert!(readiness.readiness_percentage > 0.0);
    }

    #[test]
    fn test_generate_assessment() {
        let registry = Iso27090Registry::new();
        let assessment = registry.generate_assessment();

        assert!(!assessment.generated_at.is_empty());
        assert!(assessment.overall_score > 0);
        assert!(assessment.overall_max_score > 0);
        assert_eq!(assessment.domain_scores.len(), 5);
    }

    #[test]
    fn test_assessment_to_json() {
        let registry = Iso27090Registry::new();
        let assessment = registry.generate_assessment();

        let json = assessment.to_json().unwrap();
        assert!(json.contains("overall_percentage"));
        assert!(json.contains("domain_scores"));
    }

    #[test]
    fn test_assessment_summary() {
        let registry = Iso27090Registry::new();
        let assessment = registry.generate_assessment();
        let summary = assessment.summary();

        assert!(summary.contains("ISO/IEC 27090 Readiness Assessment"));
        assert!(summary.contains("Data Security"));
        assert!(summary.contains("Certification Ready"));
    }

    #[test]
    fn test_recommendations() {
        let registry = Iso27090Registry::new();
        let assessment = registry.generate_assessment();
        let recommendations = assessment.recommendations();

        // Should have some recommendations given not everything is optimizing
        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_mappings_for_capability() {
        let registry = Iso27090Registry::new();
        let mappings = registry.mappings_for_capability(SecurityCapability::AuditLogging);

        assert!(!mappings.is_empty());
        assert!(mappings
            .iter()
            .any(|m| m.readiness == ReadinessLevel::Optimizing));
    }

    #[test]
    fn test_add_iso27090_metadata() {
        let registry = Iso27090Registry::new();
        let mut metadata = serde_json::json!({});

        add_iso27090_metadata(
            &mut metadata,
            SecurityCapability::PolicyEnforcement,
            &registry,
        );

        assert!(metadata.get("iso27090_controls").is_some());
        assert!(metadata.get("iso27090_capability").is_some());
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical < Priority::High);
        assert!(Priority::High < Priority::Medium);
        assert!(Priority::Medium < Priority::Low);
    }
}
