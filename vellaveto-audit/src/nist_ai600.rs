// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! NIST AI 600-1 GenAI Profile compliance registry.
//!
//! Maps Vellaveto security capabilities to the 12 GenAI-specific risk areas
//! defined in NIST AI 600-1 (Generative AI Profile) and provides cross-mappings
//! to both the base NIST AI RMF and the EU AI Act.
//!
//! The 12 risk areas:
//! 1. CBRN (Chemical, Biological, Radiological, Nuclear)
//! 2. Confabulation
//! 3. Data Privacy
//! 4. Environmental
//! 5. Human-AI Configuration
//! 6. Information Integrity
//! 7. Information Security
//! 8. Intellectual Property
//! 9. Obscene/Degrading Content
//! 10. Toxicity/Bias/Homogeneity
//! 11. Value Chain/Component Integration
//! 12. Dangerous/Violent Behavior
//!
//! Reference: <https://airc.nist.gov/Docs/1>
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::nist_ai600::{NistAi600Registry, Ai600RiskArea};
//!
//! let registry = NistAi600Registry::new();
//! let report = registry.generate_report("Acme Corp", "acme-vellaveto-001");
//! println!("AI 600-1 coverage: {:.1}%", report.compliance_percentage);
//! ```

use crate::atlas::VellavetoDetection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Bounds Constants ────────────────────────────────────────────────────────

/// Maximum number of AI 600-1 controls (current profile: 24, headroom for expansion).
const MAX_AI600_CONTROLS: usize = 100;

/// Maximum number of AI 600-1 risk areas (current profile: 12, headroom for expansion).
const MAX_AI600_RISK_AREAS: usize = 24;

/// Maximum mitigations per control.
const MAX_MITIGATIONS_PER_CONTROL: usize = 50;

/// Maximum cross-mappings in a report.
const MAX_CROSS_MAPPINGS: usize = 200;

/// Maximum detection mappings per control.
const MAX_DETECTIONS_PER_CONTROL: usize = 30;

/// Maximum length for control description.
const MAX_DESCRIPTION_LEN: usize = 2000;

/// Maximum length for control ID.
const MAX_CONTROL_ID_LEN: usize = 64;

// ── Risk Area Enum ──────────────────────────────────────────────────────────

/// NIST AI 600-1 GenAI-specific risk area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ai600RiskArea {
    /// Chemical, Biological, Radiological, Nuclear information risks.
    Cbrn,
    /// Model confabulation / hallucination.
    Confabulation,
    /// Data privacy risks (training data, PII leakage).
    DataPrivacy,
    /// Environmental impacts (compute, energy).
    Environmental,
    /// Human-AI configuration and oversight risks.
    HumanAiConfiguration,
    /// Information integrity (misinformation, deepfakes).
    InformationIntegrity,
    /// Information security (prompt injection, model extraction).
    InformationSecurity,
    /// Intellectual property (training data IP, output IP).
    IntellectualProperty,
    /// Obscene, degrading, or abusive content.
    ObsceneDegradingContent,
    /// Toxicity, bias, and homogeneity.
    ToxicityBiasHomogeneity,
    /// Value chain and component integration risks.
    ValueChainComponentIntegration,
    /// Dangerous or violent behavior.
    DangerousViolentBehavior,
}

impl Ai600RiskArea {
    /// Short code used in control IDs.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Cbrn => "CBRN",
            Self::Confabulation => "CONF",
            Self::DataPrivacy => "PRIV",
            Self::Environmental => "ENV",
            Self::HumanAiConfiguration => "HAIC",
            Self::InformationIntegrity => "IINT",
            Self::InformationSecurity => "ISEC",
            Self::IntellectualProperty => "IP",
            Self::ObsceneDegradingContent => "ODC",
            Self::ToxicityBiasHomogeneity => "TBH",
            Self::ValueChainComponentIntegration => "VCINT",
            Self::DangerousViolentBehavior => "DVB",
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cbrn => "CBRN Information",
            Self::Confabulation => "Confabulation",
            Self::DataPrivacy => "Data Privacy",
            Self::Environmental => "Environmental",
            Self::HumanAiConfiguration => "Human-AI Configuration",
            Self::InformationIntegrity => "Information Integrity",
            Self::InformationSecurity => "Information Security",
            Self::IntellectualProperty => "Intellectual Property",
            Self::ObsceneDegradingContent => "Obscene/Degrading Content",
            Self::ToxicityBiasHomogeneity => "Toxicity, Bias & Homogeneity",
            Self::ValueChainComponentIntegration => "Value Chain/Component Integration",
            Self::DangerousViolentBehavior => "Dangerous/Violent Behavior",
        }
    }

    /// All risk areas in specification order.
    pub fn all() -> &'static [Ai600RiskArea] {
        &[
            Self::Cbrn,
            Self::Confabulation,
            Self::DataPrivacy,
            Self::Environmental,
            Self::HumanAiConfiguration,
            Self::InformationIntegrity,
            Self::InformationSecurity,
            Self::IntellectualProperty,
            Self::ObsceneDegradingContent,
            Self::ToxicityBiasHomogeneity,
            Self::ValueChainComponentIntegration,
            Self::DangerousViolentBehavior,
        ]
    }
}

impl std::fmt::Display for Ai600RiskArea {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── Control Identifier ──────────────────────────────────────────────────────

/// NIST AI 600-1 control identifier (e.g., "AI600-CONF-01").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ai600ControlId(pub String);

impl Ai600ControlId {
    /// Create a new control ID from a risk area and sequence number.
    pub fn new(risk_area: Ai600RiskArea, number: u8) -> Self {
        Self(format!("AI600-{}-{:02}", risk_area.code(), number))
    }

    /// Parse the risk area from the ID.
    pub fn risk_area(&self) -> Option<Ai600RiskArea> {
        let parts: Vec<&str> = self.0.split('-').collect();
        if parts.len() < 3 {
            return None;
        }
        match parts[1] {
            "CBRN" => Some(Ai600RiskArea::Cbrn),
            "CONF" => Some(Ai600RiskArea::Confabulation),
            "PRIV" => Some(Ai600RiskArea::DataPrivacy),
            "ENV" => Some(Ai600RiskArea::Environmental),
            "HAIC" => Some(Ai600RiskArea::HumanAiConfiguration),
            "IINT" => Some(Ai600RiskArea::InformationIntegrity),
            "ISEC" => Some(Ai600RiskArea::InformationSecurity),
            "IP" => Some(Ai600RiskArea::IntellectualProperty),
            "ODC" => Some(Ai600RiskArea::ObsceneDegradingContent),
            "TBH" => Some(Ai600RiskArea::ToxicityBiasHomogeneity),
            "VCINT" => Some(Ai600RiskArea::ValueChainComponentIntegration),
            "DVB" => Some(Ai600RiskArea::DangerousViolentBehavior),
            _ => None,
        }
    }
}

impl std::fmt::Display for Ai600ControlId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Implementation Status ───────────────────────────────────────────────────

/// Implementation status for an AI 600-1 control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ai600ComplianceStatus {
    /// Fully mitigated by Vellaveto capabilities.
    Mitigated,
    /// Partially mitigated -- some controls in place.
    Partial,
    /// Not yet implemented.
    NotImplemented,
    /// Not applicable to Vellaveto's scope (e.g., environmental compute).
    NotApplicable,
}

impl std::fmt::Display for Ai600ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mitigated => write!(f, "Mitigated"),
            Self::Partial => write!(f, "Partial"),
            Self::NotImplemented => write!(f, "Not Implemented"),
            Self::NotApplicable => write!(f, "N/A"),
        }
    }
}

// ── Control Definition ──────────────────────────────────────────────────────

/// An AI 600-1 GenAI Profile control (mitigation action).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistAi600Control {
    /// Control identifier (e.g., "AI600-ISEC-01").
    pub id: Ai600ControlId,
    /// GenAI risk area this control addresses.
    pub risk_area: Ai600RiskArea,
    /// Short title.
    pub title: String,
    /// Full description of the mitigation action.
    pub description: String,
    /// NIST AI RMF subcategory cross-references (e.g., "GOVERN 1.1", "MEASURE 2.7").
    pub rmf_subcategories: Vec<String>,
    /// EU AI Act article cross-references (e.g., "Art 9", "Art 15").
    pub eu_ai_act_articles: Vec<String>,
}

// ── Vellaveto Mitigation ────────────────────────────────────────────────────

/// Maps a Vellaveto detection or capability to an AI 600-1 control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ai600Mitigation {
    /// The AI 600-1 control being mitigated.
    pub control_id: Ai600ControlId,
    /// Vellaveto detection type providing the mitigation.
    pub detection: VellavetoDetection,
    /// Implementation status.
    pub status: Ai600ComplianceStatus,
    /// Evidence description.
    pub evidence: Option<String>,
}

// ── Registry ────────────────────────────────────────────────────────────────

/// NIST AI 600-1 GenAI Profile compliance registry.
///
/// Populates controls from the AI 600-1 profile and maps Vellaveto detections
/// to specific controls for compliance evidence.
#[derive(Debug, Clone)]
pub struct NistAi600Registry {
    controls: HashMap<String, NistAi600Control>,
    mitigations: Vec<Ai600Mitigation>,
}

impl NistAi600Registry {
    /// Create a new registry with all controls and Vellaveto mitigation mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            controls: HashMap::new(),
            mitigations: Vec::new(),
        };
        registry.populate_controls();
        registry.populate_mitigations();
        registry
    }

    // ── Control Population ──────────────────────────────────────────────────

    fn add_control(
        &mut self,
        risk_area: Ai600RiskArea,
        number: u8,
        title: &str,
        description: &str,
        rmf_subcategories: &[&str],
        eu_ai_act_articles: &[&str],
    ) {
        let id = Ai600ControlId::new(risk_area, number);
        self.controls.insert(
            id.0.clone(),
            NistAi600Control {
                id,
                risk_area,
                title: title.to_string(),
                description: description.to_string(),
                rmf_subcategories: rmf_subcategories.iter().map(|s| s.to_string()).collect(),
                eu_ai_act_articles: eu_ai_act_articles.iter().map(|s| s.to_string()).collect(),
            },
        );
    }

    fn add_mitigation(
        &mut self,
        control_id_str: &str,
        detection: VellavetoDetection,
        status: Ai600ComplianceStatus,
        evidence: Option<&str>,
    ) {
        self.mitigations.push(Ai600Mitigation {
            control_id: Ai600ControlId(control_id_str.to_string()),
            detection,
            status,
            evidence: evidence.map(String::from),
        });
    }

    fn populate_controls(&mut self) {
        // ── 1. CBRN Information ─────────────────────────────────────────────
        self.add_control(
            Ai600RiskArea::Cbrn, 1,
            "CBRN content filtering",
            "Implement filters and guardrails to prevent GenAI systems from generating detailed instructions for creating CBRN weapons or precursors.",
            &["GOVERN 1.2", "MANAGE 1.3"],
            &["Art 5", "Art 9"],
        );
        self.add_control(
            Ai600RiskArea::Cbrn, 2,
            "CBRN query monitoring",
            "Monitor and audit queries related to CBRN topics; flag and escalate suspicious patterns for human review.",
            &["MEASURE 2.6", "MANAGE 4.1"],
            &["Art 9", "Art 12"],
        );

        // ── 2. Confabulation ────────────────────────────────────────────────
        self.add_control(
            Ai600RiskArea::Confabulation, 1,
            "Confabulation detection and flagging",
            "Detect and flag confabulated (hallucinated) outputs by comparing generated content against trusted knowledge sources and internal consistency checks.",
            &["MEASURE 2.6", "MEASURE 2.1"],
            &["Art 15"],
        );
        self.add_control(
            Ai600RiskArea::Confabulation, 2,
            "Output provenance tracking",
            "Track provenance of generated outputs and provide confidence indicators to users; log confabulation incidents for continuous improvement.",
            &["MEASURE 3.1", "MANAGE 4.2"],
            &["Art 13", "Art 15"],
        );

        // ── 3. Data Privacy ─────────────────────────────────────────────────
        self.add_control(
            Ai600RiskArea::DataPrivacy, 1,
            "PII and sensitive data scanning",
            "Scan GenAI inputs and outputs for PII, secrets, and sensitive data; block or redact before transmission.",
            &["MEASURE 2.12", "GOVERN 1.2"],
            &["Art 10"],
        );
        self.add_control(
            Ai600RiskArea::DataPrivacy, 2,
            "Data leakage prevention",
            "Implement data loss prevention controls to prevent training data extraction and model memorization exploitation.",
            &["MEASURE 2.7", "MANAGE 2.2"],
            &["Art 10", "Art 15"],
        );

        // ── 4. Environmental ────────────────────────────────────────────────
        self.add_control(
            Ai600RiskArea::Environmental, 1,
            "Compute usage monitoring",
            "Monitor and report compute resource consumption of GenAI operations; provide energy usage metrics.",
            &["MEASURE 1.1", "MEASURE 3.2"],
            &[],
        );
        self.add_control(
            Ai600RiskArea::Environmental, 2,
            "Resource efficiency guardrails",
            "Implement rate limiting and budget controls to prevent wasteful or excessive GenAI compute usage.",
            &["MANAGE 2.1", "GOVERN 1.5"],
            &[],
        );

        // ── 5. Human-AI Configuration ───────────────────────────────────────
        self.add_control(
            Ai600RiskArea::HumanAiConfiguration, 1,
            "Human oversight enforcement",
            "Enforce human-in-the-loop approval for high-risk tool calls; configurable triggers based on tool sensitivity and action type.",
            &["MANAGE 2.4", "GOVERN 1.2"],
            &["Art 14"],
        );
        self.add_control(
            Ai600RiskArea::HumanAiConfiguration, 2,
            "Excessive agency prevention",
            "Detect and prevent excessive AI autonomy through least-agency tracking, workflow budgets, and permission scope enforcement.",
            &["MEASURE 2.6", "MANAGE 1.3"],
            &["Art 14", "Art 9"],
        );

        // ── 6. Information Integrity ────────────────────────────────────────
        self.add_control(
            Ai600RiskArea::InformationIntegrity, 1,
            "Output integrity validation",
            "Validate GenAI outputs against expected schemas and integrity constraints; detect and flag anomalous or manipulated outputs.",
            &["MEASURE 2.1", "MAP 2.3"],
            &["Art 15", "Art 50(2)"],
        );
        self.add_control(
            Ai600RiskArea::InformationIntegrity, 2,
            "Tamper-evident audit trail",
            "Maintain tamper-evident audit trail for all GenAI decisions and outputs using cryptographic hash chains.",
            &["GOVERN 4.2", "MANAGE 4.1"],
            &["Art 12", "Art 13"],
        );

        // ── 7. Information Security ─────────────────────────────────────────
        self.add_control(
            Ai600RiskArea::InformationSecurity, 1,
            "Prompt injection prevention",
            "Detect and block direct, indirect, and second-order prompt injection attacks using pattern matching, Unicode normalization, and behavioral analysis.",
            &["MEASURE 2.7", "MANAGE 1.3"],
            &["Art 9", "Art 15"],
        );
        self.add_control(
            Ai600RiskArea::InformationSecurity, 2,
            "Model and data exfiltration prevention",
            "Prevent unauthorized extraction of model weights, training data, and sensitive parameters through output scanning and rate limiting.",
            &["MEASURE 2.7", "GOVERN 6.1"],
            &["Art 15"],
        );

        // ── 8. Intellectual Property ────────────────────────────────────────
        self.add_control(
            Ai600RiskArea::IntellectualProperty, 1,
            "IP content detection",
            "Detect potential intellectual property violations in GenAI outputs including copyrighted content and trade secrets.",
            &["MAP 4.1", "GOVERN 1.1"],
            &["Art 53"],
        );
        self.add_control(
            Ai600RiskArea::IntellectualProperty, 2,
            "Training data provenance",
            "Track and document data provenance for GenAI components; maintain records of third-party model and data licenses.",
            &["MAP 4.2", "GOVERN 6.1"],
            &["Art 10", "Art 53"],
        );

        // ── 9. Obscene/Degrading Content ────────────────────────────────────
        self.add_control(
            Ai600RiskArea::ObsceneDegradingContent, 1,
            "Content safety filtering",
            "Implement content safety filters to detect and block obscene, degrading, or abusive content in GenAI outputs.",
            &["MEASURE 2.6", "MANAGE 1.3"],
            &["Art 5", "Art 9"],
        );
        self.add_control(
            Ai600RiskArea::ObsceneDegradingContent, 2,
            "Content incident logging",
            "Log and escalate incidents of harmful content generation for review and model improvement.",
            &["MANAGE 4.1", "MANAGE 4.3"],
            &["Art 12", "Art 9"],
        );

        // ── 10. Toxicity, Bias & Homogeneity ───────────────────────────────
        self.add_control(
            Ai600RiskArea::ToxicityBiasHomogeneity, 1,
            "Bias and toxicity detection",
            "Detect patterns of biased, toxic, or homogeneous outputs in GenAI systems; flag for human review when thresholds are exceeded.",
            &["MEASURE 2.11", "MEASURE 2.6"],
            &["Art 9", "Art 10"],
        );
        self.add_control(
            Ai600RiskArea::ToxicityBiasHomogeneity, 2,
            "Output diversity monitoring",
            "Monitor output diversity and homogeneity patterns; track bias metrics over time for continuous improvement.",
            &["MEASURE 3.1", "MANAGE 4.2"],
            &["Art 9", "Art 13"],
        );

        // ── 11. Value Chain / Component Integration ─────────────────────────
        self.add_control(
            Ai600RiskArea::ValueChainComponentIntegration, 1,
            "Supply chain integrity verification",
            "Verify integrity of third-party AI components through tool signature validation, schema hash tracking, and rug-pull detection.",
            &["GOVERN 6.1", "MAP 4.1"],
            &["Art 15"],
        );
        self.add_control(
            Ai600RiskArea::ValueChainComponentIntegration, 2,
            "Component drift monitoring",
            "Monitor third-party AI components for behavioral drift, schema changes, and annotation modifications; alert on supply chain anomalies.",
            &["MANAGE 3.1", "MANAGE 3.2"],
            &["Art 9", "Art 15"],
        );

        // ── 12. Dangerous / Violent Behavior ────────────────────────────────
        self.add_control(
            Ai600RiskArea::DangerousViolentBehavior, 1,
            "Dangerous action prevention",
            "Prevent GenAI agents from executing dangerous or violent actions through policy-based tool call restrictions and kill-switch capabilities.",
            &["MANAGE 1.3", "MANAGE 4.3"],
            &["Art 5", "Art 9"],
        );
        self.add_control(
            Ai600RiskArea::DangerousViolentBehavior, 2,
            "Behavioral anomaly detection",
            "Detect anomalous agent behavior patterns that may indicate goal drift toward dangerous or violent outcomes; trigger circuit breaker on detection.",
            &["MEASURE 2.6", "MEASURE 3.1"],
            &["Art 9", "Art 14"],
        );
    }

    // ── Mitigation Population ───────────────────────────────────────────────

    fn populate_mitigations(&mut self) {
        // ── CBRN ────────────────────────────────────────────────────────────
        self.add_mitigation(
            "AI600-CBRN-01",
            VellavetoDetection::PromptInjection,
            Ai600ComplianceStatus::Partial,
            Some("Injection detection blocks attempts to elicit CBRN content via prompt manipulation"),
        );
        self.add_mitigation(
            "AI600-CBRN-02",
            VellavetoDetection::RateLimitExceeded,
            Ai600ComplianceStatus::Partial,
            Some("Audit logging and rate limiting flag high-volume CBRN-related query patterns"),
        );

        // ── Confabulation ───────────────────────────────────────────────────
        self.add_mitigation(
            "AI600-CONF-01",
            VellavetoDetection::GoalDrift,
            Ai600ComplianceStatus::Partial,
            Some("Goal drift detection identifies agent output inconsistencies indicative of confabulation"),
        );
        self.add_mitigation(
            "AI600-CONF-02",
            VellavetoDetection::MemoryInjection,
            Ai600ComplianceStatus::Partial,
            Some("Memory poisoning detection prevents tainted context from causing confabulated outputs"),
        );

        // ── Data Privacy ────────────────────────────────────────────────────
        self.add_mitigation(
            "AI600-PRIV-01",
            VellavetoDetection::SecretsInOutput,
            Ai600ComplianceStatus::Mitigated,
            Some("5-layer DLP scanning detects PII, secrets, and sensitive data in tool call parameters and responses"),
        );
        self.add_mitigation(
            "AI600-PRIV-02",
            VellavetoDetection::DataLaundering,
            Ai600ComplianceStatus::Mitigated,
            Some("Data laundering detection prevents cross-request sensitive data exfiltration"),
        );

        // ── Environmental ───────────────────────────────────────────────────
        self.add_mitigation(
            "AI600-ENV-01",
            VellavetoDetection::RateLimitExceeded,
            Ai600ComplianceStatus::Partial,
            Some("Prometheus metrics track evaluation rates and resource usage patterns"),
        );
        self.add_mitigation(
            "AI600-ENV-02",
            VellavetoDetection::WorkflowBudgetExceeded,
            Ai600ComplianceStatus::Partial,
            Some("Rate limiting and workflow budgets cap excessive compute usage"),
        );

        // ── Human-AI Configuration ──────────────────────────────────────────
        self.add_mitigation(
            "AI600-HAIC-01",
            VellavetoDetection::ExcessiveAgency,
            Ai600ComplianceStatus::Mitigated,
            Some("Human-in-the-loop approval workflow with configurable tool sensitivity triggers"),
        );
        self.add_mitigation(
            "AI600-HAIC-02",
            VellavetoDetection::ExcessiveAgency,
            Ai600ComplianceStatus::Mitigated,
            Some("Least-agency tracking enforces minimal permissions; workflow budgets prevent excessive autonomy"),
        );

        // ── Information Integrity ───────────────────────────────────────────
        self.add_mitigation(
            "AI600-IINT-01",
            VellavetoDetection::SchemaPoisoning,
            Ai600ComplianceStatus::Mitigated,
            Some("Output schema validation registry validates GenAI outputs against expected schemas"),
        );
        self.add_mitigation(
            "AI600-IINT-02",
            VellavetoDetection::GoalDrift,
            Ai600ComplianceStatus::Mitigated,
            Some("SHA-256 hash chain audit log with Ed25519 signed checkpoints provides tamper-evident trail"),
        );

        // ── Information Security ────────────────────────────────────────────
        self.add_mitigation(
            "AI600-ISEC-01",
            VellavetoDetection::PromptInjection,
            Ai600ComplianceStatus::Mitigated,
            Some("Aho-Corasick pattern matching with Unicode NFKC normalization detects direct and indirect injection"),
        );
        self.add_mitigation(
            "AI600-ISEC-01",
            VellavetoDetection::IndirectInjection,
            Ai600ComplianceStatus::Mitigated,
            Some("Response-side injection scanning covers indirect injection via tool outputs"),
        );
        self.add_mitigation(
            "AI600-ISEC-02",
            VellavetoDetection::SecretsInOutput,
            Ai600ComplianceStatus::Mitigated,
            Some("DLP scanning and rate limiting prevent data exfiltration and model extraction"),
        );

        // ── Intellectual Property ───────────────────────────────────────────
        self.add_mitigation(
            "AI600-IP-01",
            VellavetoDetection::SecretsInOutput,
            Ai600ComplianceStatus::Partial,
            Some("DLP scanning detects known secret patterns; general IP detection requires domain-specific rules"),
        );
        self.add_mitigation(
            "AI600-IP-02",
            VellavetoDetection::ToolAnnotationChange,
            Ai600ComplianceStatus::Partial,
            Some("Tool signature verification tracks third-party component provenance"),
        );

        // ── Obscene/Degrading Content ───────────────────────────────────────
        self.add_mitigation(
            "AI600-ODC-01",
            VellavetoDetection::PromptInjection,
            Ai600ComplianceStatus::Partial,
            Some("Injection detection blocks attempts to bypass content safety filters via prompt manipulation"),
        );
        self.add_mitigation(
            "AI600-ODC-02",
            VellavetoDetection::GoalDrift,
            Ai600ComplianceStatus::Partial,
            Some("Audit logging records all tool call outputs for content safety review"),
        );

        // ── Toxicity, Bias & Homogeneity ────────────────────────────────────
        self.add_mitigation(
            "AI600-TBH-01",
            VellavetoDetection::GoalDrift,
            Ai600ComplianceStatus::Partial,
            Some("Behavioral anomaly detection flags output pattern deviations that may indicate bias"),
        );
        self.add_mitigation(
            "AI600-TBH-02",
            VellavetoDetection::RateLimitExceeded,
            Ai600ComplianceStatus::Partial,
            Some("Prometheus metrics enable long-term bias and homogeneity monitoring"),
        );

        // ── Value Chain / Component Integration ─────────────────────────────
        self.add_mitigation(
            "AI600-VCINT-01",
            VellavetoDetection::ToolAnnotationChange,
            Ai600ComplianceStatus::Mitigated,
            Some("Rug-pull detection verifies tool signatures against registered schemas"),
        );
        self.add_mitigation(
            "AI600-VCINT-01",
            VellavetoDetection::SchemaPoisoning,
            Ai600ComplianceStatus::Mitigated,
            Some("Schema poisoning detection tracks hash changes in tool definitions"),
        );
        self.add_mitigation(
            "AI600-VCINT-02",
            VellavetoDetection::ToolAnnotationChange,
            Ai600ComplianceStatus::Mitigated,
            Some("Continuous tool annotation monitoring detects behavioral drift in supply chain components"),
        );

        // ── Dangerous / Violent Behavior ────────────────────────────────────
        self.add_mitigation(
            "AI600-DVB-01",
            VellavetoDetection::ExcessiveAgency,
            Ai600ComplianceStatus::Mitigated,
            Some("Policy engine blocks dangerous tool calls; kill switch provides immediate shutdown"),
        );
        self.add_mitigation(
            "AI600-DVB-02",
            VellavetoDetection::GoalDrift,
            Ai600ComplianceStatus::Mitigated,
            Some("Goal drift and behavioral anomaly detection trigger circuit breaker on dangerous patterns"),
        );
        self.add_mitigation(
            "AI600-DVB-02",
            VellavetoDetection::CircuitBreakerTriggered,
            Ai600ComplianceStatus::Mitigated,
            Some("Circuit breaker pattern halts agent execution on anomaly detection"),
        );
    }

    // ── Query Methods ───────────────────────────────────────────────────────

    /// Get all controls.
    pub fn controls(&self) -> impl Iterator<Item = &NistAi600Control> {
        self.controls.values()
    }

    /// Get a control by ID.
    pub fn get_control(&self, id: &str) -> Option<&NistAi600Control> {
        self.controls.get(id)
    }

    /// Get all controls for a risk area.
    pub fn controls_for_risk_area(&self, risk_area: Ai600RiskArea) -> Vec<&NistAi600Control> {
        self.controls
            .values()
            .filter(|c| c.risk_area == risk_area)
            .collect()
    }

    /// Get all mitigations for a control.
    pub fn mitigations_for_control(&self, control_id: &str) -> Vec<&Ai600Mitigation> {
        self.mitigations
            .iter()
            .filter(|m| m.control_id.0 == control_id)
            .collect()
    }

    /// Get all mitigations for a detection type.
    pub fn mitigations_for_detection(
        &self,
        detection: VellavetoDetection,
    ) -> Vec<&Ai600Mitigation> {
        self.mitigations
            .iter()
            .filter(|m| m.detection == detection)
            .collect()
    }

    /// Get the RMF subcategory cross-references for a control.
    pub fn rmf_cross_references(&self, control_id: &str) -> Vec<&str> {
        self.controls
            .get(control_id)
            .map(|c| c.rmf_subcategories.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get the EU AI Act article cross-references for a control.
    pub fn eu_ai_act_cross_references(&self, control_id: &str) -> Vec<&str> {
        self.controls
            .get(control_id)
            .map(|c| c.eu_ai_act_articles.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    // ── Report Generation ───────────────────────────────────────────────────

    /// Generate a compliance evidence report.
    pub fn generate_report(
        &self,
        organization_name: &str,
        system_id: &str,
    ) -> Ai600ComplianceReport {
        let mut risk_area_assessments = Vec::new();

        for risk_area in Ai600RiskArea::all() {
            let area_controls = self.controls_for_risk_area(*risk_area);
            let mut control_assessments = Vec::new();

            for control in &area_controls {
                let mitigations = self.mitigations_for_control(&control.id.0);
                let status = if mitigations.is_empty() {
                    Ai600ComplianceStatus::NotImplemented
                } else {
                    let all_mitigated = mitigations
                        .iter()
                        .all(|m| m.status == Ai600ComplianceStatus::Mitigated);
                    let any_coverage = mitigations.iter().any(|m| {
                        m.status == Ai600ComplianceStatus::Mitigated
                            || m.status == Ai600ComplianceStatus::Partial
                    });
                    if all_mitigated {
                        Ai600ComplianceStatus::Mitigated
                    } else if any_coverage {
                        Ai600ComplianceStatus::Partial
                    } else {
                        Ai600ComplianceStatus::NotImplemented
                    }
                };

                let evidence: Vec<String> = mitigations
                    .iter()
                    .filter_map(|m| m.evidence.clone())
                    .collect();
                let detections: Vec<VellavetoDetection> =
                    mitigations.iter().map(|m| m.detection).collect();

                control_assessments.push(Ai600ControlAssessment {
                    control_id: control.id.0.clone(),
                    title: control.title.clone(),
                    status,
                    detections,
                    evidence,
                    rmf_subcategories: control.rmf_subcategories.clone(),
                    eu_ai_act_articles: control.eu_ai_act_articles.clone(),
                });
            }

            control_assessments.sort_by(|a, b| a.control_id.cmp(&b.control_id));

            let total_controls = control_assessments.len();
            let mitigated_controls = control_assessments
                .iter()
                .filter(|a| a.status == Ai600ComplianceStatus::Mitigated)
                .count();
            let partial_controls = control_assessments
                .iter()
                .filter(|a| a.status == Ai600ComplianceStatus::Partial)
                .count();

            let coverage_percent = if total_controls > 0 {
                ((mitigated_controls as f32 + partial_controls as f32 * 0.5)
                    / total_controls as f32)
                    * 100.0
            } else {
                0.0
            };

            risk_area_assessments.push(RiskAreaAssessment {
                risk_area: *risk_area,
                risk_area_name: risk_area.name().to_string(),
                total_controls,
                mitigated_controls,
                partial_controls,
                coverage_percent,
                controls: control_assessments,
            });
        }

        let total_controls: usize = risk_area_assessments.iter().map(|r| r.total_controls).sum();
        let mitigated: usize = risk_area_assessments
            .iter()
            .map(|r| r.mitigated_controls)
            .sum();
        let partial: usize = risk_area_assessments
            .iter()
            .map(|r| r.partial_controls)
            .sum();
        let compliance_percentage = if total_controls > 0 {
            ((mitigated as f32 + partial as f32 * 0.5) / total_controls as f32) * 100.0
        } else {
            0.0
        };

        // Build cross-mappings
        let mut cross_mappings = Vec::new();
        for control in self.controls.values() {
            for rmf_sub in &control.rmf_subcategories {
                cross_mappings.push(Ai600CrossMapping {
                    ai600_control_id: control.id.0.clone(),
                    framework: "NIST AI RMF".to_string(),
                    framework_ref: rmf_sub.clone(),
                });
            }
            for article in &control.eu_ai_act_articles {
                cross_mappings.push(Ai600CrossMapping {
                    ai600_control_id: control.id.0.clone(),
                    framework: "EU AI Act".to_string(),
                    framework_ref: article.clone(),
                });
            }
        }
        cross_mappings.sort_by(|a, b| a.ai600_control_id.cmp(&b.ai600_control_id));

        Ai600ComplianceReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            organization_name: organization_name.to_string(),
            system_id: system_id.to_string(),
            compliance_percentage,
            total_risk_areas: risk_area_assessments.len(),
            total_controls,
            mitigated_controls: mitigated,
            partial_controls: partial,
            risk_areas: risk_area_assessments,
            cross_mappings,
        }
    }
}

impl Default for NistAi600Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Report Types ────────────────────────────────────────────────────────────

/// Assessment for a single AI 600-1 control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ai600ControlAssessment {
    /// Control identifier.
    pub control_id: String,
    /// Short title.
    pub title: String,
    /// Compliance status.
    pub status: Ai600ComplianceStatus,
    /// Vellaveto detections providing mitigation.
    pub detections: Vec<VellavetoDetection>,
    /// Evidence descriptions.
    pub evidence: Vec<String>,
    /// Cross-reference to NIST AI RMF subcategories.
    pub rmf_subcategories: Vec<String>,
    /// Cross-reference to EU AI Act articles.
    pub eu_ai_act_articles: Vec<String>,
}

/// Assessment for a risk area (aggregation of controls).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAreaAssessment {
    /// Risk area enum value.
    pub risk_area: Ai600RiskArea,
    /// Human-readable name.
    pub risk_area_name: String,
    /// Total controls in this risk area.
    pub total_controls: usize,
    /// Controls fully mitigated.
    pub mitigated_controls: usize,
    /// Controls partially mitigated.
    pub partial_controls: usize,
    /// Coverage percentage.
    pub coverage_percent: f32,
    /// Individual control assessments.
    pub controls: Vec<Ai600ControlAssessment>,
}

/// Cross-mapping between AI 600-1 controls and other frameworks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ai600CrossMapping {
    /// AI 600-1 control ID.
    pub ai600_control_id: String,
    /// Target framework name (e.g., "NIST AI RMF", "EU AI Act").
    pub framework: String,
    /// Reference in the target framework (e.g., "GOVERN 1.2", "Art 9").
    pub framework_ref: String,
}

/// NIST AI 600-1 GenAI Profile compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ai600ComplianceReport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Organization name.
    pub organization_name: String,
    /// System identifier.
    pub system_id: String,
    /// Overall compliance percentage.
    pub compliance_percentage: f32,
    /// Number of risk areas assessed.
    pub total_risk_areas: usize,
    /// Total controls across all risk areas.
    pub total_controls: usize,
    /// Controls fully mitigated.
    pub mitigated_controls: usize,
    /// Controls partially mitigated.
    pub partial_controls: usize,
    /// Per-risk-area breakdown.
    pub risk_areas: Vec<RiskAreaAssessment>,
    /// Cross-mappings to other frameworks.
    pub cross_mappings: Vec<Ai600CrossMapping>,
}

impl Ai600ComplianceReport {
    /// Validate bounds on deserialized data.
    pub fn validate(&self) -> Result<(), String> {
        if !self.compliance_percentage.is_finite()
            || self.compliance_percentage < 0.0
            || self.compliance_percentage > 100.0
        {
            return Err(format!(
                "compliance_percentage out of range: {}",
                self.compliance_percentage
            ));
        }
        if self.risk_areas.len() > MAX_AI600_RISK_AREAS {
            return Err(format!(
                "risk_areas has {} entries, max is {}",
                self.risk_areas.len(),
                MAX_AI600_RISK_AREAS
            ));
        }
        let total_controls: usize = self.risk_areas.iter().map(|r| r.controls.len()).sum();
        if total_controls > MAX_AI600_CONTROLS {
            return Err(format!(
                "total controls across risk areas is {}, max is {}",
                total_controls, MAX_AI600_CONTROLS
            ));
        }
        if self.cross_mappings.len() > MAX_CROSS_MAPPINGS {
            return Err(format!(
                "cross_mappings has {} entries, max is {}",
                self.cross_mappings.len(),
                MAX_CROSS_MAPPINGS
            ));
        }
        for ra in &self.risk_areas {
            if !ra.coverage_percent.is_finite()
                || ra.coverage_percent < 0.0
                || ra.coverage_percent > 100.0
            {
                return Err(format!(
                    "risk_area[{}].coverage_percent out of range: {}",
                    ra.risk_area_name, ra.coverage_percent
                ));
            }
            for ctrl in &ra.controls {
                if ctrl.detections.len() > MAX_DETECTIONS_PER_CONTROL {
                    return Err(format!(
                        "control[{}].detections has {} entries, max is {}",
                        ctrl.control_id,
                        ctrl.detections.len(),
                        MAX_DETECTIONS_PER_CONTROL
                    ));
                }
                if ctrl.evidence.len() > MAX_MITIGATIONS_PER_CONTROL {
                    return Err(format!(
                        "control[{}].evidence has {} entries, max is {}",
                        ctrl.control_id,
                        ctrl.evidence.len(),
                        MAX_MITIGATIONS_PER_CONTROL
                    ));
                }
                if ctrl.control_id.len() > MAX_CONTROL_ID_LEN {
                    return Err(format!(
                        "control_id '{}' exceeds max length {}",
                        ctrl.control_id, MAX_CONTROL_ID_LEN
                    ));
                }
                for ev in &ctrl.evidence {
                    if ev.len() > MAX_DESCRIPTION_LEN {
                        return Err(format!(
                            "control[{}] evidence exceeds max length {}",
                            ctrl.control_id, MAX_DESCRIPTION_LEN
                        ));
                    }
                }
            }
        }
        for cm in &self.cross_mappings {
            if cm.ai600_control_id.len() > MAX_CONTROL_ID_LEN {
                return Err(format!(
                    "cross_mapping control_id '{}' exceeds max length {}",
                    cm.ai600_control_id, MAX_CONTROL_ID_LEN
                ));
            }
        }
        Ok(())
    }

    /// Convert report to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get a human-readable summary.
    pub fn summary(&self) -> String {
        let mut output = String::new();
        output.push_str("NIST AI 600-1 GenAI Profile Compliance Summary\n");
        output.push_str("===============================================\n\n");
        output.push_str(&format!("Generated: {}\n", self.generated_at));
        output.push_str(&format!("Organization: {}\n", self.organization_name));
        output.push_str(&format!("System: {}\n", self.system_id));
        output.push_str(&format!(
            "Overall Coverage: {:.1}%\n\n",
            self.compliance_percentage
        ));

        output.push_str("Coverage by Risk Area:\n");
        for ra in &self.risk_areas {
            output.push_str(&format!(
                "  {}: {}/{} mitigated, {} partial ({:.1}%)\n",
                ra.risk_area_name,
                ra.mitigated_controls,
                ra.total_controls,
                ra.partial_controls,
                ra.coverage_percent
            ));
        }

        output.push_str(&format!(
            "\nTotal Controls: {} | Mitigated: {} | Partial: {}\n",
            self.total_controls, self.mitigated_controls, self.partial_controls
        ));
        output.push_str(&format!(
            "Cross-Mappings: {} (NIST AI RMF + EU AI Act)\n",
            self.cross_mappings.len()
        ));

        output
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = NistAi600Registry::new();
        assert!(!registry.controls.is_empty());
        assert!(!registry.mitigations.is_empty());
    }

    #[test]
    fn test_control_count_is_24() {
        let registry = NistAi600Registry::new();
        assert_eq!(
            registry.controls.len(),
            24,
            "Expected 24 controls (2 per 12 risk areas)"
        );
    }

    #[test]
    fn test_all_risk_areas_have_controls() {
        let registry = NistAi600Registry::new();
        for risk_area in Ai600RiskArea::all() {
            let controls = registry.controls_for_risk_area(*risk_area);
            assert!(
                controls.len() >= 2,
                "Risk area {} should have at least 2 controls, got {}",
                risk_area,
                controls.len()
            );
        }
    }

    #[test]
    fn test_control_id_creation() {
        let id = Ai600ControlId::new(Ai600RiskArea::InformationSecurity, 1);
        assert_eq!(id.0, "AI600-ISEC-01");
    }

    #[test]
    fn test_control_id_risk_area_parsing() {
        let id = Ai600ControlId::new(Ai600RiskArea::DataPrivacy, 2);
        assert_eq!(id.risk_area(), Some(Ai600RiskArea::DataPrivacy));
    }

    #[test]
    fn test_control_id_risk_area_parsing_all() {
        for risk_area in Ai600RiskArea::all() {
            let id = Ai600ControlId::new(*risk_area, 1);
            assert_eq!(
                id.risk_area(),
                Some(*risk_area),
                "Failed to round-trip risk area {:?} through control ID {}",
                risk_area,
                id
            );
        }
    }

    #[test]
    fn test_control_id_invalid_parsing() {
        let id = Ai600ControlId("invalid".to_string());
        assert_eq!(id.risk_area(), None);
    }

    #[test]
    fn test_risk_area_codes_unique() {
        let mut codes = std::collections::HashSet::new();
        for risk_area in Ai600RiskArea::all() {
            assert!(
                codes.insert(risk_area.code()),
                "Duplicate risk area code: {}",
                risk_area.code()
            );
        }
    }

    #[test]
    fn test_risk_area_display() {
        assert_eq!(Ai600RiskArea::Cbrn.to_string(), "CBRN Information");
        assert_eq!(
            Ai600RiskArea::InformationSecurity.to_string(),
            "Information Security"
        );
        assert_eq!(
            Ai600RiskArea::ValueChainComponentIntegration.to_string(),
            "Value Chain/Component Integration"
        );
    }

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(Ai600ComplianceStatus::Mitigated.to_string(), "Mitigated");
        assert_eq!(Ai600ComplianceStatus::Partial.to_string(), "Partial");
        assert_eq!(
            Ai600ComplianceStatus::NotImplemented.to_string(),
            "Not Implemented"
        );
        assert_eq!(Ai600ComplianceStatus::NotApplicable.to_string(), "N/A");
    }

    #[test]
    fn test_get_control() {
        let registry = NistAi600Registry::new();
        let control = registry.get_control("AI600-ISEC-01");
        assert!(control.is_some());
        assert_eq!(control.unwrap().title, "Prompt injection prevention");
    }

    #[test]
    fn test_mitigations_for_prompt_injection() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_detection(VellavetoDetection::PromptInjection);
        assert!(
            !mitigations.is_empty(),
            "PromptInjection should map to at least one AI 600-1 control"
        );
        // Should map to ISEC controls
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("ISEC")));
    }

    #[test]
    fn test_mitigations_for_secrets_in_output() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_detection(VellavetoDetection::SecretsInOutput);
        assert!(
            !mitigations.is_empty(),
            "SecretsInOutput should map to PRIV controls"
        );
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("PRIV")));
    }

    #[test]
    fn test_mitigations_for_excessive_agency() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_detection(VellavetoDetection::ExcessiveAgency);
        assert!(
            !mitigations.is_empty(),
            "ExcessiveAgency should map to HAIC controls"
        );
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("HAIC")));
    }

    #[test]
    fn test_mitigations_for_tool_annotation_change() {
        let registry = NistAi600Registry::new();
        let mitigations =
            registry.mitigations_for_detection(VellavetoDetection::ToolAnnotationChange);
        assert!(
            !mitigations.is_empty(),
            "ToolAnnotationChange should map to VCINT controls"
        );
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("VCINT")));
    }

    #[test]
    fn test_mitigations_for_schema_poisoning() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_detection(VellavetoDetection::SchemaPoisoning);
        assert!(
            !mitigations.is_empty(),
            "SchemaPoisoning should map to VCINT controls"
        );
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("VCINT")));
    }

    #[test]
    fn test_mitigations_for_goal_drift() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_detection(VellavetoDetection::GoalDrift);
        assert!(
            !mitigations.is_empty(),
            "GoalDrift should map to CONF controls"
        );
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("CONF")));
    }

    #[test]
    fn test_mitigations_for_memory_injection() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_detection(VellavetoDetection::MemoryInjection);
        assert!(
            !mitigations.is_empty(),
            "MemoryInjection should map to CONF controls"
        );
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("CONF")));
    }

    #[test]
    fn test_mitigations_for_data_laundering() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_detection(VellavetoDetection::DataLaundering);
        assert!(
            !mitigations.is_empty(),
            "DataLaundering should map to PRIV controls"
        );
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("PRIV")));
    }

    #[test]
    fn test_mitigations_for_indirect_injection() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_detection(VellavetoDetection::IndirectInjection);
        assert!(
            !mitigations.is_empty(),
            "IndirectInjection should map to ISEC controls"
        );
        assert!(mitigations.iter().any(|m| m.control_id.0.contains("ISEC")));
    }

    #[test]
    fn test_rmf_cross_references() {
        let registry = NistAi600Registry::new();
        let refs = registry.rmf_cross_references("AI600-ISEC-01");
        assert!(!refs.is_empty(), "ISEC-01 should have RMF cross-references");
        assert!(refs.iter().any(|r| r.starts_with("MEASURE")));
    }

    #[test]
    fn test_eu_ai_act_cross_references() {
        let registry = NistAi600Registry::new();
        let refs = registry.eu_ai_act_cross_references("AI600-ISEC-01");
        assert!(
            !refs.is_empty(),
            "ISEC-01 should have EU AI Act cross-references"
        );
        assert!(refs.iter().any(|r| r.starts_with("Art")));
    }

    #[test]
    fn test_cross_references_nonexistent_control() {
        let registry = NistAi600Registry::new();
        let refs = registry.rmf_cross_references("AI600-NONEXISTENT-99");
        assert!(refs.is_empty());
    }

    #[test]
    fn test_generate_report() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test Corp", "test-001");
        assert!(!report.risk_areas.is_empty());
        assert!(report.compliance_percentage > 0.0);
        assert_eq!(report.organization_name, "Test Corp");
        assert_eq!(report.system_id, "test-001");
        assert_eq!(report.total_risk_areas, 12, "Should have 12 risk areas");
        assert_eq!(report.total_controls, 24, "Should have 24 total controls");
    }

    #[test]
    fn test_generate_report_has_cross_mappings() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test", "test");
        assert!(
            !report.cross_mappings.is_empty(),
            "Report should include cross-mappings"
        );
        // Should have both NIST AI RMF and EU AI Act mappings
        assert!(
            report
                .cross_mappings
                .iter()
                .any(|cm| cm.framework == "NIST AI RMF"),
            "Should have NIST AI RMF cross-mappings"
        );
        assert!(
            report
                .cross_mappings
                .iter()
                .any(|cm| cm.framework == "EU AI Act"),
            "Should have EU AI Act cross-mappings"
        );
    }

    #[test]
    fn test_compliance_percentage_range() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test", "test");
        assert!(report.compliance_percentage >= 0.0);
        assert!(report.compliance_percentage <= 100.0);
    }

    #[test]
    fn test_report_validate_success() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test", "test");
        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_report_validate_bad_percentage() {
        let registry = NistAi600Registry::new();
        let mut report = registry.generate_report("Test", "test");
        report.compliance_percentage = f32::NAN;
        assert!(report.validate().is_err());
    }

    #[test]
    fn test_report_validate_negative_percentage() {
        let registry = NistAi600Registry::new();
        let mut report = registry.generate_report("Test", "test");
        report.compliance_percentage = -1.0;
        assert!(report.validate().is_err());
    }

    #[test]
    fn test_report_validate_over_100_percentage() {
        let registry = NistAi600Registry::new();
        let mut report = registry.generate_report("Test", "test");
        report.compliance_percentage = 101.0;
        assert!(report.validate().is_err());
    }

    #[test]
    fn test_report_validate_too_many_risk_areas() {
        let registry = NistAi600Registry::new();
        let mut report = registry.generate_report("Test", "test");
        for i in 0..MAX_AI600_RISK_AREAS + 1 {
            report.risk_areas.push(RiskAreaAssessment {
                risk_area: Ai600RiskArea::Cbrn,
                risk_area_name: format!("fake-{i}"),
                total_controls: 0,
                mitigated_controls: 0,
                partial_controls: 0,
                coverage_percent: 0.0,
                controls: Vec::new(),
            });
        }
        assert!(report.validate().is_err());
    }

    #[test]
    fn test_report_validate_too_many_cross_mappings() {
        let registry = NistAi600Registry::new();
        let mut report = registry.generate_report("Test", "test");
        for i in 0..MAX_CROSS_MAPPINGS + 1 {
            report.cross_mappings.push(Ai600CrossMapping {
                ai600_control_id: format!("AI600-TEST-{i:02}"),
                framework: "test".to_string(),
                framework_ref: "test".to_string(),
            });
        }
        assert!(report.validate().is_err());
    }

    #[test]
    fn test_report_to_json() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test", "test");
        let json = report.to_json().unwrap();
        assert!(json.contains("compliance_percentage"));
        assert!(json.contains("risk_areas"));
        assert!(json.contains("cross_mappings"));
    }

    #[test]
    fn test_report_summary() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test Corp", "test");
        let summary = report.summary();
        assert!(summary.contains("NIST AI 600-1 GenAI Profile Compliance Summary"));
        assert!(summary.contains("Test Corp"));
        assert!(summary.contains("Information Security"));
        assert!(summary.contains("Data Privacy"));
        assert!(summary.contains("Confabulation"));
    }

    #[test]
    fn test_serde_roundtrip_report() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test", "test");
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: Ai600ComplianceReport =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.total_controls, report.total_controls);
        assert_eq!(deserialized.mitigated_controls, report.mitigated_controls);
        assert_eq!(deserialized.total_risk_areas, report.total_risk_areas);
    }

    #[test]
    fn test_default_trait() {
        let registry = NistAi600Registry::default();
        assert!(!registry.controls.is_empty());
    }

    #[test]
    fn test_all_controls_have_rmf_cross_references() {
        let registry = NistAi600Registry::new();
        for control in registry.controls() {
            assert!(
                !control.rmf_subcategories.is_empty(),
                "Control {} should have RMF cross-references",
                control.id
            );
        }
    }

    #[test]
    fn test_all_mitigations_reference_valid_controls() {
        let registry = NistAi600Registry::new();
        for mitigation in &registry.mitigations {
            assert!(
                registry.get_control(&mitigation.control_id.0).is_some(),
                "Mitigation references non-existent control: {}",
                mitigation.control_id
            );
        }
    }

    #[test]
    fn test_risk_area_all_returns_12() {
        assert_eq!(Ai600RiskArea::all().len(), 12);
    }

    #[test]
    fn test_mitigations_for_control_isec01() {
        let registry = NistAi600Registry::new();
        let mitigations = registry.mitigations_for_control("AI600-ISEC-01");
        assert!(
            mitigations.len() >= 2,
            "ISEC-01 should have mitigations for both direct and indirect injection"
        );
    }

    #[test]
    fn test_report_risk_area_assessments_sorted() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test", "test");
        // Risk areas should be in specification order (Ai600RiskArea::all() order)
        let expected_order: Vec<Ai600RiskArea> = Ai600RiskArea::all().to_vec();
        let actual_order: Vec<Ai600RiskArea> =
            report.risk_areas.iter().map(|ra| ra.risk_area).collect();
        assert_eq!(actual_order, expected_order);
    }

    #[test]
    fn test_report_controls_within_risk_area_sorted() {
        let registry = NistAi600Registry::new();
        let report = registry.generate_report("Test", "test");
        for ra in &report.risk_areas {
            for i in 1..ra.controls.len() {
                assert!(
                    ra.controls[i - 1].control_id <= ra.controls[i].control_id,
                    "Controls within {} should be sorted by ID",
                    ra.risk_area_name
                );
            }
        }
    }

    #[test]
    fn test_environmental_controls_have_no_eu_articles() {
        // Environmental risk area is not directly covered by EU AI Act articles
        let registry = NistAi600Registry::new();
        let controls = registry.controls_for_risk_area(Ai600RiskArea::Environmental);
        for control in controls {
            assert!(
                control.eu_ai_act_articles.is_empty(),
                "Environmental control {} should not reference EU AI Act articles",
                control.id
            );
        }
    }

    #[test]
    fn test_high_priority_detections_have_mitigations() {
        let registry = NistAi600Registry::new();

        // These detections are specified in the task as mandatory mappings
        let mandatory = [
            (VellavetoDetection::PromptInjection, "ISEC"),
            (VellavetoDetection::IndirectInjection, "ISEC"),
            (VellavetoDetection::SecretsInOutput, "PRIV"),
            (VellavetoDetection::DataLaundering, "PRIV"),
            (VellavetoDetection::ExcessiveAgency, "HAIC"),
            (VellavetoDetection::GoalDrift, "CONF"),
            (VellavetoDetection::MemoryInjection, "CONF"),
            (VellavetoDetection::ToolAnnotationChange, "VCINT"),
            (VellavetoDetection::SchemaPoisoning, "VCINT"),
        ];

        for (detection, expected_code) in mandatory {
            let mitigations = registry.mitigations_for_detection(detection);
            assert!(
                mitigations
                    .iter()
                    .any(|m| m.control_id.0.contains(expected_code)),
                "Detection {:?} should map to a {} control",
                detection,
                expected_code
            );
        }
    }
}
