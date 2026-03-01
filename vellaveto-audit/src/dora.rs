// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! DORA (Digital Operational Resilience Act) compliance evidence generation.
//!
//! Registry mapping Vellaveto capabilities to DORA articles (5–45) for
//! financial sector ICT risk management compliance evidence.
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::dora::DoraRegistry;
//!
//! let registry = DoraRegistry::new();
//! let report = registry.generate_report("Acme Bank", "acme-vellaveto-001");
//! println!("DORA coverage: {:.1}%", report.compliance_percentage);
//! ```

use serde::{Deserialize, Serialize};

// ── Article Identifier ───────────────────────────────────────────────────────

/// DORA article identifier (e.g., "Art 5", "Art 17").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DoraArticleId(pub String);

impl DoraArticleId {
    pub fn new(article: &str) -> Self {
        Self(article.to_string())
    }
}

impl std::fmt::Display for DoraArticleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Vellaveto Capability ─────────────────────────────────────────────────────

/// Vellaveto capabilities relevant to DORA compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DoraCapability {
    /// Art 5-6: ICT risk management framework — policy engine, fail-closed.
    IctRiskManagement,
    /// Art 7-8: ICT risk assessment — threat detection, behavioral anomaly.
    IctRiskAssessment,
    /// Art 9: Access control — ABAC, capability tokens, rate limiting.
    AccessControl,
    /// Art 10: Data integrity — hash chain, Merkle proofs, signed checkpoints.
    DataIntegrity,
    /// Art 11: Continuous monitoring — behavioral anomaly, least-agency tracking.
    ContinuousMonitoring,
    /// Art 12: ICT change management — policy lifecycle (Phase 47).
    IctChangeManagement,
    /// Art 13: Backup and recovery — circuit breaker, fallback chain.
    BackupAndRecovery,
    /// Art 17-19: ICT incident management — audit logging, alert events.
    IctIncidentManagement,
    /// Art 19-23: ICT incident reporting — audit export, webhook notifications.
    IctIncidentReporting,
    /// Art 24-27: Digital resilience testing — circuit breaker, red team engine.
    DigitalResilienceTesting,
    /// Art 28-30: Third-party ICT risk — tool registry, trust scoring, ETDI.
    ThirdPartyRisk,
    /// Art 45: Information sharing — audit trail, transparency marking.
    InformationSharing,
    /// Incident classification — DLP scanning, injection detection.
    IncidentClassification,
}

impl std::fmt::Display for DoraCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ── Compliance Status ────────────────────────────────────────────────────────

/// Implementation status for a DORA article.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DoraComplianceStatus {
    /// Fully implemented by Vellaveto capabilities.
    Compliant,
    /// Partially implemented — some evidence available.
    Partial,
    /// Not yet implemented.
    NotImplemented,
}

impl std::fmt::Display for DoraComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compliant => write!(f, "Compliant"),
            Self::Partial => write!(f, "Partial"),
            Self::NotImplemented => write!(f, "Not Implemented"),
        }
    }
}

// ── Assessment ───────────────────────────────────────────────────────────────

/// Assessment of a single DORA article.
/// SECURITY (FIND-R215-002): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoraAssessment {
    /// Article identifier.
    pub article_id: DoraArticleId,
    /// Short title.
    pub title: String,
    /// Description of the article requirement.
    pub description: String,
    /// Implementation status.
    pub status: DoraComplianceStatus,
    /// Vellaveto capabilities providing evidence.
    pub capabilities: Vec<DoraCapability>,
    /// Evidence description.
    pub evidence: String,
}

// ── Report ───────────────────────────────────────────────────────────────────

/// DORA compliance evidence report.
/// SECURITY (FIND-R215-002): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoraReport {
    /// ISO 8601 timestamp of generation.
    pub generated_at: String,
    /// Organization name.
    pub organization_name: String,
    /// System identifier.
    pub system_id: String,
    /// Individual article assessments.
    pub assessments: Vec<DoraAssessment>,
    /// Overall compliance percentage (0.0–100.0).
    pub compliance_percentage: f32,
    /// Total number of assessed articles.
    pub total_articles: usize,
    /// Number of compliant articles.
    pub compliant_articles: usize,
    /// Number of partially compliant articles.
    pub partial_articles: usize,
}

/// Maximum number of assessments in a report (bounds deserialized input).
const MAX_DORA_ASSESSMENTS: usize = 1_000;

impl DoraReport {
    /// Validate deserialized DoraReport bounds.
    ///
    /// SECURITY (FIND-R216-007): Prevents OOM from unbounded assessment vectors
    /// and ensures compliance_percentage is finite and in [0.0, 100.0].
    pub fn validate(&self) -> Result<(), String> {
        if self.assessments.len() > MAX_DORA_ASSESSMENTS {
            return Err(format!(
                "assessments count {} exceeds maximum of {}",
                self.assessments.len(),
                MAX_DORA_ASSESSMENTS,
            ));
        }
        if !self.compliance_percentage.is_finite()
            || self.compliance_percentage < 0.0
            || self.compliance_percentage > 100.0
        {
            return Err(format!(
                "compliance_percentage must be in [0.0, 100.0], got {}",
                self.compliance_percentage,
            ));
        }
        Ok(())
    }
}

// ── Registry ─────────────────────────────────────────────────────────────────

/// DORA compliance registry mapping Vellaveto capabilities to DORA articles.
pub struct DoraRegistry {
    assessments: Vec<DoraAssessment>,
}

impl DoraRegistry {
    /// Create a new registry with all article assessments populated.
    pub fn new() -> Self {
        let mut registry = Self {
            assessments: Vec::new(),
        };
        registry.populate();
        registry
    }

    /// Generate a DORA compliance evidence report.
    pub fn generate_report(&self, organization_name: &str, system_id: &str) -> DoraReport {
        let total = self.assessments.len();
        let compliant = self
            .assessments
            .iter()
            .filter(|a| a.status == DoraComplianceStatus::Compliant)
            .count();
        let partial = self
            .assessments
            .iter()
            .filter(|a| a.status == DoraComplianceStatus::Partial)
            .count();

        // SECURITY (FIND-R216-004): Fail-closed — no evidence means no compliance.
        // Returning 100% on empty assessments would be fail-open.
        let pct = if total > 0 {
            ((compliant as f32 + partial as f32 * 0.5) / total as f32) * 100.0
        } else {
            0.0
        };

        DoraReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            organization_name: organization_name.to_string(),
            system_id: system_id.to_string(),
            assessments: self.assessments.clone(),
            compliance_percentage: pct,
            total_articles: total,
            compliant_articles: compliant,
            partial_articles: partial,
        }
    }

    fn add(
        &mut self,
        article: &str,
        title: &str,
        description: &str,
        status: DoraComplianceStatus,
        capabilities: Vec<DoraCapability>,
        evidence: &str,
    ) {
        self.assessments.push(DoraAssessment {
            article_id: DoraArticleId::new(article),
            title: title.to_string(),
            description: description.to_string(),
            status,
            capabilities,
            evidence: evidence.to_string(),
        });
    }

    fn populate(&mut self) {
        use DoraCapability::*;
        use DoraComplianceStatus::*;

        // ── Chapter II: ICT Risk Management (Art 5–16) ──────────────────

        self.add(
            "Art 5",
            "ICT risk management framework",
            "Financial entities shall have an internal governance and control framework for ICT risk management.",
            Compliant,
            vec![IctRiskManagement],
            "Policy engine provides configurable ICT risk management with fail-closed defaults and priority-based evaluation",
        );

        self.add(
            "Art 6",
            "ICT risk management framework — elements",
            "ICT risk management framework shall include strategies, policies, procedures, protocols, and tools.",
            Compliant,
            vec![IctRiskManagement, AccessControl],
            "Comprehensive policy framework with path/domain/action rules, ABAC authorization, and capability-based delegation tokens",
        );

        self.add(
            "Art 7",
            "ICT systems, protocols and tools",
            "Financial entities shall identify, classify and document ICT-supported business functions and assets.",
            Partial,
            vec![IctRiskAssessment],
            "Tool discovery engine identifies and catalogs tools with sensitivity classification; shadow AI detection finds unregistered agents",
        );

        self.add(
            "Art 8",
            "Identification",
            "Identify all sources of ICT risk, ICT-supported business functions, and information assets.",
            Compliant,
            vec![IctRiskAssessment, IncidentClassification],
            "Threat detection across injection, DLP, rug-pull, squatting, behavioral anomaly, and cross-request exfiltration provides comprehensive risk identification",
        );

        self.add(
            "Art 9",
            "Protection and prevention",
            "Financial entities shall use ICT security tools and policies to minimize ICT risk impact.",
            Compliant,
            vec![AccessControl, IctRiskManagement],
            "ABAC with forbid-overrides, capability tokens, rate limiting, DLP scanning, injection detection, and domain/IP filtering",
        );

        self.add(
            "Art 10",
            "Detection",
            "Mechanisms to promptly detect anomalous activities and ICT-related incidents.",
            Compliant,
            vec![ContinuousMonitoring, IncidentClassification],
            "EMA-based behavioral anomaly detection, injection scanning (Aho-Corasick + NFKC), DLP 5-layer decode, tool squatting detection, memory poisoning defense",
        );

        self.add(
            "Art 11",
            "Response and recovery",
            "ICT business continuity policy with response and recovery procedures.",
            Compliant,
            vec![BackupAndRecovery, IctIncidentManagement],
            "Circuit breaker pattern (Closed/Open/HalfOpen with exponential backoff), cross-transport smart fallback chain (gRPC→WS→HTTP→stdio)",
        );

        self.add(
            "Art 12",
            "Backup policies and procedures",
            "Backup policies for restoration and recovery of data.",
            Partial,
            vec![DataIntegrity],
            "Tamper-evident audit log with SHA-256 hash chain, Ed25519 checkpoints, and immutable archive; audit log rotation with compressed archives",
        );

        self.add(
            "Art 13",
            "Learning and evolving",
            "Gather intelligence on vulnerabilities, threats, and post-incident reviews.",
            Compliant,
            vec![ContinuousMonitoring, DigitalResilienceTesting],
            "Red team mutation engine for continuous testing, behavioral anomaly detection with EMA drift, gap analysis across 8 frameworks",
        );

        self.add(
            "Art 14",
            "Communication",
            "Communication plans for ICT-related incidents and responsible disclosure.",
            Partial,
            vec![IctIncidentReporting],
            "Audit export to SIEM (CEF/JSONL/webhook/syslog), webhook notifications for security events, transparency marking per EU AI Act Art 50",
        );

        self.add(
            "Art 15",
            "Further harmonisation of ICT risk management tools",
            "Regulatory technical standards for ICT risk management tools.",
            Partial,
            vec![IctRiskManagement],
            "Standardized policy framework with TOML/JSON configuration, consistent evaluation semantics, formal verification (TLA+/Alloy)",
        );

        self.add(
            "Art 16",
            "Simplified ICT risk management framework",
            "Proportional simplified framework for certain financial entities.",
            Compliant,
            vec![IctRiskManagement],
            "Configurable policy complexity from simple allow/deny rules to full ABAC; tiered licensing supports proportional deployment",
        );

        // ── Chapter III: ICT Incidents (Art 17–23) ──────────────────────

        self.add(
            "Art 17",
            "ICT-related incident management process",
            "Define and implement an ICT-related incident management process.",
            Compliant,
            vec![IctIncidentManagement],
            "Comprehensive audit logging of all security decisions with tamper-evident hash chain; circuit breaker for cascading failure prevention",
        );

        self.add(
            "Art 18",
            "Classification of ICT-related incidents",
            "Classify ICT-related incidents based on number of affected clients, duration, data loss, and criticality.",
            Compliant,
            vec![IctIncidentManagement, IncidentClassification],
            "DLP classification (PII patterns, custom rules), injection severity levels, behavioral anomaly scoring, tool squatting detection severity",
        );

        self.add(
            "Art 19",
            "Reporting of major ICT-related incidents",
            "Report major ICT-related incidents to competent authorities.",
            Partial,
            vec![IctIncidentReporting],
            "Audit export supports CEF, JSONL, webhook, and syslog formats for SIEM integration; real-time webhook notifications for security events",
        );

        self.add(
            "Art 20",
            "Harmonisation of reporting content",
            "Standard templates and timelines for incident reporting.",
            Partial,
            vec![IctIncidentReporting],
            "Structured audit entries with consistent JSON schema; compliance reporting across 8 frameworks provides standardized evidence format",
        );

        self.add(
            "Art 21",
            "Centralisation of reporting",
            "Single EU hub for incident reporting.",
            Partial,
            vec![IctIncidentReporting],
            "Centralized audit store with PostgreSQL dual-write; audit query API with time/tool/verdict/agent filters",
        );

        self.add(
            "Art 22",
            "Supervisory feedback",
            "Competent authorities provide feedback on incidents.",
            Partial,
            vec![IctIncidentReporting],
            "Audit trail provides evidence basis for supervisory review; compliance reports support management review cycles",
        );

        self.add(
            "Art 23",
            "Operational or security payment-related incidents",
            "Payment-specific incident reporting obligations.",
            Partial,
            vec![IctIncidentReporting, IncidentClassification],
            "DLP scanning detects payment data exposure; audit events capture payment-related tool call patterns",
        );

        // ── Chapter IV: Digital Operational Resilience Testing (Art 24–27) ─

        self.add(
            "Art 24",
            "General requirements for testing",
            "Proportionate digital operational resilience testing programme.",
            Compliant,
            vec![DigitalResilienceTesting],
            "Red team mutation engine generates adversarial test cases; 24 fuzz targets; formal verification with TLA+ and Alloy models",
        );

        self.add(
            "Art 25",
            "Testing of ICT tools and systems",
            "Testing shall include vulnerability assessments, network security assessments, and source code reviews.",
            Compliant,
            vec![DigitalResilienceTesting],
            "Continuous adversarial testing through 210 audit rounds; injection/DLP/rug-pull detection validation; OWASP coverage tracking",
        );

        self.add(
            "Art 26",
            "Advanced testing: threat-led penetration testing",
            "TLPT for significant financial entities.",
            Compliant,
            vec![DigitalResilienceTesting],
            "Red team mutation engine simulates adversarial tool calls; session guard monitors for suspicious behavioral patterns",
        );

        self.add(
            "Art 27",
            "Requirements for testers",
            "Requirements for entities performing TLPT.",
            Partial,
            vec![DigitalResilienceTesting],
            "Red team engine provides automated adversarial testing; external pentest support through structured policy configuration",
        );

        // ── Chapter V: Third-Party ICT Risk (Art 28–44) ─────────────────

        self.add(
            "Art 28",
            "General principles",
            "Financial entities shall manage ICT third-party risk.",
            Compliant,
            vec![ThirdPartyRisk],
            "Tool registry with trust scoring, ETDI cryptographic verification of tool definitions, rug-pull detection for tool modification",
        );

        self.add(
            "Art 29",
            "Preliminary assessment of ICT concentration risk",
            "Assess concentration risk from third-party ICT providers.",
            Partial,
            vec![ThirdPartyRisk],
            "Shadow AI discovery detects unregistered tool providers; gateway routing tracks per-backend tool distribution",
        );

        self.add(
            "Art 30",
            "Key contractual provisions",
            "Contractual arrangements with ICT third-party providers.",
            Partial,
            vec![ThirdPartyRisk],
            "ETDI version pinning enforces tool provider commitments; capability token delegation with bounded scope and expiry",
        );

        self.add(
            "Art 31",
            "Register of information",
            "Register of all contractual arrangements with third-party ICT providers.",
            Compliant,
            vec![ThirdPartyRisk, DataIntegrity],
            "Tool registry maintains comprehensive catalog; NHI lifecycle management tracks agent identities and credentials; audit store provides historical record",
        );

        self.add(
            "Art 33",
            "Preliminary assessment of ICT concentration risk at entity level",
            "Entity-level concentration risk assessment.",
            Partial,
            vec![ThirdPartyRisk],
            "Least-agency tracking monitors tool usage patterns; shadow AI discovery identifies over-reliance on specific providers",
        );

        // ── Chapter VI: Information Sharing (Art 45) ────────────────────

        self.add(
            "Art 45",
            "Information sharing arrangements",
            "Financial entities may exchange cyber threat intelligence.",
            Compliant,
            vec![InformationSharing],
            "Structured audit trail with tamper-evident evidence; transparency marking per EU AI Act Art 50; OTLP export for observability sharing",
        );
    }
}

impl Default for DoraRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = DoraRegistry::new();
        assert!(!registry.assessments.is_empty());
    }

    #[test]
    fn test_article_id_display() {
        let id = DoraArticleId::new("Art 5");
        assert_eq!(id.to_string(), "Art 5");
    }

    #[test]
    fn test_generate_report() {
        let registry = DoraRegistry::new();
        let report = registry.generate_report("Test Bank", "bank-001");
        assert_eq!(report.organization_name, "Test Bank");
        assert_eq!(report.system_id, "bank-001");
        assert!(!report.assessments.is_empty());
        assert!(report.compliance_percentage > 0.0);
        assert!(report.compliance_percentage <= 100.0);
        assert!(report.compliant_articles > 0);
    }

    #[test]
    fn test_all_articles_present() {
        let registry = DoraRegistry::new();
        let report = registry.generate_report("Test", "test");
        // DORA has articles 5-16, 17-23, 24-27, 28-31, 33, 45 = ~27 articles
        assert!(
            report.total_articles >= 25,
            "Expected >= 25 articles, got {}",
            report.total_articles,
        );
    }

    #[test]
    fn test_coverage_above_50_percent() {
        let registry = DoraRegistry::new();
        let report = registry.generate_report("Test", "test");
        assert!(
            report.compliance_percentage >= 50.0,
            "DORA coverage {:.1}% below 50%",
            report.compliance_percentage,
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let registry = DoraRegistry::new();
        let report = registry.generate_report("Test", "test");
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: DoraReport =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.total_articles, report.total_articles);
    }

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(DoraComplianceStatus::Compliant.to_string(), "Compliant");
        assert_eq!(DoraComplianceStatus::Partial.to_string(), "Partial");
        assert_eq!(
            DoraComplianceStatus::NotImplemented.to_string(),
            "Not Implemented"
        );
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(
            format!("{}", DoraCapability::IctRiskManagement),
            "IctRiskManagement"
        );
    }

    #[test]
    fn test_default_trait() {
        let registry = DoraRegistry::default();
        let report = registry.generate_report("Test", "test");
        assert!(report.total_articles > 0);
    }

    /// FIND-R216-004: Empty registry returns 0% compliance (fail-closed).
    #[test]
    fn test_r216_004_empty_registry_returns_zero_percent() {
        let registry = DoraRegistry {
            assessments: Vec::new(),
        };
        let report = registry.generate_report("Test", "test");
        assert_eq!(
            report.compliance_percentage, 0.0,
            "Empty assessments must return 0% (fail-closed), not 100%"
        );
    }

    /// FIND-R216-007: DoraReport::validate() accepts valid report.
    #[test]
    fn test_r216_007_dora_report_validate_valid() {
        let registry = DoraRegistry::new();
        let report = registry.generate_report("Test", "test");
        assert!(report.validate().is_ok());
    }

    /// FIND-R216-007: DoraReport::validate() rejects NaN compliance_percentage.
    #[test]
    fn test_r216_007_dora_report_validate_nan_percentage() {
        let mut report = DoraRegistry::new().generate_report("Test", "test");
        report.compliance_percentage = f32::NAN;
        assert!(report.validate().is_err());
    }

    /// FIND-R216-007: DoraReport::validate() rejects out-of-range compliance_percentage.
    #[test]
    fn test_r216_007_dora_report_validate_out_of_range_percentage() {
        let mut report = DoraRegistry::new().generate_report("Test", "test");
        report.compliance_percentage = 150.0;
        assert!(report.validate().is_err());
    }
}
