// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! ISO/IEC 42001 AI Management System compliance evidence generation.
//!
//! Registry mapping Vellaveto capabilities to ISO 42001 clauses (4–10) for
//! certification readiness evidence. ISO 42001 is the world's first
//! certifiable AI management system standard.
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::iso42001::Iso42001Registry;
//!
//! let registry = Iso42001Registry::new();
//! let report = registry.generate_report("Acme Corp", "acme-vellaveto-001");
//! println!("ISO 42001 coverage: {:.1}%", report.compliance_percentage);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Clause Identifier ───────────────────────────────────────────────────────

/// ISO 42001 clause identifier (e.g., "4.1", "6.1.2").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClauseId(pub String);

impl ClauseId {
    pub fn new(clause: &str) -> Self {
        Self(clause.to_string())
    }
}

impl std::fmt::Display for ClauseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Vellaveto Capability ─────────────────────────────────────────────────────

/// Vellaveto capabilities relevant to ISO 42001 compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Iso42001Capability {
    /// Clause 4: Context — risk identification and stakeholder analysis.
    RiskIdentification,
    /// Clause 5: Leadership — policy definition and enforcement.
    PolicyEnforcement,
    /// Clause 5: Leadership — fail-closed design commitment.
    FailClosedDesign,
    /// Clause 6: Planning — risk assessment and treatment.
    RiskAssessment,
    /// Clause 6: Planning — injection/DLP detection as risk treatment.
    ThreatDetection,
    /// Clause 7: Support — audit logging and documentation.
    AuditLogging,
    /// Clause 7: Support — metrics and observability.
    MetricsCollection,
    /// Clause 8: Operation — policy evaluation at runtime.
    RuntimeEvaluation,
    /// Clause 8: Operation — human-in-the-loop approval.
    HumanApproval,
    /// Clause 9: Performance evaluation — hash chain verification.
    HashChainVerification,
    /// Clause 9: Performance evaluation — compliance reporting.
    ComplianceReporting,
    /// Clause 9: Performance evaluation — Merkle inclusion proofs.
    MerkleInclusionProofs,
    /// Clause 10: Improvement — behavioral anomaly detection.
    BehavioralAnomalyDetection,
    /// Clause 10: Improvement — circuit breaker for continuous improvement.
    CircuitBreaker,
}

impl std::fmt::Display for Iso42001Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ── Compliance Status ───────────────────────────────────────────────────────

/// Implementation status for an ISO 42001 clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// Fully implemented by Vellaveto capabilities.
    Compliant,
    /// Partially implemented — some evidence available.
    Partial,
    /// Not yet implemented.
    NotImplemented,
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compliant => write!(f, "Compliant"),
            Self::Partial => write!(f, "Partial"),
            Self::NotImplemented => write!(f, "Not Implemented"),
        }
    }
}

// ── Clause Definition ───────────────────────────────────────────────────────

/// An ISO 42001 clause requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clause {
    /// Clause identifier.
    pub id: ClauseId,
    /// Short title of the clause.
    pub title: String,
    /// Full description.
    pub description: String,
}

// ── Capability Mapping ──────────────────────────────────────────────────────

/// Maps a Vellaveto capability to an ISO 42001 clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseMapping {
    /// The Vellaveto capability providing evidence.
    pub capability: Iso42001Capability,
    /// The clause this evidence supports.
    pub clause_id: ClauseId,
    /// Implementation status.
    pub status: ComplianceStatus,
    /// Evidence description.
    pub evidence: Option<String>,
}

// ── Registry ────────────────────────────────────────────────────────────────

/// ISO/IEC 42001 AI Management System compliance registry.
///
/// Populates clauses from the standard and maps Vellaveto capabilities
/// to specific clauses for certification readiness evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso42001Registry {
    pub clauses: HashMap<String, Clause>,
    pub mappings: Vec<ClauseMapping>,
}

impl Iso42001Registry {
    /// Create a new registry with all clauses and capability mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            clauses: HashMap::new(),
            mappings: Vec::new(),
        };
        registry.populate_clauses();
        registry.populate_mappings();
        registry
    }

    fn add_clause(&mut self, id: &str, title: &str, description: &str) {
        let clause_id = ClauseId::new(id);
        self.clauses.insert(
            clause_id.0.clone(),
            Clause {
                id: clause_id,
                title: title.to_string(),
                description: description.to_string(),
            },
        );
    }

    fn add_mapping(
        &mut self,
        capability: Iso42001Capability,
        clause_id: &str,
        status: ComplianceStatus,
        evidence: Option<&str>,
    ) {
        self.mappings.push(ClauseMapping {
            capability,
            clause_id: ClauseId::new(clause_id),
            status,
            evidence: evidence.map(String::from),
        });
    }

    fn populate_clauses(&mut self) {
        // Clause 4: Context of the organization
        self.add_clause(
            "4.1",
            "Understanding the organization and its context",
            "Determine external and internal issues relevant to the AI management system.",
        );
        self.add_clause(
            "4.2",
            "Understanding needs and expectations of interested parties",
            "Determine interested parties and their requirements for the AIMS.",
        );
        self.add_clause(
            "4.3",
            "Determining the scope of the AIMS",
            "Determine boundaries and applicability of the AI management system.",
        );
        self.add_clause(
            "4.4",
            "AI management system",
            "Establish, implement, maintain and continually improve the AIMS.",
        );

        // Clause 5: Leadership
        self.add_clause(
            "5.1",
            "Leadership and commitment",
            "Top management demonstrates leadership and commitment to the AIMS.",
        );
        self.add_clause(
            "5.2",
            "AI policy",
            "Establish an AI policy appropriate to the purpose of the organization.",
        );
        self.add_clause(
            "5.3",
            "Organizational roles, responsibilities and authorities",
            "Assign and communicate responsibilities and authorities for the AIMS.",
        );

        // Clause 6: Planning
        self.add_clause(
            "6.1",
            "Actions to address risks and opportunities",
            "Plan actions to address risks and opportunities for the AIMS.",
        );
        self.add_clause(
            "6.1.2",
            "AI risk assessment",
            "Define and apply an AI risk assessment process.",
        );
        self.add_clause(
            "6.1.3",
            "AI risk treatment",
            "Define and apply an AI risk treatment process.",
        );
        self.add_clause(
            "6.2",
            "AI objectives and planning to achieve them",
            "Establish AI objectives at relevant functions and levels.",
        );

        // Clause 7: Support
        self.add_clause(
            "7.1",
            "Resources",
            "Determine and provide resources needed for the AIMS.",
        );
        self.add_clause(
            "7.4",
            "Communication",
            "Determine internal and external communications relevant to the AIMS.",
        );
        self.add_clause(
            "7.5",
            "Documented information",
            "The AIMS shall include documented information required by this standard.",
        );

        // Clause 8: Operation
        self.add_clause(
            "8.1",
            "Operational planning and control",
            "Plan, implement and control processes needed to meet AIMS requirements.",
        );
        self.add_clause(
            "8.2",
            "AI risk assessment execution",
            "Perform AI risk assessments at planned intervals or when significant changes occur.",
        );
        self.add_clause(
            "8.3",
            "AI risk treatment execution",
            "Implement the AI risk treatment plan.",
        );
        self.add_clause(
            "8.4",
            "AI system impact assessment",
            "Conduct impact assessments for AI systems considering affected stakeholders.",
        );

        // Clause 9: Performance evaluation
        self.add_clause(
            "9.1",
            "Monitoring, measurement, analysis and evaluation",
            "Determine what needs to be monitored and measured for AIMS effectiveness.",
        );
        self.add_clause(
            "9.2",
            "Internal audit",
            "Conduct internal audits at planned intervals to verify AIMS conformity.",
        );
        self.add_clause(
            "9.3",
            "Management review",
            "Top management reviews the AIMS at planned intervals for continuing suitability.",
        );

        // Clause 10: Improvement
        self.add_clause(
            "10.1",
            "Continual improvement",
            "Continually improve the suitability, adequacy and effectiveness of the AIMS.",
        );
        self.add_clause(
            "10.2",
            "Nonconformity and corrective action",
            "When nonconformity occurs, take action to control and correct it.",
        );
    }

    fn populate_mappings(&mut self) {
        // Clause 4: Context — risk identification
        self.add_mapping(
            Iso42001Capability::RiskIdentification,
            "4.1",
            ComplianceStatus::Partial,
            Some("Policy engine models AI system context through configurable security policies"),
        );
        self.add_mapping(
            Iso42001Capability::RiskIdentification,
            "4.4",
            ComplianceStatus::Compliant,
            Some("Vellaveto provides runtime AI management system for tool call governance"),
        );

        // Clause 5: Leadership — policy
        self.add_mapping(
            Iso42001Capability::PolicyEnforcement,
            "5.2",
            ComplianceStatus::Compliant,
            Some("AI policy enforcement through configurable security policies with fail-closed defaults"),
        );
        self.add_mapping(
            Iso42001Capability::FailClosedDesign,
            "5.1",
            ComplianceStatus::Compliant,
            Some("Fail-closed design demonstrates commitment to safe AI operation"),
        );

        // Clause 6: Planning — risk assessment and treatment
        self.add_mapping(
            Iso42001Capability::RiskAssessment,
            "6.1",
            ComplianceStatus::Compliant,
            Some("Policy evaluation addresses risks through path/domain/action rules"),
        );
        self.add_mapping(
            Iso42001Capability::RiskAssessment,
            "6.1.2",
            ComplianceStatus::Compliant,
            Some("Threat detection across injection, DLP, rug-pull, squatting provides risk assessment"),
        );
        self.add_mapping(
            Iso42001Capability::ThreatDetection,
            "6.1.3",
            ComplianceStatus::Compliant,
            Some("Deny verdicts and DLP scanning implement AI risk treatment controls"),
        );

        // Clause 7: Support — documentation and communication
        self.add_mapping(
            Iso42001Capability::AuditLogging,
            "7.5",
            ComplianceStatus::Compliant,
            Some("Tamper-evident SHA-256 hash chain audit log provides documented information"),
        );
        self.add_mapping(
            Iso42001Capability::MetricsCollection,
            "7.4",
            ComplianceStatus::Compliant,
            Some("Prometheus metrics, CEF/JSONL/syslog export enable AIMS communication"),
        );

        // Clause 8: Operation — runtime controls
        self.add_mapping(
            Iso42001Capability::RuntimeEvaluation,
            "8.1",
            ComplianceStatus::Compliant,
            Some("Policy engine evaluates every tool call at runtime with <5ms P99 latency"),
        );
        self.add_mapping(
            Iso42001Capability::ThreatDetection,
            "8.2",
            ComplianceStatus::Compliant,
            Some(
                "Continuous risk assessment via injection detection, DLP, and behavioral analysis",
            ),
        );
        self.add_mapping(
            Iso42001Capability::RuntimeEvaluation,
            "8.3",
            ComplianceStatus::Compliant,
            Some("Risk treatment execution through Deny verdicts and policy enforcement"),
        );
        self.add_mapping(
            Iso42001Capability::HumanApproval,
            "8.4",
            ComplianceStatus::Compliant,
            Some("Human-in-the-loop approval workflow for AI system impact assessment"),
        );

        // Clause 9: Performance evaluation — monitoring and audit
        self.add_mapping(
            Iso42001Capability::MetricsCollection,
            "9.1",
            ComplianceStatus::Compliant,
            Some("Prometheus metrics with evaluation histograms for AIMS monitoring"),
        );
        self.add_mapping(
            Iso42001Capability::HashChainVerification,
            "9.2",
            ComplianceStatus::Compliant,
            Some("Hash chain verification with tamper detection provides internal audit evidence"),
        );
        self.add_mapping(
            Iso42001Capability::MerkleInclusionProofs,
            "9.2",
            ComplianceStatus::Compliant,
            Some("RFC 6962 Merkle tree inclusion proofs for individual entry verification"),
        );
        self.add_mapping(
            Iso42001Capability::ComplianceReporting,
            "9.3",
            ComplianceStatus::Compliant,
            Some("Cross-framework compliance reporting supports management review"),
        );

        // Clause 10: Improvement — continuous improvement
        self.add_mapping(
            Iso42001Capability::BehavioralAnomalyDetection,
            "10.1",
            ComplianceStatus::Compliant,
            Some("EMA-based behavioral anomaly detection drives continual improvement"),
        );
        self.add_mapping(
            Iso42001Capability::CircuitBreaker,
            "10.2",
            ComplianceStatus::Compliant,
            Some("Circuit breaker pattern provides corrective action on detected failures"),
        );
    }

    // ── Query Methods ────────────────────────────────────────────────────────

    /// Get mappings for a specific clause.
    pub fn mappings_for_clause(&self, clause_id: &str) -> Vec<&ClauseMapping> {
        self.mappings
            .iter()
            .filter(|m| m.clause_id.0 == clause_id)
            .collect()
    }

    /// Get mappings for a specific capability.
    pub fn mappings_for_capability(&self, capability: Iso42001Capability) -> Vec<&ClauseMapping> {
        self.mappings
            .iter()
            .filter(|m| m.capability == capability)
            .collect()
    }

    /// Get a clause definition.
    pub fn get_clause(&self, clause_id: &str) -> Option<&Clause> {
        self.clauses.get(clause_id)
    }

    // ── Report Generation ────────────────────────────────────────────────────

    /// Generate an ISO 42001 compliance evidence report.
    pub fn generate_report(&self, organization_name: &str, system_id: &str) -> Iso42001Report {
        let mut clause_assessments = Vec::new();

        for (clause_key, clause) in &self.clauses {
            let mappings = self.mappings_for_clause(clause_key);
            let status = if mappings.is_empty() {
                ComplianceStatus::NotImplemented
            } else {
                let all_compliant = mappings
                    .iter()
                    .all(|m| m.status == ComplianceStatus::Compliant);
                let any_evidence = mappings.iter().any(|m| {
                    m.status == ComplianceStatus::Compliant || m.status == ComplianceStatus::Partial
                });
                if all_compliant {
                    ComplianceStatus::Compliant
                } else if any_evidence {
                    ComplianceStatus::Partial
                } else {
                    ComplianceStatus::NotImplemented
                }
            };

            let evidence: Vec<String> =
                mappings.iter().filter_map(|m| m.evidence.clone()).collect();
            let capabilities: Vec<Iso42001Capability> =
                mappings.iter().map(|m| m.capability).collect();

            clause_assessments.push(ClauseAssessment {
                clause_id: clause_key.clone(),
                title: clause.title.clone(),
                status,
                capabilities,
                evidence,
            });
        }

        clause_assessments.sort_by(|a, b| a.clause_id.cmp(&b.clause_id));

        let total_clauses = clause_assessments.len();
        let compliant_count = clause_assessments
            .iter()
            .filter(|a| a.status == ComplianceStatus::Compliant)
            .count();
        let partial_count = clause_assessments
            .iter()
            .filter(|a| a.status == ComplianceStatus::Partial)
            .count();

        let compliance_percentage = if total_clauses > 0 {
            ((compliant_count as f32 + partial_count as f32 * 0.5) / total_clauses as f32) * 100.0
        } else {
            100.0
        };

        Iso42001Report {
            generated_at: chrono::Utc::now().to_rfc3339(),
            organization_name: organization_name.to_string(),
            system_id: system_id.to_string(),
            compliance_percentage,
            total_clauses,
            compliant_clauses: compliant_count,
            partial_clauses: partial_count,
            assessments: clause_assessments,
        }
    }
}

impl Default for Iso42001Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Report Types ────────────────────────────────────────────────────────────

/// Assessment for a single ISO 42001 clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseAssessment {
    pub clause_id: String,
    pub title: String,
    pub status: ComplianceStatus,
    pub capabilities: Vec<Iso42001Capability>,
    pub evidence: Vec<String>,
}

/// ISO 42001 compliance evidence report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso42001Report {
    pub generated_at: String,
    pub organization_name: String,
    pub system_id: String,
    pub compliance_percentage: f32,
    pub total_clauses: usize,
    pub compliant_clauses: usize,
    pub partial_clauses: usize,
    pub assessments: Vec<ClauseAssessment>,
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = Iso42001Registry::new();
        assert!(!registry.clauses.is_empty());
        assert!(!registry.mappings.is_empty());
    }

    #[test]
    fn test_clause_id_creation() {
        let id = ClauseId::new("6.1.2");
        assert_eq!(id.0, "6.1.2");
        assert_eq!(id.to_string(), "6.1.2");
    }

    #[test]
    fn test_all_major_clauses_populated() {
        let registry = Iso42001Registry::new();
        // Clauses 4–10 should be present
        assert!(registry.get_clause("4.1").is_some(), "Missing clause 4.1");
        assert!(registry.get_clause("5.2").is_some(), "Missing clause 5.2");
        assert!(registry.get_clause("6.1").is_some(), "Missing clause 6.1");
        assert!(registry.get_clause("7.5").is_some(), "Missing clause 7.5");
        assert!(registry.get_clause("8.1").is_some(), "Missing clause 8.1");
        assert!(registry.get_clause("9.1").is_some(), "Missing clause 9.1");
        assert!(registry.get_clause("10.1").is_some(), "Missing clause 10.1");
    }

    #[test]
    fn test_clause_content() {
        let registry = Iso42001Registry::new();
        let clause = registry.get_clause("5.2").expect("clause 5.2 should exist");
        assert_eq!(clause.title, "AI policy");
    }

    #[test]
    fn test_mappings_for_clause() {
        let registry = Iso42001Registry::new();
        let mappings = registry.mappings_for_clause("9.2");
        assert!(
            mappings.len() >= 2,
            "Clause 9.2 should have at least 2 mappings (hash chain + merkle)"
        );
    }

    #[test]
    fn test_mappings_for_capability() {
        let registry = Iso42001Registry::new();
        let mappings = registry.mappings_for_capability(Iso42001Capability::PolicyEnforcement);
        assert!(!mappings.is_empty());
    }

    #[test]
    fn test_generate_report() {
        let registry = Iso42001Registry::new();
        let report = registry.generate_report("Test Corp", "test-001");
        assert!(!report.assessments.is_empty());
        assert!(report.compliance_percentage > 0.0);
        assert_eq!(report.organization_name, "Test Corp");
        assert_eq!(report.system_id, "test-001");
        assert!(report.compliant_clauses > 0);
    }

    #[test]
    fn test_compliance_percentage_range() {
        let registry = Iso42001Registry::new();
        let report = registry.generate_report("Test", "test");
        assert!(report.compliance_percentage >= 0.0);
        assert!(report.compliance_percentage <= 100.0);
    }

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(ComplianceStatus::Compliant.to_string(), "Compliant");
        assert_eq!(ComplianceStatus::Partial.to_string(), "Partial");
        assert_eq!(
            ComplianceStatus::NotImplemented.to_string(),
            "Not Implemented"
        );
    }

    #[test]
    fn test_assessments_sorted() {
        let registry = Iso42001Registry::new();
        let report = registry.generate_report("Test", "test");
        for i in 1..report.assessments.len() {
            assert!(
                report.assessments[i - 1].clause_id <= report.assessments[i].clause_id,
                "Assessments should be sorted by clause_id"
            );
        }
    }

    #[test]
    fn test_serde_roundtrip_report() {
        let registry = Iso42001Registry::new();
        let report = registry.generate_report("Test", "test");
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: Iso42001Report =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.total_clauses, report.total_clauses);
        assert_eq!(deserialized.compliant_clauses, report.compliant_clauses);
    }

    #[test]
    fn test_default_trait() {
        let registry = Iso42001Registry::default();
        assert!(!registry.clauses.is_empty());
    }

    #[test]
    fn test_high_coverage() {
        let registry = Iso42001Registry::new();
        let report = registry.generate_report("Test", "test");
        // Most clauses should have at least partial coverage
        let covered = report
            .assessments
            .iter()
            .filter(|a| a.status != ComplianceStatus::NotImplemented)
            .count();
        assert!(
            covered as f32 / report.total_clauses as f32 >= 0.5,
            "At least 50% of clauses should have coverage"
        );
    }

    #[test]
    fn test_clause_count() {
        let registry = Iso42001Registry::new();
        // ISO 42001 has clauses 4–10 with subclauses; we should have ~22
        assert!(
            registry.clauses.len() >= 15,
            "Expected >= 15 clauses, got {}",
            registry.clauses.len()
        );
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(
            format!("{}", Iso42001Capability::PolicyEnforcement),
            "PolicyEnforcement"
        );
    }
}
