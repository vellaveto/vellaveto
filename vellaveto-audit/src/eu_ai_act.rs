// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! EU AI Act compliance evidence generation.
//!
//! Registry pattern matching `nist_rmf.rs` and `iso27090.rs`. Maps Vellaveto
//! capabilities to EU AI Act articles and generates conformity assessment
//! reports for Art 43 compliance evidence.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Article Identifiers ──────────────────────────────────────────────────────

/// EU AI Act article identifier (e.g., "Art 12", "Art 50(1)").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArticleId(pub String);

impl ArticleId {
    pub fn new(article: u8, paragraph: Option<u8>) -> Self {
        if let Some(p) = paragraph {
            Self(format!("Art {article}({p})"))
        } else {
            Self(format!("Art {article}"))
        }
    }
}

impl std::fmt::Display for ArticleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Transparency Capability ──────────────────────────────────────────────────

/// Vellaveto capabilities relevant to EU AI Act compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransparencyCapability {
    /// Art 50(1): AI-mediated content marking.
    AiMediationMarking,
    /// Art 50(2): Synthetic content labeling.
    SyntheticContentLabeling,
    /// Art 14: Human oversight / approval workflow.
    HumanApproval,
    /// Art 12: Tamper-evident audit logging.
    TamperEvidentAuditLog,
    /// Art 12: Hash chain verification.
    HashChainVerification,
    /// Art 12: Merkle tree inclusion proofs.
    MerkleInclusionProofs,
    /// Art 9: Risk management — policy enforcement.
    PolicyEnforcement,
    /// Art 9: Risk management — injection detection.
    InjectionDetection,
    /// Art 9: Risk management — DLP scanning.
    DlpScanning,
    /// Art 15: Accuracy — output validation.
    OutputValidation,
    /// Art 15: Robustness — circuit breaker.
    CircuitBreaker,
    /// Art 15: Cybersecurity — rate limiting.
    RateLimiting,
    /// Art 13: Transparency — audit log export.
    AuditLogExport,
    /// Art 13: Transparency — metrics collection.
    MetricsCollection,
    /// Art 43: Conformity assessment — signed checkpoints.
    SignedCheckpoints,
    /// Art 6: Risk classification evidence.
    RiskClassification,
    /// Art 14: Human oversight — kill switch.
    KillSwitch,
    /// Art 10: Data governance record keeping.
    DataGovernance,
}

impl std::fmt::Display for TransparencyCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── Obligation ───────────────────────────────────────────────────────────────

/// An obligation under the EU AI Act.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    /// Article identifier.
    pub article_id: ArticleId,
    /// Short title of the obligation.
    pub title: String,
    /// Full description.
    pub description: String,
    /// Which risk classes this applies to.
    pub applies_to: Vec<vellaveto_types::AiActRiskClass>,
}

// ── Compliance Status ────────────────────────────────────────────────────────

/// Implementation status for an article obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// Fully implemented by Vellaveto capabilities.
    Compliant,
    /// Partially implemented — some evidence available.
    Partial,
    /// Not yet implemented.
    NotImplemented,
    /// Not applicable to the configured risk class.
    NotApplicable,
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compliant => write!(f, "Compliant"),
            Self::Partial => write!(f, "Partial"),
            Self::NotImplemented => write!(f, "Not Implemented"),
            Self::NotApplicable => write!(f, "N/A"),
        }
    }
}

// ── Capability Mapping ───────────────────────────────────────────────────────

/// Maps a Vellaveto capability to an EU AI Act article.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArticleMapping {
    /// The Vellaveto capability providing evidence.
    pub capability: TransparencyCapability,
    /// The article this evidence supports.
    pub article_id: ArticleId,
    /// Implementation status.
    pub status: ComplianceStatus,
    /// Evidence description.
    pub evidence: Option<String>,
}

// ── Registry ─────────────────────────────────────────────────────────────────

/// EU AI Act compliance registry.
///
/// Populates obligations from the Act and maps Vellaveto capabilities
/// to specific articles for conformity assessment evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EuAiActRegistry {
    pub obligations: HashMap<String, Obligation>,
    pub mappings: Vec<ArticleMapping>,
}

impl EuAiActRegistry {
    /// Create a new registry with all obligations and capability mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            obligations: HashMap::new(),
            mappings: Vec::new(),
        };
        registry.populate_obligations();
        registry.populate_mappings();
        registry
    }

    fn add_obligation(
        &mut self,
        article: u8,
        paragraph: Option<u8>,
        title: &str,
        description: &str,
        applies_to: Vec<vellaveto_types::AiActRiskClass>,
    ) {
        let id = ArticleId::new(article, paragraph);
        self.obligations.insert(
            id.0.clone(),
            Obligation {
                article_id: id,
                title: title.to_string(),
                description: description.to_string(),
                applies_to,
            },
        );
    }

    fn add_mapping(
        &mut self,
        capability: TransparencyCapability,
        article: &str,
        status: ComplianceStatus,
        evidence: Option<&str>,
    ) {
        self.mappings.push(ArticleMapping {
            capability,
            article_id: ArticleId(article.to_string()),
            status,
            evidence: evidence.map(String::from),
        });
    }

    fn populate_obligations(&mut self) {
        use vellaveto_types::AiActRiskClass::*;

        self.add_obligation(
            5,
            None,
            "Prohibited AI practices",
            "AI systems falling under Art 5 prohibited practices must not be deployed.",
            vec![Unacceptable],
        );
        self.add_obligation(
            6,
            None,
            "Classification rules for high-risk AI",
            "AI systems meeting Art 6 criteria must comply with Chapter III requirements.",
            vec![HighRisk],
        );
        self.add_obligation(
            9,
            None,
            "Risk management system",
            "Establish and maintain a risk management system throughout the AI system lifecycle.",
            vec![HighRisk],
        );
        self.add_obligation(
            10,
            None,
            "Data and data governance",
            "Training, validation and testing data sets shall meet quality criteria, be subject to data governance and management practices.",
            vec![HighRisk],
        );
        self.add_obligation(
            12, None,
            "Record-keeping / logging",
            "Automatic recording of events (logs) throughout the AI system lifetime for traceability.",
            vec![HighRisk],
        );
        self.add_obligation(
            13, None,
            "Transparency and information provision",
            "Provide sufficient transparency to deployers to interpret and use the system appropriately.",
            vec![HighRisk, Limited],
        );
        self.add_obligation(
            14,
            None,
            "Human oversight",
            "AI systems designed to allow effective human oversight during use.",
            vec![HighRisk],
        );
        self.add_obligation(
            15,
            None,
            "Accuracy, robustness, and cybersecurity",
            "AI systems achieve appropriate levels of accuracy, robustness, and cybersecurity.",
            vec![HighRisk],
        );
        self.add_obligation(
            43, None,
            "Conformity assessment",
            "High-risk AI systems undergo conformity assessment procedure before placement on market.",
            vec![HighRisk],
        );
        self.add_obligation(
            50,
            Some(1),
            "Transparency: AI interaction disclosure",
            "Persons interacting with AI must be informed they are interacting with an AI system.",
            vec![Limited, HighRisk],
        );
        self.add_obligation(
            50, Some(2),
            "Transparency: synthetic content labeling",
            "AI-generated synthetic content must be marked as artificially generated or manipulated.",
            vec![Limited, HighRisk],
        );
    }

    fn populate_mappings(&mut self) {
        // Art 50(1): Transparency — AI interaction disclosure
        self.add_mapping(
            TransparencyCapability::AiMediationMarking,
            "Art 50(1)",
            ComplianceStatus::Compliant,
            Some("Runtime transparency marking injects _meta.vellaveto_ai_mediated into tool responses per Art 50(1)"),
        );

        // Art 50(2): Synthetic content labeling + automated decision explanations
        self.add_mapping(
            TransparencyCapability::SyntheticContentLabeling,
            "Art 50(2)",
            ComplianceStatus::Compliant,
            Some("Per-verdict structured decision explanations injected into _meta at configurable verbosity (none/summary/full)"),
        );

        // Art 9: Risk management
        self.add_mapping(
            TransparencyCapability::PolicyEnforcement,
            "Art 9",
            ComplianceStatus::Compliant,
            Some("Policy engine enforces security policies on all tool calls"),
        );
        self.add_mapping(
            TransparencyCapability::InjectionDetection,
            "Art 9",
            ComplianceStatus::Compliant,
            Some("Injection detection with Aho-Corasick and Unicode NFKC normalization"),
        );
        self.add_mapping(
            TransparencyCapability::DlpScanning,
            "Art 9",
            ComplianceStatus::Compliant,
            Some("5-layer DLP scanning on requests and responses"),
        );

        // Art 10: Data governance
        self.add_mapping(
            TransparencyCapability::DataGovernance,
            "Art 10",
            ComplianceStatus::Compliant,
            Some("Data governance registry with per-tool classification, provenance, purpose, and retention tracking"),
        );

        // Art 12: Record-keeping
        self.add_mapping(
            TransparencyCapability::TamperEvidentAuditLog,
            "Art 12",
            ComplianceStatus::Compliant,
            Some("SHA-256 hash chain audit log with tamper detection"),
        );
        self.add_mapping(
            TransparencyCapability::HashChainVerification,
            "Art 12",
            ComplianceStatus::Compliant,
            Some("Cryptographic hash chain verification with gap and tamper detection"),
        );
        self.add_mapping(
            TransparencyCapability::MerkleInclusionProofs,
            "Art 12",
            ComplianceStatus::Compliant,
            Some("RFC 6962 Merkle tree inclusion proofs for individual entry verification"),
        );
        self.add_mapping(
            TransparencyCapability::SignedCheckpoints,
            "Art 12",
            ComplianceStatus::Compliant,
            Some("Ed25519 signed checkpoints with Merkle root for audit trail integrity"),
        );

        // Art 13: Transparency
        self.add_mapping(
            TransparencyCapability::AuditLogExport,
            "Art 13",
            ComplianceStatus::Compliant,
            Some("CEF, JSON Lines, webhook, and syslog export for SIEM integration"),
        );
        self.add_mapping(
            TransparencyCapability::MetricsCollection,
            "Art 13",
            ComplianceStatus::Compliant,
            Some("Prometheus metrics endpoint with evaluation histograms"),
        );

        // Art 14: Human oversight
        self.add_mapping(
            TransparencyCapability::HumanApproval,
            "Art 14",
            ComplianceStatus::Compliant,
            Some("Human-in-the-loop approval workflow with deduplication, audit trail, and configurable human oversight tool triggers"),
        );
        self.add_mapping(
            TransparencyCapability::KillSwitch,
            "Art 14",
            ComplianceStatus::Compliant,
            Some("Circuit breaker kill switch for immediate system shutdown"),
        );

        // Art 15: Accuracy, robustness, cybersecurity
        self.add_mapping(
            TransparencyCapability::OutputValidation,
            "Art 15",
            ComplianceStatus::Compliant,
            Some("Structured output schema validation registry"),
        );
        self.add_mapping(
            TransparencyCapability::CircuitBreaker,
            "Art 15",
            ComplianceStatus::Compliant,
            Some("Circuit breaker with half-open recovery for cascading failure protection"),
        );
        self.add_mapping(
            TransparencyCapability::RateLimiting,
            "Art 15",
            ComplianceStatus::Compliant,
            Some("Per-category rate limiting on all endpoints"),
        );

        // Art 6: Risk classification
        self.add_mapping(
            TransparencyCapability::RiskClassification,
            "Art 6",
            ComplianceStatus::Partial,
            Some("Risk class configurable; automated classification not yet implemented"),
        );

        // Art 43: Conformity assessment
        self.add_mapping(
            TransparencyCapability::SignedCheckpoints,
            "Art 43",
            ComplianceStatus::Partial,
            Some("Signed checkpoints provide audit evidence for conformity assessment"),
        );
    }

    // ── Query Methods ────────────────────────────────────────────────────────

    /// Get mappings for a specific article.
    pub fn mappings_for_article(&self, article_id: &str) -> Vec<&ArticleMapping> {
        self.mappings
            .iter()
            .filter(|m| m.article_id.0 == article_id)
            .collect()
    }

    /// Get mappings for a specific capability.
    pub fn mappings_for_capability(
        &self,
        capability: TransparencyCapability,
    ) -> Vec<&ArticleMapping> {
        self.mappings
            .iter()
            .filter(|m| m.capability == capability)
            .collect()
    }

    /// Get obligation for an article.
    pub fn get_obligation(&self, article_id: &str) -> Option<&Obligation> {
        self.obligations.get(article_id)
    }

    // ── Assessment Generation ────────────────────────────────────────────────

    /// Generate a conformity assessment report.
    ///
    /// Parameters are passed as primitives so this module does not depend on
    /// vellaveto-config (preserving the crate dependency graph).
    pub fn generate_assessment(
        &self,
        risk_class: vellaveto_types::AiActRiskClass,
        deployer_name: &str,
        system_id: &str,
    ) -> ConformityAssessmentReport {
        let mut article_assessments = Vec::new();

        for (article_key, obligation) in &self.obligations {
            // Check if this article applies to the configured risk class
            let applicable = obligation.applies_to.contains(&risk_class);

            let mappings = self.mappings_for_article(article_key);
            let status = if !applicable {
                ComplianceStatus::NotApplicable
            } else if mappings.is_empty() {
                ComplianceStatus::NotImplemented
            } else {
                // Overall status: Compliant if all are Compliant, Partial if any Partial,
                // NotImplemented if none
                let all_compliant = mappings
                    .iter()
                    .all(|m| m.status == ComplianceStatus::Compliant);
                let any_compliant = mappings.iter().any(|m| {
                    m.status == ComplianceStatus::Compliant || m.status == ComplianceStatus::Partial
                });
                if all_compliant {
                    ComplianceStatus::Compliant
                } else if any_compliant {
                    ComplianceStatus::Partial
                } else {
                    ComplianceStatus::NotImplemented
                }
            };

            let evidence: Vec<String> =
                mappings.iter().filter_map(|m| m.evidence.clone()).collect();

            let capabilities: Vec<TransparencyCapability> =
                mappings.iter().map(|m| m.capability).collect();

            article_assessments.push(ArticleAssessment {
                article_id: article_key.clone(),
                title: obligation.title.clone(),
                status,
                applicable,
                capabilities,
                evidence,
            });
        }

        article_assessments.sort_by(|a, b| a.article_id.cmp(&b.article_id));

        // Calculate overall compliance
        let applicable_count = article_assessments.iter().filter(|a| a.applicable).count();
        let compliant_count = article_assessments
            .iter()
            .filter(|a| a.applicable && a.status == ComplianceStatus::Compliant)
            .count();
        let partial_count = article_assessments
            .iter()
            .filter(|a| a.applicable && a.status == ComplianceStatus::Partial)
            .count();

        let compliance_percentage = if applicable_count > 0 {
            ((compliant_count as f32 + partial_count as f32 * 0.5) / applicable_count as f32)
                * 100.0
        } else {
            100.0
        };

        ConformityAssessmentReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            risk_class,
            deployer_name: deployer_name.to_string(),
            system_id: system_id.to_string(),
            compliance_percentage,
            total_articles: article_assessments.len(),
            applicable_articles: applicable_count,
            compliant_articles: compliant_count,
            partial_articles: partial_count,
            assessments: article_assessments,
        }
    }
}

impl Default for EuAiActRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Report Types ─────────────────────────────────────────────────────────────

/// Assessment for a single EU AI Act article.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArticleAssessment {
    pub article_id: String,
    pub title: String,
    pub status: ComplianceStatus,
    pub applicable: bool,
    pub capabilities: Vec<TransparencyCapability>,
    pub evidence: Vec<String>,
}

/// Conformity assessment report per Art 43.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformityAssessmentReport {
    pub generated_at: String,
    pub risk_class: vellaveto_types::AiActRiskClass,
    pub deployer_name: String,
    pub system_id: String,
    pub compliance_percentage: f32,
    pub total_articles: usize,
    pub applicable_articles: usize,
    pub compliant_articles: usize,
    pub partial_articles: usize,
    pub assessments: Vec<ArticleAssessment>,
}

// ── Entry Classification ─────────────────────────────────────────────────────

/// Classify an audit entry for EU AI Act transparency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyRecord {
    /// Which articles this entry provides evidence for.
    pub relevant_articles: Vec<String>,
    /// Classification reason.
    pub reason: String,
}

/// Classify an audit entry for EU AI Act relevance.
///
/// Entries are classified at report time (read-time classification),
/// matching the pattern used by `nist_rmf.rs` and `iso27090.rs`.
pub fn classify_entry_transparency(entry: &crate::AuditEntry) -> TransparencyRecord {
    let mut articles = Vec::new();
    let mut reasons = Vec::new();

    // All audit entries provide Art 12 evidence (record-keeping)
    articles.push("Art 12".to_string());
    reasons.push("audit log entry");

    // Approval entries provide Art 14 evidence (human oversight)
    if entry.action.tool.contains("approval") || entry.action.function.contains("approval") {
        articles.push("Art 14".to_string());
        reasons.push("human oversight evidence");
    }

    // Deny verdicts provide Art 9 evidence (risk management)
    if matches!(entry.verdict, vellaveto_types::Verdict::Deny { .. }) {
        articles.push("Art 9".to_string());
        reasons.push("risk management enforcement");
    }

    // DLP or injection findings provide Art 9 + Art 15 evidence
    if entry.action.function.contains("dlp") || entry.action.function.contains("injection") {
        articles.push("Art 9".to_string());
        articles.push("Art 15".to_string());
        reasons.push("security detection evidence");
    }

    // Deduplicate
    articles.sort();
    articles.dedup();

    TransparencyRecord {
        relevant_articles: articles,
        reason: reasons.join("; "),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::AiActRiskClass;

    #[test]
    fn test_registry_creation() {
        let registry = EuAiActRegistry::new();
        assert!(!registry.obligations.is_empty());
        assert!(!registry.mappings.is_empty());
    }

    #[test]
    fn test_article_id_parsing() {
        let id = ArticleId::new(50, Some(1));
        assert_eq!(id.0, "Art 50(1)");

        let id2 = ArticleId::new(12, None);
        assert_eq!(id2.0, "Art 12");
    }

    #[test]
    fn test_obligation_populated() {
        let registry = EuAiActRegistry::new();
        let art12 = registry.get_obligation("Art 12");
        assert!(art12.is_some());
        assert_eq!(art12.unwrap().title, "Record-keeping / logging");
    }

    #[test]
    fn test_mappings_for_article() {
        let registry = EuAiActRegistry::new();
        let art12_mappings = registry.mappings_for_article("Art 12");
        assert!(
            art12_mappings.len() >= 3,
            "Art 12 should have at least 3 mappings (audit log, hash chain, merkle, checkpoints)"
        );
    }

    #[test]
    fn test_mappings_for_capability() {
        let registry = EuAiActRegistry::new();
        let mappings =
            registry.mappings_for_capability(TransparencyCapability::TamperEvidentAuditLog);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|m| m.article_id.0 == "Art 12"));
    }

    #[test]
    fn test_generate_assessment_high_risk() {
        let registry = EuAiActRegistry::new();
        let report =
            registry.generate_assessment(AiActRiskClass::HighRisk, "Test Corp", "test-001");
        assert!(!report.assessments.is_empty());
        assert!(report.compliance_percentage > 0.0);
        assert_eq!(report.risk_class, AiActRiskClass::HighRisk);
        assert!(report.applicable_articles > 0);
    }

    #[test]
    fn test_generate_assessment_minimal_risk() {
        let registry = EuAiActRegistry::new();
        let report = registry.generate_assessment(AiActRiskClass::Minimal, "", "");
        // Minimal risk — most articles are not applicable
        let applicable = report.assessments.iter().filter(|a| a.applicable).count();
        assert!(
            applicable < report.total_articles,
            "Minimal risk should have fewer applicable articles"
        );
    }

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(ComplianceStatus::Compliant.to_string(), "Compliant");
        assert_eq!(ComplianceStatus::NotApplicable.to_string(), "N/A");
    }

    fn make_test_entry(
        tool: &str,
        function: &str,
        verdict: vellaveto_types::Verdict,
    ) -> crate::AuditEntry {
        crate::AuditEntry {
            id: "test-1".to_string(),
            action: vellaveto_types::Action::new(
                tool.to_string(),
                function.to_string(),
                serde_json::json!({}),
            ),
            verdict,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: serde_json::json!({}),
            sequence: 1,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
        }
    }

    #[test]
    fn test_classify_entry_all_provide_art12() {
        let entry = make_test_entry("file_system", "read_file", vellaveto_types::Verdict::Allow);
        let record = classify_entry_transparency(&entry);
        assert!(record.relevant_articles.contains(&"Art 12".to_string()));
    }

    #[test]
    fn test_classify_entry_deny_adds_art9() {
        let entry = make_test_entry(
            "shell",
            "execute",
            vellaveto_types::Verdict::Deny {
                reason: "blocked".into(),
            },
        );
        let record = classify_entry_transparency(&entry);
        assert!(record.relevant_articles.contains(&"Art 9".to_string()));
        assert!(record.relevant_articles.contains(&"Art 12".to_string()));
    }

    #[test]
    fn test_classify_entry_approval_adds_art14() {
        let entry = make_test_entry(
            "approval",
            "human_approval",
            vellaveto_types::Verdict::Allow,
        );
        let record = classify_entry_transparency(&entry);
        assert!(record.relevant_articles.contains(&"Art 14".to_string()));
    }
}
