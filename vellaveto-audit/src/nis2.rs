//! NIS2 (Network and Information Security Directive 2) compliance evidence generation.
//!
//! Registry mapping Vellaveto capabilities to NIS2 Art 21 risk management
//! measures and Art 23 incident notification requirements.
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::nis2::Nis2Registry;
//!
//! let registry = Nis2Registry::new();
//! let report = registry.generate_report("Acme Corp", "acme-vellaveto-001");
//! println!("NIS2 coverage: {:.1}%", report.compliance_percentage);
//! ```

use serde::{Deserialize, Serialize};

// ── Article Identifier ───────────────────────────────────────────────────────

/// NIS2 article identifier (e.g., "Art 21.2.a", "Art 23").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nis2ArticleId(pub String);

impl Nis2ArticleId {
    pub fn new(article: &str) -> Self {
        Self(article.to_string())
    }
}

impl std::fmt::Display for Nis2ArticleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Vellaveto Capability ─────────────────────────────────────────────────────

/// Vellaveto capabilities relevant to NIS2 compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Nis2Capability {
    /// Art 21.2.a: Risk analysis — policy engine, threat detection.
    RiskAnalysis,
    /// Art 21.2.b: Incident handling — audit logging, circuit breaker.
    IncidentHandling,
    /// Art 21.2.c: Business continuity — circuit breaker, fallback chain.
    BusinessContinuity,
    /// Art 21.2.d + Art 22: Supply chain security — tool registry, ETDI, trust scoring.
    SupplyChainSecurity,
    /// Art 21.2.e: Network security — domain/IP filtering, SSRF protection.
    NetworkSecurity,
    /// Art 21.2.f: Vulnerability handling — rug-pull detection, tool squatting.
    VulnerabilityHandling,
    /// Art 21.2.g: Cyber hygiene — injection detection, DLP.
    CyberHygiene,
    /// Art 21.2.h: Cryptography — hash chain, signed checkpoints, ZK proofs.
    Cryptography,
    /// Art 21.2.i: Access control — ABAC, capability tokens.
    AccessControl,
    /// Art 21.2.j: Asset management — tool discovery, shadow AI detection.
    AssetManagement,
    /// Art 23: Incident notification — audit export, webhook events.
    IncidentNotification,
    /// Security audit and compliance reporting.
    SecurityAudit,
}

impl std::fmt::Display for Nis2Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ── Compliance Status ────────────────────────────────────────────────────────

/// Implementation status for a NIS2 article.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nis2ComplianceStatus {
    /// Fully implemented by Vellaveto capabilities.
    Compliant,
    /// Partially implemented — some evidence available.
    Partial,
    /// Not yet implemented.
    NotImplemented,
}

impl std::fmt::Display for Nis2ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compliant => write!(f, "Compliant"),
            Self::Partial => write!(f, "Partial"),
            Self::NotImplemented => write!(f, "Not Implemented"),
        }
    }
}

// ── Assessment ───────────────────────────────────────────────────────────────

/// Assessment of a single NIS2 article.
/// SECURITY (FIND-R215-002): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nis2Assessment {
    /// Article identifier.
    pub article_id: Nis2ArticleId,
    /// Short title.
    pub title: String,
    /// Description of the article requirement.
    pub description: String,
    /// Implementation status.
    pub status: Nis2ComplianceStatus,
    /// Vellaveto capabilities providing evidence.
    pub capabilities: Vec<Nis2Capability>,
    /// Evidence description.
    pub evidence: String,
}

// ── Report ───────────────────────────────────────────────────────────────────

/// NIS2 compliance evidence report.
/// SECURITY (FIND-R215-002): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nis2Report {
    /// ISO 8601 timestamp of generation.
    pub generated_at: String,
    /// Organization name.
    pub organization_name: String,
    /// System identifier.
    pub system_id: String,
    /// Individual article assessments.
    pub assessments: Vec<Nis2Assessment>,
    /// Overall compliance percentage (0.0–100.0).
    pub compliance_percentage: f32,
    /// Total number of assessed articles.
    pub total_articles: usize,
    /// Number of compliant articles.
    pub compliant_articles: usize,
    /// Number of partially compliant articles.
    pub partial_articles: usize,
}

// ── Registry ─────────────────────────────────────────────────────────────────

/// NIS2 compliance registry mapping Vellaveto capabilities to NIS2 articles.
pub struct Nis2Registry {
    assessments: Vec<Nis2Assessment>,
}

impl Nis2Registry {
    /// Create a new registry with all article assessments populated.
    pub fn new() -> Self {
        let mut registry = Self {
            assessments: Vec::new(),
        };
        registry.populate();
        registry
    }

    /// Generate a NIS2 compliance evidence report.
    pub fn generate_report(&self, organization_name: &str, system_id: &str) -> Nis2Report {
        let total = self.assessments.len();
        let compliant = self
            .assessments
            .iter()
            .filter(|a| a.status == Nis2ComplianceStatus::Compliant)
            .count();
        let partial = self
            .assessments
            .iter()
            .filter(|a| a.status == Nis2ComplianceStatus::Partial)
            .count();

        let pct = if total > 0 {
            ((compliant as f32 + partial as f32 * 0.5) / total as f32) * 100.0
        } else {
            100.0
        };

        Nis2Report {
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
        status: Nis2ComplianceStatus,
        capabilities: Vec<Nis2Capability>,
        evidence: &str,
    ) {
        self.assessments.push(Nis2Assessment {
            article_id: Nis2ArticleId::new(article),
            title: title.to_string(),
            description: description.to_string(),
            status,
            capabilities,
            evidence: evidence.to_string(),
        });
    }

    fn populate(&mut self) {
        use Nis2Capability::*;
        use Nis2ComplianceStatus::*;

        // ── Art 21: Cybersecurity risk-management measures ──────────────

        self.add(
            "Art 21.1",
            "Risk management measures — general obligation",
            "Essential and important entities shall take appropriate technical, operational, and organisational measures to manage cybersecurity risks.",
            Compliant,
            vec![RiskAnalysis, SecurityAudit],
            "Comprehensive policy engine with fail-closed defaults; configurable security policies for path/domain/action governance; compliance reporting across 8+ frameworks",
        );

        self.add(
            "Art 21.2.a",
            "Policies on risk analysis and information system security",
            "Risk analysis policies and information system security policies.",
            Compliant,
            vec![RiskAnalysis],
            "Policy engine evaluates every tool call with <5ms P99 latency; threat detection across injection, DLP, rug-pull, squatting; behavioral anomaly analysis",
        );

        self.add(
            "Art 21.2.b",
            "Incident handling",
            "Incident handling procedures and capabilities.",
            Compliant,
            vec![IncidentHandling],
            "Tamper-evident audit logging with SHA-256 hash chain; circuit breaker for cascading failure prevention; real-time webhook notifications for security events",
        );

        self.add(
            "Art 21.2.c",
            "Business continuity and crisis management",
            "Business continuity including backup management, disaster recovery, and crisis management.",
            Compliant,
            vec![BusinessContinuity],
            "Circuit breaker pattern (Closed/Open/HalfOpen with exponential backoff); cross-transport smart fallback chain (gRPC→WS→HTTP→stdio); immutable audit archive",
        );

        self.add(
            "Art 21.2.d",
            "Supply chain security",
            "Supply chain security including security-related aspects of relationships with direct suppliers.",
            Compliant,
            vec![SupplyChainSecurity],
            "Tool registry with trust scoring; ETDI cryptographic verification of tool definitions; rug-pull detection; tool squatting prevention (Levenshtein + homoglyph)",
        );

        self.add(
            "Art 21.2.e",
            "Security in network and information systems acquisition",
            "Security in acquisition, development, and maintenance of network and information systems, including vulnerability handling.",
            Compliant,
            vec![NetworkSecurity],
            "Domain/IP filtering with SSRF protection (private IP rejection); DNS rebinding defense; path traversal protection; URL scheme validation",
        );

        self.add(
            "Art 21.2.f",
            "Vulnerability handling and disclosure",
            "Policies and procedures for handling and disclosing vulnerabilities.",
            Compliant,
            vec![VulnerabilityHandling],
            "Rug-pull detection monitors tool definition changes; tool squatting detection (Levenshtein distance + homoglyph); red team mutation engine for vulnerability testing",
        );

        self.add(
            "Art 21.2.g",
            "Cyber hygiene practices and cybersecurity training",
            "Basic cyber hygiene practices and cybersecurity training.",
            Compliant,
            vec![CyberHygiene],
            "Injection detection (Aho-Corasick + NFKC normalization); DLP 5-layer decode with PII pattern matching; multimodal injection scanning (PNG/JPEG/PDF/audio/video)",
        );

        self.add(
            "Art 21.2.h",
            "Policies on the use of cryptography and encryption",
            "Policies and procedures regarding the use of cryptography and, where appropriate, encryption.",
            Compliant,
            vec![Cryptography],
            "SHA-256 hash chain for audit integrity; Ed25519 signed checkpoints; Merkle tree inclusion proofs; Pedersen commitments for ZK audit; FIPS 140-3 mode available",
        );

        self.add(
            "Art 21.2.i",
            "Human resources security and access control",
            "Human resources security, access control policies, and asset management.",
            Compliant,
            vec![AccessControl],
            "ABAC with forbid-overrides; capability-based delegation tokens with scope and expiry; rate limiting; NHI lifecycle management; SOC 2 access review reports",
        );

        self.add(
            "Art 21.2.j",
            "Multi-factor authentication and secure communications",
            "Use of multi-factor authentication or continuous authentication, secured voice/video/text, and secured emergency communications.",
            Partial,
            vec![AccessControl],
            "OAuth 2.1/JWT/JWKS authentication; DPoP proof-of-possession; session guards with anomaly detection; continuous authorization through ABAC",
        );

        // ── Art 22: Supply chain coordinated risk assessments ──────────

        self.add(
            "Art 22",
            "Coordinated security risk assessments of critical supply chains",
            "Coordinated risk assessments of critical supply chains at Union level.",
            Compliant,
            vec![SupplyChainSecurity, SecurityAudit],
            "Tool registry with trust scoring provides supply chain visibility; shadow AI discovery detects unregistered providers; gap analysis consolidates risk across frameworks",
        );

        // ── Art 23: Reporting obligations ───────────────────────────────

        self.add(
            "Art 23.1",
            "Significant incident notification — early warning",
            "Without undue delay and within 24 hours: early warning.",
            Partial,
            vec![IncidentNotification],
            "Real-time webhook notifications for security events; audit export to SIEM (CEF/JSONL/syslog) enables automated alerting within 24h window",
        );

        self.add(
            "Art 23.2",
            "Significant incident notification — incident notification",
            "Without undue delay and within 72 hours: incident notification.",
            Partial,
            vec![IncidentNotification],
            "Structured audit entries with consistent JSON schema provide evidence basis; centralized audit store with PostgreSQL supports report generation within 72h",
        );

        self.add(
            "Art 23.3",
            "Significant incident notification — intermediate report",
            "Upon request of competent authority: intermediate report on status updates.",
            Partial,
            vec![IncidentNotification, SecurityAudit],
            "Audit query API with time/tool/verdict/agent filters; compliance reporting generates on-demand evidence bundles for authority requests",
        );

        self.add(
            "Art 23.4",
            "Significant incident notification — final report",
            "Within one month: final report with root cause analysis.",
            Partial,
            vec![IncidentNotification, SecurityAudit],
            "Tamper-evident audit trail provides complete event history; hash chain verification ensures evidence integrity; gap analysis identifies root cause areas",
        );
    }
}

impl Default for Nis2Registry {
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
        let registry = Nis2Registry::new();
        assert!(!registry.assessments.is_empty());
    }

    #[test]
    fn test_article_id_display() {
        let id = Nis2ArticleId::new("Art 21.2.a");
        assert_eq!(id.to_string(), "Art 21.2.a");
    }

    #[test]
    fn test_generate_report() {
        let registry = Nis2Registry::new();
        let report = registry.generate_report("Test Corp", "corp-001");
        assert_eq!(report.organization_name, "Test Corp");
        assert_eq!(report.system_id, "corp-001");
        assert!(!report.assessments.is_empty());
        assert!(report.compliance_percentage > 0.0);
        assert!(report.compliance_percentage <= 100.0);
        assert!(report.compliant_articles > 0);
    }

    #[test]
    fn test_all_art21_measures_present() {
        let registry = Nis2Registry::new();
        let report = registry.generate_report("Test", "test");
        let ids: Vec<&str> = report
            .assessments
            .iter()
            .map(|a| a.article_id.0.as_str())
            .collect();
        // Art 21.2.a through 21.2.j = 10 measures + Art 21.1 + Art 22 + Art 23.x
        assert!(ids.contains(&"Art 21.2.a"), "Missing Art 21.2.a");
        assert!(ids.contains(&"Art 21.2.j"), "Missing Art 21.2.j");
        assert!(ids.contains(&"Art 22"), "Missing Art 22");
        assert!(ids.contains(&"Art 23.1"), "Missing Art 23.1");
    }

    #[test]
    fn test_coverage_above_50_percent() {
        let registry = Nis2Registry::new();
        let report = registry.generate_report("Test", "test");
        assert!(
            report.compliance_percentage >= 50.0,
            "NIS2 coverage {:.1}% below 50%",
            report.compliance_percentage,
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let registry = Nis2Registry::new();
        let report = registry.generate_report("Test", "test");
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: Nis2Report =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.total_articles, report.total_articles);
    }

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(Nis2ComplianceStatus::Compliant.to_string(), "Compliant");
        assert_eq!(Nis2ComplianceStatus::Partial.to_string(), "Partial");
        assert_eq!(
            Nis2ComplianceStatus::NotImplemented.to_string(),
            "Not Implemented"
        );
    }

    #[test]
    fn test_default_trait() {
        let registry = Nis2Registry::default();
        let report = registry.generate_report("Test", "test");
        assert!(report.total_articles > 0);
    }
}
