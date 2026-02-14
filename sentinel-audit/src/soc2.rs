//! SOC 2 Trust Services Criteria compliance evidence generation.
//!
//! Registry pattern matching `nist_rmf.rs` and `iso27090.rs`. Maps Sentinel
//! capabilities to SOC 2 Common Criteria (CC1-CC9) and generates evidence
//! reports for Type II audit readiness.

use sentinel_types::TrustServicesCategory;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Criterion Identifier ─────────────────────────────────────────────────────

/// SOC 2 criterion identifier (e.g., "CC1.1", "CC6.3").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CriterionId(pub String);

impl CriterionId {
    pub fn new(category: TrustServicesCategory, number: u8) -> Self {
        let prefix = match category {
            TrustServicesCategory::CC1 => "CC1",
            TrustServicesCategory::CC2 => "CC2",
            TrustServicesCategory::CC3 => "CC3",
            TrustServicesCategory::CC4 => "CC4",
            TrustServicesCategory::CC5 => "CC5",
            TrustServicesCategory::CC6 => "CC6",
            TrustServicesCategory::CC7 => "CC7",
            TrustServicesCategory::CC8 => "CC8",
            TrustServicesCategory::CC9 => "CC9",
        };
        Self(format!("{}.{}", prefix, number))
    }

    /// Parse the category from the criterion ID.
    pub fn category(&self) -> Option<TrustServicesCategory> {
        let prefix = self.0.split('.').next()?;
        match prefix {
            "CC1" => Some(TrustServicesCategory::CC1),
            "CC2" => Some(TrustServicesCategory::CC2),
            "CC3" => Some(TrustServicesCategory::CC3),
            "CC4" => Some(TrustServicesCategory::CC4),
            "CC5" => Some(TrustServicesCategory::CC5),
            "CC6" => Some(TrustServicesCategory::CC6),
            "CC7" => Some(TrustServicesCategory::CC7),
            "CC8" => Some(TrustServicesCategory::CC8),
            "CC9" => Some(TrustServicesCategory::CC9),
            _ => None,
        }
    }
}

impl std::fmt::Display for CriterionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── SOC 2 Capability ─────────────────────────────────────────────────────────

/// Sentinel capabilities relevant to SOC 2 compliance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Soc2Capability {
    // CC1: Control Environment
    PolicyEnforcement,
    FailClosedDesign,

    // CC2: Communication and Information
    AuditLogging,
    AuditLogExport,
    MetricsCollection,

    // CC3: Risk Assessment
    InjectionDetection,
    DlpScanning,
    RugPullDetection,

    // CC4: Monitoring Activities
    BehavioralAnomalyDetection,
    CircuitBreaker,
    HashChainVerification,

    // CC5: Control Activities
    PathRules,
    NetworkRules,
    ParameterConstraints,

    // CC6: Logical and Physical Access Controls
    OAuthAuthentication,
    JwtValidation,
    RateLimiting,
    SessionManagement,

    // CC7: System Operations
    HumanApproval,
    KillSwitch,
    PolicyHotReload,

    // CC8: Change Management
    SignedCheckpoints,
    MerkleInclusionProofs,
    VersionPinning,

    // CC9: Risk Mitigation
    OutputValidation,
    ToolSquattingDetection,
    SchemaPoisoningDetection,
}

impl std::fmt::Display for Soc2Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ── Criterion Definition ─────────────────────────────────────────────────────

/// A SOC 2 Trust Services Criterion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Criterion {
    pub id: CriterionId,
    pub category: TrustServicesCategory,
    pub title: String,
    pub description: String,
}

// ── Readiness Level ──────────────────────────────────────────────────────────

/// Maturity level for SOC 2 criterion coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReadinessLevel {
    NotStarted,
    Initial,
    Developing,
    Defined,
    Managed,
    Optimizing,
}

impl ReadinessLevel {
    pub fn score(&self) -> u8 {
        match self {
            Self::NotStarted => 0,
            Self::Initial => 1,
            Self::Developing => 2,
            Self::Defined => 3,
            Self::Managed => 4,
            Self::Optimizing => 5,
        }
    }
}

impl std::fmt::Display for ReadinessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted => write!(f, "Not Started"),
            Self::Initial => write!(f, "Initial"),
            Self::Developing => write!(f, "Developing"),
            Self::Defined => write!(f, "Defined"),
            Self::Managed => write!(f, "Managed"),
            Self::Optimizing => write!(f, "Optimizing"),
        }
    }
}

// ── Capability Mapping ───────────────────────────────────────────────────────

/// Maps a Sentinel capability to a SOC 2 criterion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionMapping {
    pub criterion_id: CriterionId,
    pub capability: Soc2Capability,
    pub readiness: ReadinessLevel,
    pub evidence: Option<String>,
    pub gaps: Vec<String>,
}

// ── Registry ─────────────────────────────────────────────────────────────────

/// SOC 2 compliance registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soc2Registry {
    pub criteria: HashMap<String, Criterion>,
    pub mappings: Vec<CriterionMapping>,
}

impl Soc2Registry {
    /// Create a new registry with all criteria and capability mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            criteria: HashMap::new(),
            mappings: Vec::new(),
        };
        registry.populate_criteria();
        registry.populate_mappings();
        registry
    }

    fn add_criterion(
        &mut self,
        category: TrustServicesCategory,
        number: u8,
        title: &str,
        description: &str,
    ) {
        let id = CriterionId::new(category, number);
        self.criteria.insert(
            id.0.clone(),
            Criterion {
                id,
                category,
                title: title.to_string(),
                description: description.to_string(),
            },
        );
    }

    fn add_mapping(
        &mut self,
        criterion: &str,
        capability: Soc2Capability,
        readiness: ReadinessLevel,
        evidence: Option<&str>,
        gaps: Vec<&str>,
    ) {
        self.mappings.push(CriterionMapping {
            criterion_id: CriterionId(criterion.to_string()),
            capability,
            readiness,
            evidence: evidence.map(String::from),
            gaps: gaps.into_iter().map(String::from).collect(),
        });
    }

    fn populate_criteria(&mut self) {
        use TrustServicesCategory::*;

        // CC1: Control Environment
        self.add_criterion(CC1, 1, "Commitment to integrity and ethics",
            "The entity demonstrates commitment to integrity and ethical values.");
        self.add_criterion(CC1, 2, "Board oversight",
            "The board of directors demonstrates independence and exercises oversight.");
        self.add_criterion(CC1, 3, "Organizational structure",
            "Management establishes structures, reporting lines, and authority.");

        // CC2: Communication and Information
        self.add_criterion(CC2, 1, "Internal communication",
            "The entity obtains or generates and uses relevant, quality information.");
        self.add_criterion(CC2, 2, "External communication",
            "The entity internally communicates information necessary for internal controls.");
        self.add_criterion(CC2, 3, "Security event communication",
            "The entity communicates with external parties regarding security matters.");

        // CC3: Risk Assessment
        self.add_criterion(CC3, 1, "Risk identification",
            "The entity specifies objectives to identify and assess risks.");
        self.add_criterion(CC3, 2, "Fraud risk assessment",
            "The entity identifies risks to the achievement of objectives across the entity.");
        self.add_criterion(CC3, 3, "Change risk assessment",
            "The entity considers potential for fraud in assessing risks.");

        // CC4: Monitoring Activities
        self.add_criterion(CC4, 1, "Ongoing monitoring",
            "The entity selects and develops monitoring activities.");
        self.add_criterion(CC4, 2, "Deficiency remediation",
            "The entity evaluates and communicates deficiencies in a timely manner.");

        // CC5: Control Activities
        self.add_criterion(CC5, 1, "Control selection and development",
            "The entity selects and develops control activities.");
        self.add_criterion(CC5, 2, "Technology controls",
            "The entity deploys control activities through technology.");
        self.add_criterion(CC5, 3, "Policy deployment",
            "The entity deploys control activities through policies.");

        // CC6: Logical and Physical Access Controls
        self.add_criterion(CC6, 1, "Logical access security",
            "The entity implements logical access security software, infrastructure, and architecture.");
        self.add_criterion(CC6, 2, "User authentication",
            "The entity authenticates users before granting access.");
        self.add_criterion(CC6, 3, "Access authorization",
            "The entity authorizes, modifies, and removes access to data.");

        // CC7: System Operations
        self.add_criterion(CC7, 1, "Infrastructure monitoring",
            "The entity detects and monitors configuration changes.");
        self.add_criterion(CC7, 2, "Anomaly detection",
            "The entity monitors system components for anomalies indicative of malicious acts.");
        self.add_criterion(CC7, 3, "Incident response",
            "The entity evaluates security events to determine incidents.");

        // CC8: Change Management
        self.add_criterion(CC8, 1, "Change authorization",
            "The entity authorizes, designs, develops, configures, and tests changes.");

        // CC9: Risk Mitigation
        self.add_criterion(CC9, 1, "Risk mitigation activities",
            "The entity identifies, selects, and develops risk mitigation activities.");
        self.add_criterion(CC9, 2, "Vendor risk management",
            "The entity assesses and manages risks associated with vendors and business partners.");
    }

    fn populate_mappings(&mut self) {
        use ReadinessLevel::*;

        // CC1: Control Environment
        self.add_mapping("CC1.1", Soc2Capability::PolicyEnforcement, Managed,
            Some("Security policies enforced at runtime on all tool calls"),
            vec![]);
        self.add_mapping("CC1.1", Soc2Capability::FailClosedDesign, Optimizing,
            Some("Fail-closed design: errors, missing policies, and unresolved context produce Deny"),
            vec![]);

        // CC2: Communication and Information
        self.add_mapping("CC2.1", Soc2Capability::AuditLogging, Optimizing,
            Some("Tamper-evident SHA-256 hash chain audit log with every decision recorded"),
            vec![]);
        self.add_mapping("CC2.2", Soc2Capability::AuditLogExport, Managed,
            Some("CEF, JSON Lines, webhook, and syslog export for SIEM integration"),
            vec![]);
        self.add_mapping("CC2.3", Soc2Capability::MetricsCollection, Managed,
            Some("Prometheus metrics endpoint with evaluation histograms"),
            vec![]);

        // CC3: Risk Assessment
        self.add_mapping("CC3.1", Soc2Capability::InjectionDetection, Optimizing,
            Some("Aho-Corasick injection detection with Unicode NFKC normalization"),
            vec![]);
        self.add_mapping("CC3.1", Soc2Capability::DlpScanning, Managed,
            Some("5-layer DLP scanning on requests and responses"),
            vec![]);
        self.add_mapping("CC3.2", Soc2Capability::RugPullDetection, Managed,
            Some("Rug-pull detection: annotation changes, schema mutations, persistent flagging"),
            vec![]);

        // CC4: Monitoring Activities
        self.add_mapping("CC4.1", Soc2Capability::BehavioralAnomalyDetection, Managed,
            Some("EMA-based behavioral anomaly detection for tool call frequency"),
            vec![]);
        self.add_mapping("CC4.1", Soc2Capability::CircuitBreaker, Managed,
            Some("Circuit breaker with half-open recovery for cascading failure protection"),
            vec![]);
        self.add_mapping("CC4.2", Soc2Capability::HashChainVerification, Optimizing,
            Some("Cryptographic hash chain verification with gap and tamper detection"),
            vec![]);

        // CC5: Control Activities
        self.add_mapping("CC5.1", Soc2Capability::PathRules, Optimizing,
            Some("Path rules with glob matching and traversal-safe normalization"),
            vec![]);
        self.add_mapping("CC5.1", Soc2Capability::NetworkRules, Optimizing,
            Some("Network rules with domain validation and DNS rebinding protection"),
            vec![]);
        self.add_mapping("CC5.2", Soc2Capability::ParameterConstraints, Managed,
            Some("Parameter constraint validation on tool call arguments"),
            vec![]);
        self.add_mapping("CC5.3", Soc2Capability::PolicyEnforcement, Optimizing,
            Some("Policy engine with glob, regex, domain matching, parameter constraints"),
            vec![]);

        // CC6: Logical and Physical Access Controls
        self.add_mapping("CC6.1", Soc2Capability::OAuthAuthentication, Managed,
            Some("OAuth 2.1 with JWKS support and scope enforcement"),
            vec![]);
        self.add_mapping("CC6.2", Soc2Capability::JwtValidation, Managed,
            Some("JWT validation with JWKS and agent identity attestation"),
            vec![]);
        self.add_mapping("CC6.2", Soc2Capability::SessionManagement, Managed,
            Some("Session management with CSRF protection"),
            vec![]);
        self.add_mapping("CC6.3", Soc2Capability::RateLimiting, Managed,
            Some("Per-category rate limiting on all endpoints"),
            vec![]);

        // CC7: System Operations
        self.add_mapping("CC7.1", Soc2Capability::PolicyHotReload, Managed,
            Some("Hot policy reload via filesystem watcher and API endpoint"),
            vec![]);
        self.add_mapping("CC7.2", Soc2Capability::BehavioralAnomalyDetection, Managed,
            Some("Behavioral anomaly detection identifies suspicious tool call patterns"),
            vec![]);
        self.add_mapping("CC7.3", Soc2Capability::HumanApproval, Managed,
            Some("Human-in-the-loop approval workflow for incident response"),
            vec![]);
        self.add_mapping("CC7.3", Soc2Capability::KillSwitch, Managed,
            Some("Circuit breaker kill switch for immediate system shutdown"),
            vec![]);

        // CC8: Change Management
        self.add_mapping("CC8.1", Soc2Capability::SignedCheckpoints, Managed,
            Some("Ed25519 signed checkpoints for audit trail integrity"),
            vec![]);
        self.add_mapping("CC8.1", Soc2Capability::MerkleInclusionProofs, Managed,
            Some("RFC 6962 Merkle tree inclusion proofs for individual entry verification"),
            vec![]);
        self.add_mapping("CC8.1", Soc2Capability::VersionPinning, Managed,
            Some("ETDI version pinning for tool definition change tracking"),
            vec![]);

        // CC9: Risk Mitigation
        self.add_mapping("CC9.1", Soc2Capability::OutputValidation, Managed,
            Some("Structured output schema validation registry"),
            vec![]);
        self.add_mapping("CC9.1", Soc2Capability::ToolSquattingDetection, Managed,
            Some("Levenshtein + homoglyph tool squatting detection"),
            vec![]);
        self.add_mapping("CC9.2", Soc2Capability::SchemaPoisoningDetection, Managed,
            Some("Schema poisoning detection for third-party tool mutations"),
            vec![]);
    }

    // ── Query Methods ────────────────────────────────────────────────────────

    /// Get mappings for a specific criterion.
    pub fn mappings_for_criterion(&self, criterion_id: &str) -> Vec<&CriterionMapping> {
        self.mappings
            .iter()
            .filter(|m| m.criterion_id.0 == criterion_id)
            .collect()
    }

    /// Get mappings for a specific capability.
    pub fn mappings_for_capability(&self, capability: Soc2Capability) -> Vec<&CriterionMapping> {
        self.mappings
            .iter()
            .filter(|m| m.capability == capability)
            .collect()
    }

    /// Get a criterion definition.
    pub fn get_criterion(&self, criterion_id: &str) -> Option<&Criterion> {
        self.criteria.get(criterion_id)
    }

    /// Calculate coverage by category.
    pub fn coverage_by_category(&self) -> HashMap<TrustServicesCategory, CategoryCoverage> {
        use TrustServicesCategory::*;
        let categories = [CC1, CC2, CC3, CC4, CC5, CC6, CC7, CC8, CC9];

        categories
            .iter()
            .map(|cat| {
                let criteria_in_cat: Vec<&Criterion> = self
                    .criteria
                    .values()
                    .filter(|c| c.category == *cat)
                    .collect();

                let total = criteria_in_cat.len();
                let mut covered = 0usize;
                let mut total_score = 0u32;
                let mut max_score = 0u32;

                for criterion in &criteria_in_cat {
                    let mappings = self.mappings_for_criterion(&criterion.id.0);
                    if !mappings.is_empty() {
                        covered += 1;
                        // Use max readiness across mappings for this criterion
                        let best = mappings
                            .iter()
                            .map(|m| m.readiness.score() as u32)
                            .max()
                            .unwrap_or(0);
                        total_score += best;
                    }
                    max_score += ReadinessLevel::Optimizing.score() as u32;
                }

                let coverage_percent = if total > 0 {
                    (covered as f32 / total as f32) * 100.0
                } else {
                    0.0
                };

                let readiness_percent = if max_score > 0 {
                    (total_score as f32 / max_score as f32) * 100.0
                } else {
                    0.0
                };

                (
                    *cat,
                    CategoryCoverage {
                        category: *cat,
                        total_criteria: total,
                        covered_criteria: covered,
                        coverage_percent,
                        readiness_score: total_score,
                        max_score,
                        readiness_percent,
                    },
                )
            })
            .collect()
    }

    // ── Report Generation ────────────────────────────────────────────────────

    /// Generate a SOC 2 evidence report.
    ///
    /// Parameters are passed as primitives so this module does not depend on
    /// sentinel-config (preserving the crate dependency graph).
    pub fn generate_evidence_report(
        &self,
        organization_name: &str,
        period_start: &str,
        period_end: &str,
        tracked_categories: &[TrustServicesCategory],
    ) -> Soc2EvidenceReport {
        let coverage = self.coverage_by_category();

        // Filter to tracked categories (or all if empty)
        let tracked: Vec<TrustServicesCategory> = if tracked_categories.is_empty() {
            use TrustServicesCategory::*;
            vec![CC1, CC2, CC3, CC4, CC5, CC6, CC7, CC8, CC9]
        } else {
            tracked_categories.to_vec()
        };

        let filtered_coverage: HashMap<TrustServicesCategory, CategoryCoverage> = coverage
            .into_iter()
            .filter(|(k, _)| tracked.contains(k))
            .collect();

        // Overall readiness
        let total_score: u32 = filtered_coverage.values().map(|c| c.readiness_score).sum();
        let max_score: u32 = filtered_coverage.values().map(|c| c.max_score).sum();
        let overall_readiness = if max_score > 0 {
            (total_score as f32 / max_score as f32) * 100.0
        } else {
            0.0
        };

        // Collect all gaps
        let gaps: Vec<String> = self
            .mappings
            .iter()
            .flat_map(|m| m.gaps.clone())
            .collect();

        // Criterion-level evidence
        let mut criterion_evidence = Vec::new();
        for (criterion_id, criterion) in &self.criteria {
            if let Some(cat) = criterion.id.category() {
                if !tracked.contains(&cat) {
                    continue;
                }
            }
            let mappings = self.mappings_for_criterion(criterion_id);
            let capabilities: Vec<Soc2Capability> = mappings.iter().map(|m| m.capability).collect();
            let evidence: Vec<String> = mappings
                .iter()
                .filter_map(|m| m.evidence.clone())
                .collect();
            let best_readiness = mappings
                .iter()
                .map(|m| m.readiness)
                .max()
                .unwrap_or(ReadinessLevel::NotStarted);

            criterion_evidence.push(CriterionEvidence {
                criterion_id: criterion_id.clone(),
                title: criterion.title.clone(),
                readiness: best_readiness,
                capabilities,
                evidence,
            });
        }

        criterion_evidence.sort_by(|a, b| a.criterion_id.cmp(&b.criterion_id));

        Soc2EvidenceReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            organization_name: organization_name.to_string(),
            period_start: period_start.to_string(),
            period_end: period_end.to_string(),
            overall_readiness,
            total_score,
            max_score,
            category_coverage: filtered_coverage,
            criterion_evidence,
            total_gaps: gaps.len(),
            gaps,
        }
    }
}

impl Default for Soc2Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Report Types ─────────────────────────────────────────────────────────────

/// Coverage statistics for a SOC 2 category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryCoverage {
    pub category: TrustServicesCategory,
    pub total_criteria: usize,
    pub covered_criteria: usize,
    pub coverage_percent: f32,
    pub readiness_score: u32,
    pub max_score: u32,
    pub readiness_percent: f32,
}

/// Evidence for a single SOC 2 criterion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionEvidence {
    pub criterion_id: String,
    pub title: String,
    pub readiness: ReadinessLevel,
    pub capabilities: Vec<Soc2Capability>,
    pub evidence: Vec<String>,
}

/// Complete SOC 2 evidence report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soc2EvidenceReport {
    pub generated_at: String,
    pub organization_name: String,
    pub period_start: String,
    pub period_end: String,
    pub overall_readiness: f32,
    pub total_score: u32,
    pub max_score: u32,
    pub category_coverage: HashMap<TrustServicesCategory, CategoryCoverage>,
    pub criterion_evidence: Vec<CriterionEvidence>,
    pub total_gaps: usize,
    pub gaps: Vec<String>,
}

// ── Entry Classification ─────────────────────────────────────────────────────

/// SOC 2 evidence record for an audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soc2EvidenceRecord {
    /// Which criteria this entry provides evidence for.
    pub relevant_criteria: Vec<String>,
    /// Classification reason.
    pub reason: String,
}

/// Classify an audit entry for SOC 2 evidence.
///
/// Read-time classification matching the nist_rmf.rs/iso27090.rs pattern.
pub fn classify_entry(entry: &crate::AuditEntry) -> Soc2EvidenceRecord {
    let mut criteria = Vec::new();
    let mut reasons = Vec::new();

    // All audit entries provide CC2.1 evidence (communication/information)
    criteria.push("CC2.1".to_string());
    reasons.push("audit log entry");

    // Deny verdicts provide CC5.1 (control activities) and CC3.1 (risk assessment)
    if matches!(entry.verdict, sentinel_types::Verdict::Deny { .. }) {
        criteria.push("CC3.1".to_string());
        criteria.push("CC5.1".to_string());
        reasons.push("security control enforcement");
    }

    // Approval entries provide CC7.3 (incident response)
    if entry.action.tool.contains("approval") || entry.action.function.contains("approval") {
        criteria.push("CC7.3".to_string());
        reasons.push("human oversight evidence");
    }

    // Auth-related entries provide CC6.2 evidence
    if entry.action.function.contains("auth") || entry.action.function.contains("login") {
        criteria.push("CC6.2".to_string());
        reasons.push("authentication evidence");
    }

    // DLP or injection findings provide CC3.1
    if entry.action.function.contains("dlp") || entry.action.function.contains("injection") {
        criteria.push("CC3.1".to_string());
        criteria.push("CC9.1".to_string());
        reasons.push("threat detection evidence");
    }

    // Deduplicate
    criteria.sort();
    criteria.dedup();

    Soc2EvidenceRecord {
        relevant_criteria: criteria,
        reason: reasons.join("; "),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_registry_creation() {
        let registry = Soc2Registry::new();
        assert!(!registry.criteria.is_empty());
        assert!(!registry.mappings.is_empty());
    }

    #[test]
    fn test_criterion_id_parsing() {
        let id = CriterionId::new(TrustServicesCategory::CC6, 2);
        assert_eq!(id.0, "CC6.2");
        assert_eq!(id.category(), Some(TrustServicesCategory::CC6));
    }

    #[test]
    fn test_criterion_populated() {
        let registry = Soc2Registry::new();
        let cc61 = registry.get_criterion("CC6.1");
        assert!(cc61.is_some());
        assert_eq!(cc61.unwrap().title, "Logical access security");
    }

    #[test]
    fn test_mappings_for_criterion() {
        let registry = Soc2Registry::new();
        let cc61_mappings = registry.mappings_for_criterion("CC6.1");
        assert!(!cc61_mappings.is_empty());
    }

    #[test]
    fn test_mappings_for_capability() {
        let registry = Soc2Registry::new();
        let mappings = registry.mappings_for_capability(Soc2Capability::AuditLogging);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|m| m.criterion_id.0.starts_with("CC2")));
    }

    #[test]
    fn test_coverage_by_category_all_covered() {
        let registry = Soc2Registry::new();
        let coverage = registry.coverage_by_category();
        // All 9 categories should have some coverage
        assert_eq!(coverage.len(), 9);
        for (_, cat_cov) in &coverage {
            assert!(
                cat_cov.covered_criteria > 0,
                "Category {} should have at least one covered criterion",
                cat_cov.category
            );
        }
    }

    #[test]
    fn test_coverage_readiness_percent() {
        let registry = Soc2Registry::new();
        let coverage = registry.coverage_by_category();
        for (_, cat_cov) in &coverage {
            assert!(cat_cov.readiness_percent >= 0.0);
            assert!(cat_cov.readiness_percent <= 100.0);
        }
    }

    #[test]
    fn test_generate_evidence_report_all_categories() {
        let registry = Soc2Registry::new();
        let report = registry.generate_evidence_report(
            "Test Corp", "2026-01-01", "2026-12-31", &[],
        );
        assert!(!report.criterion_evidence.is_empty());
        assert!(report.overall_readiness > 0.0);
        assert_eq!(report.organization_name, "Test Corp");
    }

    #[test]
    fn test_generate_evidence_report_filtered_categories() {
        let registry = Soc2Registry::new();
        let report = registry.generate_evidence_report(
            "Test", "2026-01-01", "2026-12-31",
            &[TrustServicesCategory::CC6],
        );
        // Should only include CC6 category coverage
        assert_eq!(report.category_coverage.len(), 1);
        assert!(report.category_coverage.contains_key(&TrustServicesCategory::CC6));
    }

    #[test]
    fn test_readiness_level_ordering() {
        assert!(ReadinessLevel::NotStarted < ReadinessLevel::Initial);
        assert!(ReadinessLevel::Initial < ReadinessLevel::Developing);
        assert!(ReadinessLevel::Managed < ReadinessLevel::Optimizing);
    }

    #[test]
    fn test_readiness_level_score() {
        assert_eq!(ReadinessLevel::NotStarted.score(), 0);
        assert_eq!(ReadinessLevel::Optimizing.score(), 5);
    }

    fn make_test_entry(tool: &str, function: &str, verdict: sentinel_types::Verdict) -> crate::AuditEntry {
        crate::AuditEntry {
            id: "test-1".to_string(),
            action: sentinel_types::Action::new(tool.to_string(), function.to_string(), serde_json::json!({})),
            verdict,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: serde_json::json!({}),
            sequence: 1,
            entry_hash: None,
            prev_hash: None,
        }
    }

    #[test]
    fn test_classify_entry_all_provide_cc2() {
        let entry = make_test_entry("file_system", "read_file", sentinel_types::Verdict::Allow);
        let record = classify_entry(&entry);
        assert!(record.relevant_criteria.contains(&"CC2.1".to_string()));
    }

    #[test]
    fn test_classify_entry_deny_adds_cc5_cc3() {
        let entry = make_test_entry("shell", "execute", sentinel_types::Verdict::Deny { reason: "blocked".into() });
        let record = classify_entry(&entry);
        assert!(record.relevant_criteria.contains(&"CC3.1".to_string()));
        assert!(record.relevant_criteria.contains(&"CC5.1".to_string()));
    }

    #[test]
    fn test_classify_entry_approval_adds_cc7() {
        let entry = make_test_entry("approval", "human_approval", sentinel_types::Verdict::Allow);
        let record = classify_entry(&entry);
        assert!(record.relevant_criteria.contains(&"CC7.3".to_string()));
    }
}
