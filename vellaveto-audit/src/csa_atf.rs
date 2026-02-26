//! Cloud Security Alliance (CSA) Agentic Trust Framework Compliance Registry.
//!
//! Maps Vellaveto detection capabilities to the CSA Agentic Trust Framework
//! (Feb 2026 edition), which defines progressive autonomy levels with Zero
//! Trust governance for AI agents across 6 trust domains and 24 controls.
//!
//! The framework defines four progressive autonomy levels:
//! - Level 1: Human-in-loop (all actions approved)
//! - Level 2: Human-on-loop (monitoring, override capability)
//! - Level 3: Human-over-loop (policy-governed, periodic review)
//! - Level 4: Fully autonomous (continuous monitoring, automated response)
//!
//! Trust domains:
//! 1. Identity & Authentication (CSA-IA)
//! 2. Authorization & Access Control (CSA-AA)
//! 3. Behavioral Monitoring (CSA-BM)
//! 4. Data Protection (CSA-DP)
//! 5. Audit & Accountability (CSA-AU)
//! 6. Incident Response (CSA-IR)
//!
//! # Usage
//!
//! ```
//! use vellaveto_audit::csa_atf::CsaAtfRegistry;
//!
//! let registry = CsaAtfRegistry::new();
//! let report = registry.generate_coverage_report();
//! assert!(report.coverage_percent >= 90.0);
//! ```
//!
//! Reference: <https://cloudsecurityalliance.org/agentic-trust-framework>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::atlas::VellavetoDetection;

// ── Validation Constants ────────────────────────────────────────────────────

/// Maximum number of CSA ATF controls (current spec: 24).
const MAX_CSA_CONTROLS: usize = 100;

/// Maximum number of CSA ATF trust domains (current spec: 6).
const MAX_CSA_DOMAINS: usize = 20;

/// Maximum mitigations per control.
const MAX_MITIGATIONS_PER_CONTROL: usize = 50;

/// Maximum number of autonomy levels in coverage breakdown.
const MAX_AUTONOMY_LEVELS: usize = 10;

// ── Trust Domain Enum ───────────────────────────────────────────────────────

/// CSA Agentic Trust Framework trust domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CsaAtfDomain {
    /// Identity & Authentication — Agent identity verification, credential
    /// management, mutual authentication.
    IdentityAuthentication,
    /// Authorization & Access Control — Least privilege, dynamic policy,
    /// capability-based access.
    AuthorizationAccessControl,
    /// Behavioral Monitoring — Anomaly detection, drift detection, compliance
    /// monitoring.
    BehavioralMonitoring,
    /// Data Protection — Data classification, DLP, encryption, data flow
    /// controls.
    DataProtection,
    /// Audit & Accountability — Audit trails, tamper evidence, compliance
    /// reporting.
    AuditAccountability,
    /// Incident Response — Circuit breakers, automated containment, forensic
    /// capture.
    IncidentResponse,
}

impl std::fmt::Display for CsaAtfDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityAuthentication => write!(f, "Identity & Authentication"),
            Self::AuthorizationAccessControl => write!(f, "Authorization & Access Control"),
            Self::BehavioralMonitoring => write!(f, "Behavioral Monitoring"),
            Self::DataProtection => write!(f, "Data Protection"),
            Self::AuditAccountability => write!(f, "Audit & Accountability"),
            Self::IncidentResponse => write!(f, "Incident Response"),
        }
    }
}

// ── Autonomy Level ──────────────────────────────────────────────────────────

/// Progressive autonomy levels defined by the CSA Agentic Trust Framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AutonomyLevel {
    /// Level 1: Human-in-loop — all actions require explicit human approval.
    HumanInLoop,
    /// Level 2: Human-on-loop — monitoring with override capability.
    HumanOnLoop,
    /// Level 3: Human-over-loop — policy-governed with periodic review.
    HumanOverLoop,
    /// Level 4: Fully autonomous — continuous monitoring, automated response.
    FullyAutonomous,
}

impl std::fmt::Display for AutonomyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HumanInLoop => write!(f, "Level 1: Human-in-Loop"),
            Self::HumanOnLoop => write!(f, "Level 2: Human-on-Loop"),
            Self::HumanOverLoop => write!(f, "Level 3: Human-over-Loop"),
            Self::FullyAutonomous => write!(f, "Level 4: Fully Autonomous"),
        }
    }
}

// ── Control Struct ──────────────────────────────────────────────────────────

/// A single CSA ATF control within a trust domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsaAtfControl {
    /// Control identifier (e.g., "CSA-IA-01").
    pub id: String,
    /// Parent trust domain.
    pub category: CsaAtfDomain,
    /// Human-readable control name.
    pub name: String,
    /// Description of the control requirement.
    pub description: String,
    /// Vellaveto capabilities that implement this control.
    pub mitigations: Vec<String>,
}

// ── Coverage Report Structs ─────────────────────────────────────────────────

/// Per-domain coverage breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainCoverage {
    /// Trust domain.
    pub domain: CsaAtfDomain,
    /// Domain display name.
    pub domain_name: String,
    /// Total controls in this domain.
    pub total_controls: usize,
    /// Controls with at least one Vellaveto mitigation.
    pub covered_controls: usize,
    /// Coverage percentage for this domain.
    pub coverage_percent: f32,
}

/// Per-autonomy-level coverage breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyLevelCoverage {
    /// Autonomy level.
    pub level: AutonomyLevel,
    /// Level display name.
    pub level_name: String,
    /// Number of controls required at this level.
    pub required_controls: usize,
    /// Number of required controls that are covered.
    pub covered_controls: usize,
    /// Coverage percentage for this level.
    pub coverage_percent: f32,
}

/// A single row in the control coverage matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlMatrixRow {
    /// Control ID.
    pub id: String,
    /// Parent trust domain.
    pub domain: CsaAtfDomain,
    /// Control name.
    pub name: String,
    /// Whether this control is covered.
    pub covered: bool,
    /// Vellaveto mitigations (empty if uncovered).
    pub mitigations: Vec<String>,
}

/// CSA Agentic Trust Framework coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsaAtfCoverageReport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Total trust domains (6).
    pub total_domains: usize,
    /// Domains with full coverage.
    pub covered_domains: usize,
    /// Total controls across all domains.
    pub total_controls: usize,
    /// Controls with at least one Vellaveto mitigation.
    pub covered_controls: usize,
    /// Overall coverage percentage.
    pub coverage_percent: f32,
    /// Per-domain breakdown.
    pub domain_coverage: Vec<DomainCoverage>,
    /// Per-autonomy-level breakdown.
    pub autonomy_coverage: Vec<AutonomyLevelCoverage>,
    /// Coverage matrix: one row per control.
    pub control_matrix: Vec<ControlMatrixRow>,
}

impl CsaAtfCoverageReport {
    /// Validate bounds on deserialized data.
    pub fn validate(&self) -> Result<(), String> {
        if !self.coverage_percent.is_finite()
            || self.coverage_percent < 0.0
            || self.coverage_percent > 100.0
        {
            return Err(format!(
                "coverage_percent out of range: {}",
                self.coverage_percent
            ));
        }
        if self.domain_coverage.len() > MAX_CSA_DOMAINS {
            return Err(format!(
                "domain_coverage has {} entries, max is {}",
                self.domain_coverage.len(),
                MAX_CSA_DOMAINS,
            ));
        }
        if self.control_matrix.len() > MAX_CSA_CONTROLS {
            return Err(format!(
                "control_matrix has {} entries, max is {}",
                self.control_matrix.len(),
                MAX_CSA_CONTROLS,
            ));
        }
        if self.autonomy_coverage.len() > MAX_AUTONOMY_LEVELS {
            return Err(format!(
                "autonomy_coverage has {} entries, max is {}",
                self.autonomy_coverage.len(),
                MAX_AUTONOMY_LEVELS,
            ));
        }
        for dc in &self.domain_coverage {
            if !dc.coverage_percent.is_finite()
                || dc.coverage_percent < 0.0
                || dc.coverage_percent > 100.0
            {
                return Err(format!(
                    "domain_coverage[{}].coverage_percent out of range: {}",
                    dc.domain_name, dc.coverage_percent
                ));
            }
        }
        for alc in &self.autonomy_coverage {
            if !alc.coverage_percent.is_finite()
                || alc.coverage_percent < 0.0
                || alc.coverage_percent > 100.0
            {
                return Err(format!(
                    "autonomy_coverage[{}].coverage_percent out of range: {}",
                    alc.level_name, alc.coverage_percent
                ));
            }
        }
        for row in &self.control_matrix {
            if row.mitigations.len() > MAX_MITIGATIONS_PER_CONTROL {
                return Err(format!(
                    "control_matrix[{}].mitigations has {} entries, max is {}",
                    row.id,
                    row.mitigations.len(),
                    MAX_MITIGATIONS_PER_CONTROL,
                ));
            }
        }
        Ok(())
    }

    /// Generate a human-readable report.
    pub fn to_report_string(&self) -> String {
        let mut report = String::new();

        report.push_str("=== CSA Agentic Trust Framework Coverage Report ===\n\n");
        report.push_str(&format!(
            "Coverage: {:.1}% ({}/{} controls across {}/{} trust domains)\n\n",
            self.coverage_percent,
            self.covered_controls,
            self.total_controls,
            self.covered_domains,
            self.total_domains,
        ));

        report.push_str("Trust Domain Breakdown:\n");
        for dc in &self.domain_coverage {
            report.push_str(&format!(
                "  {} — {:.1}% ({}/{})\n",
                dc.domain_name, dc.coverage_percent, dc.covered_controls, dc.total_controls,
            ));
        }

        report.push_str("\nAutonomy Level Readiness:\n");
        for alc in &self.autonomy_coverage {
            report.push_str(&format!(
                "  {} — {:.1}% ({}/{})\n",
                alc.level_name, alc.coverage_percent, alc.covered_controls, alc.required_controls,
            ));
        }

        let uncovered: Vec<&ControlMatrixRow> =
            self.control_matrix.iter().filter(|r| !r.covered).collect();
        if !uncovered.is_empty() {
            report.push_str("\nUncovered Controls:\n");
            for row in &uncovered {
                report.push_str(&format!("  - {} ({})\n", row.id, row.name));
            }
        }

        report
    }
}

// ── Registry ────────────────────────────────────────────────────────────────

/// CSA Agentic Trust Framework compliance registry.
///
/// Maps all 6 trust domains and their 24 controls to Vellaveto detection
/// capabilities, generating coverage reports for compliance dashboards and
/// autonomy-level readiness assessments.
pub struct CsaAtfRegistry {
    /// All controls, keyed by control ID.
    controls: HashMap<String, CsaAtfControl>,
    /// Detection-to-control mappings.
    detection_mappings: HashMap<VellavetoDetection, Vec<String>>,
}

impl Default for CsaAtfRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CsaAtfRegistry {
    /// Create a new registry populated with all CSA ATF controls and mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            controls: HashMap::new(),
            detection_mappings: HashMap::new(),
        };
        registry.populate_controls();
        registry.populate_detection_mappings();
        registry
    }

    /// Get a control by ID.
    pub fn get_control(&self, id: &str) -> Option<&CsaAtfControl> {
        self.controls.get(id)
    }

    /// Get all controls for a trust domain.
    pub fn get_controls_for_domain(&self, domain: CsaAtfDomain) -> Vec<&CsaAtfControl> {
        self.controls
            .values()
            .filter(|c| c.category == domain)
            .collect()
    }

    /// Get all controls mapped to a detection type.
    pub fn get_controls_for_detection(
        &self,
        detection: VellavetoDetection,
    ) -> Vec<&CsaAtfControl> {
        self.detection_mappings
            .get(&detection)
            .map(|ids| ids.iter().filter_map(|id| self.controls.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all detection types that map to a given control.
    pub fn get_detections_for_control(&self, control_id: &str) -> Vec<VellavetoDetection> {
        self.detection_mappings
            .iter()
            .filter(|(_, ids)| ids.iter().any(|id| id == control_id))
            .map(|(d, _)| *d)
            .collect()
    }

    /// Total number of controls in the registry.
    pub fn total_controls(&self) -> usize {
        self.controls.len()
    }

    /// Generate a coverage report across all trust domains and autonomy levels.
    pub fn generate_coverage_report(&self) -> CsaAtfCoverageReport {
        // Collect covered control IDs from detection mappings
        let mut covered_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for ids in self.detection_mappings.values() {
            for id in ids {
                covered_ids.insert(id.as_str());
            }
        }
        // Also count controls with non-empty mitigations (structural coverage)
        for (id, control) in &self.controls {
            if !control.mitigations.is_empty() {
                covered_ids.insert(id.as_str());
            }
        }

        let total_controls = self.controls.len();
        let covered_count = covered_ids.len();
        let coverage_percent = if total_controls > 0 {
            (covered_count as f32 / total_controls as f32) * 100.0
        } else {
            0.0
        };

        // Per-domain breakdown
        let all_domains = [
            CsaAtfDomain::IdentityAuthentication,
            CsaAtfDomain::AuthorizationAccessControl,
            CsaAtfDomain::BehavioralMonitoring,
            CsaAtfDomain::DataProtection,
            CsaAtfDomain::AuditAccountability,
            CsaAtfDomain::IncidentResponse,
        ];

        let mut domain_coverage = Vec::new();
        let mut covered_domains = 0usize;

        for domain in &all_domains {
            let dom_controls: Vec<&CsaAtfControl> = self
                .controls
                .values()
                .filter(|c| c.category == *domain)
                .collect();
            let dom_total = dom_controls.len();
            let dom_covered = dom_controls
                .iter()
                .filter(|c| covered_ids.contains(c.id.as_str()))
                .count();
            let dom_pct = if dom_total > 0 {
                (dom_covered as f32 / dom_total as f32) * 100.0
            } else {
                0.0
            };
            if dom_covered == dom_total && dom_total > 0 {
                covered_domains += 1;
            }
            domain_coverage.push(DomainCoverage {
                domain: *domain,
                domain_name: domain.to_string(),
                total_controls: dom_total,
                covered_controls: dom_covered,
                coverage_percent: dom_pct,
            });
        }

        // Autonomy level readiness
        // Level 1 (Human-in-loop): requires IA + AA controls (identity + access)
        // Level 2 (Human-on-loop): Level 1 + BM controls (monitoring)
        // Level 3 (Human-over-loop): Level 2 + AU + DP controls (audit + data)
        // Level 4 (Fully autonomous): all controls including IR
        let autonomy_coverage = self.compute_autonomy_coverage(&covered_ids);

        // Build control matrix (sorted by ID)
        let mut matrix: Vec<ControlMatrixRow> = self
            .controls
            .values()
            .map(|c| ControlMatrixRow {
                id: c.id.clone(),
                domain: c.category,
                name: c.name.clone(),
                covered: covered_ids.contains(c.id.as_str()),
                mitigations: c.mitigations.clone(),
            })
            .collect();
        matrix.sort_by(|a, b| a.id.cmp(&b.id));

        CsaAtfCoverageReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_domains: all_domains.len(),
            covered_domains,
            total_controls,
            covered_controls: covered_count,
            coverage_percent,
            domain_coverage,
            autonomy_coverage,
            control_matrix: matrix,
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    fn add_control(
        &mut self,
        id: &str,
        category: CsaAtfDomain,
        name: &str,
        description: &str,
        mitigations: &[&str],
    ) {
        self.controls.insert(
            id.to_string(),
            CsaAtfControl {
                id: id.to_string(),
                category,
                name: name.to_string(),
                description: description.to_string(),
                mitigations: mitigations.iter().map(|s| s.to_string()).collect(),
            },
        );
    }

    fn map_detection(&mut self, detection: VellavetoDetection, control_ids: Vec<&str>) {
        self.detection_mappings.insert(
            detection,
            control_ids.iter().map(|s| s.to_string()).collect(),
        );
    }

    /// Compute per-autonomy-level coverage based on domain requirements.
    fn compute_autonomy_coverage(
        &self,
        covered_ids: &std::collections::HashSet<&str>,
    ) -> Vec<AutonomyLevelCoverage> {
        let levels = [
            (
                AutonomyLevel::HumanInLoop,
                vec![
                    CsaAtfDomain::IdentityAuthentication,
                    CsaAtfDomain::AuthorizationAccessControl,
                ],
            ),
            (
                AutonomyLevel::HumanOnLoop,
                vec![
                    CsaAtfDomain::IdentityAuthentication,
                    CsaAtfDomain::AuthorizationAccessControl,
                    CsaAtfDomain::BehavioralMonitoring,
                ],
            ),
            (
                AutonomyLevel::HumanOverLoop,
                vec![
                    CsaAtfDomain::IdentityAuthentication,
                    CsaAtfDomain::AuthorizationAccessControl,
                    CsaAtfDomain::BehavioralMonitoring,
                    CsaAtfDomain::DataProtection,
                    CsaAtfDomain::AuditAccountability,
                ],
            ),
            (
                AutonomyLevel::FullyAutonomous,
                vec![
                    CsaAtfDomain::IdentityAuthentication,
                    CsaAtfDomain::AuthorizationAccessControl,
                    CsaAtfDomain::BehavioralMonitoring,
                    CsaAtfDomain::DataProtection,
                    CsaAtfDomain::AuditAccountability,
                    CsaAtfDomain::IncidentResponse,
                ],
            ),
        ];

        levels
            .iter()
            .map(|(level, domains)| {
                let required: Vec<&CsaAtfControl> = self
                    .controls
                    .values()
                    .filter(|c| domains.contains(&c.category))
                    .collect();
                let req_count = required.len();
                let cov_count = required
                    .iter()
                    .filter(|c| covered_ids.contains(c.id.as_str()))
                    .count();
                let pct = if req_count > 0 {
                    (cov_count as f32 / req_count as f32) * 100.0
                } else {
                    0.0
                };
                AutonomyLevelCoverage {
                    level: *level,
                    level_name: level.to_string(),
                    required_controls: req_count,
                    covered_controls: cov_count,
                    coverage_percent: pct,
                }
            })
            .collect()
    }

    /// Populate all CSA ATF controls across 6 trust domains.
    fn populate_controls(&mut self) {
        // ── Domain 1: Identity & Authentication (CSA-IA) ────────────────────

        self.add_control(
            "CSA-IA-01",
            CsaAtfDomain::IdentityAuthentication,
            "Agent identity verification",
            "Verify agent identity through cryptographic attestation, \
                DID:PLC binding, and ETDI tool signatures before granting access.",
            &[
                "Agent identity attestation (ETDI Ed25519)",
                "DID:PLC identity binding",
                "Identity federation with JWKS/OIDC",
            ],
        );
        self.add_control(
            "CSA-IA-02",
            CsaAtfDomain::IdentityAuthentication,
            "Credential lifecycle management",
            "Manage agent credentials with rotation, expiry, and revocation \
                capabilities across all transport types.",
            &[
                "OAuth 2.1/JWT/JWKS validation with expiry checking",
                "Token expiry checking across all transports",
                "RFC 8707 resource indicators",
            ],
        );
        self.add_control(
            "CSA-IA-03",
            CsaAtfDomain::IdentityAuthentication,
            "Tool integrity verification",
            "Verify the cryptographic integrity and provenance of MCP tools \
                using ETDI signatures and supply chain verification.",
            &[
                "ETDI tool signatures (Ed25519)",
                "Supply chain verification (SHA-256 binary integrity)",
                "Tool manifest signing and version pinning",
            ],
        );
        self.add_control(
            "CSA-IA-04",
            CsaAtfDomain::IdentityAuthentication,
            "Tool squatting defense",
            "Detect tools with names deceptively similar to legitimate tools \
                using Levenshtein distance, homoglyph, and NFKC analysis.",
            &[
                "Levenshtein distance name similarity detection",
                "Homoglyph detection (Unicode confusables)",
                "NFKC normalization for Mathematical Bold bypass",
            ],
        );

        // ── Domain 2: Authorization & Access Control (CSA-AA) ───────────────

        self.add_control(
            "CSA-AA-01",
            CsaAtfDomain::AuthorizationAccessControl,
            "Policy-based access control",
            "Enforce granular policies on tool invocations with glob, regex, \
                and domain matching rules. Fail-closed evaluation by default.",
            &[
                "Policy engine with glob/regex/domain matching",
                "Fail-closed evaluation",
                "Path traversal protection with normalization",
            ],
        );
        self.add_control(
            "CSA-AA-02",
            CsaAtfDomain::AuthorizationAccessControl,
            "Attribute-based access control",
            "ABAC engine with Cedar-style evaluation and forbid-overrides \
                semantics. Supports IDNA domain normalization.",
            &[
                "ABAC engine with Cedar-style evaluation",
                "Forbid-overrides semantics",
                "IDNA domain normalization (fail-closed)",
            ],
        );
        self.add_control(
            "CSA-AA-03",
            CsaAtfDomain::AuthorizationAccessControl,
            "Capability-based delegation",
            "Enforce capability tokens with monotonic attenuation, bounded \
                delegation depth, and temporal ordering validation.",
            &[
                "Capability delegation tokens",
                "Monotonic attenuation enforcement",
                "Bounded delegation depth with self-delegation rejection",
            ],
        );
        self.add_control(
            "CSA-AA-04",
            CsaAtfDomain::AuthorizationAccessControl,
            "Network boundary enforcement",
            "Enforce domain allowlists/blocklists with IDNA normalization \
                and IP-based rules including private IP blocking and CIDR ranges.",
            &[
                "Domain allowlist/blocklist with IDNA normalization",
                "IP-based rules (private IP blocking, CIDR ranges)",
                "DNS rebinding defense with resolved IP validation",
            ],
        );

        // ── Domain 3: Behavioral Monitoring (CSA-BM) ────────────────────────

        self.add_control(
            "CSA-BM-01",
            CsaAtfDomain::BehavioralMonitoring,
            "Injection detection",
            "Detect prompt injection attempts through Aho-Corasick pattern \
                matching with NFKC normalization and multi-layer decode.",
            &[
                "Aho-Corasick injection scanner",
                "NFKC Unicode normalization",
                "Multi-layer decode (URL/Base64/Unicode/hex/nested)",
            ],
        );
        self.add_control(
            "CSA-BM-02",
            CsaAtfDomain::BehavioralMonitoring,
            "Behavioral anomaly detection",
            "Detect goal drift and behavioral anomalies using exponential \
                moving average analysis and intent chain tracking.",
            &[
                "Goal drift detection with intent chain analysis",
                "Behavioral anomaly detection (EMA)",
                "Trust decay on corrupt timestamps",
            ],
        );
        self.add_control(
            "CSA-BM-03",
            CsaAtfDomain::BehavioralMonitoring,
            "Shadow agent detection",
            "Detect unregistered agents and rogue agents in multi-agent \
                environments using passive discovery and registration enforcement.",
            &[
                "ShadowAiDiscoveryEngine (passive detection)",
                "ShadowAgentDetector with bounded tracking",
                "Agent registration enforcement",
            ],
        );
        self.add_control(
            "CSA-BM-04",
            CsaAtfDomain::BehavioralMonitoring,
            "Memory poisoning detection",
            "Detect replayed response data in subsequent tool call parameters \
                and cross-request data flow tracking.",
            &[
                "Memory tracker with response fingerprinting",
                "Cross-request data flow tracking",
                "Tainted response exclusion from tracker",
            ],
        );

        // ── Domain 4: Data Protection (CSA-DP) ─────────────────────────────

        self.add_control(
            "CSA-DP-01",
            CsaAtfDomain::DataProtection,
            "Data loss prevention",
            "Scan tool parameters and responses for secrets and sensitive \
                data using 5-layer decode DLP with configurable pattern sets.",
            &[
                "5-layer decode DLP (URL/Base64/Unicode/hex/nested)",
                "Parameter and response DLP scanning",
                "Configurable pattern sets (API keys, tokens, PII)",
            ],
        );
        self.add_control(
            "CSA-DP-02",
            CsaAtfDomain::DataProtection,
            "PII redaction engine",
            "Automatically redact personally identifiable information from \
                audit logs, tool responses, and error messages.",
            &[
                "PII scanning with configurable patterns",
                "Sensitive key redaction in audit entries",
                "Custom Debug impls redacting secrets",
            ],
        );
        self.add_control(
            "CSA-DP-03",
            CsaAtfDomain::DataProtection,
            "Covert channel detection",
            "Detect and block steganographic data exfiltration, covert \
                channels, and cross-request data laundering.",
            &[
                "Covert channel detection in tool output",
                "Steganography detection (multimodal inspection)",
                "Cross-request data laundering defense",
            ],
        );
        self.add_control(
            "CSA-DP-04",
            CsaAtfDomain::DataProtection,
            "Output schema validation",
            "Validate tool output against registered JSON schemas to prevent \
                unexpected data shapes and enforce data contracts.",
            &[
                "OutputSchemaRegistry with per-tool schemas",
                "structuredContent validation",
                "Schema violation blocking (configurable)",
            ],
        );

        // ── Domain 5: Audit & Accountability (CSA-AU) ──────────────────────

        self.add_control(
            "CSA-AU-01",
            CsaAtfDomain::AuditAccountability,
            "Tamper-evident audit logging",
            "Append-only audit log with SHA-256 hash chains, Merkle tree \
                inclusion proofs, and Ed25519-signed checkpoints.",
            &[
                "SHA-256 hash chain (append-only)",
                "Merkle tree inclusion proofs",
                "Ed25519-signed checkpoints",
            ],
        );
        self.add_control(
            "CSA-AU-02",
            CsaAtfDomain::AuditAccountability,
            "Compliance framework reporting",
            "Automated coverage reporting across multiple security frameworks \
                including EU AI Act, SOC 2, ISO 42001, DORA, and NIS2.",
            &[
                "EU AI Act conformity assessment registry",
                "SOC 2 evidence generation",
                "Cross-framework gap analysis",
            ],
        );
        self.add_control(
            "CSA-AU-03",
            CsaAtfDomain::AuditAccountability,
            "Zero-knowledge audit proofs",
            "Generate zero-knowledge proofs (Pedersen + Groth16) for audit \
                verification without revealing sensitive decision details.",
            &[
                "Pedersen commitment-based ZK proofs",
                "Groth16 verification circuits",
                "Evidence pack generation for compliance",
            ],
        );
        self.add_control(
            "CSA-AU-04",
            CsaAtfDomain::AuditAccountability,
            "Audit export and integration",
            "Export audit trails in multiple formats (CEF, JSONL, webhook, \
                syslog) with dual-write to PostgreSQL for enterprise SIEM.",
            &[
                "CEF/JSONL/webhook/syslog export",
                "PostgreSQL dual-write",
                "Log rotation with tamper detection manifests",
            ],
        );

        // ── Domain 6: Incident Response (CSA-IR) ───────────────────────────

        self.add_control(
            "CSA-IR-01",
            CsaAtfDomain::IncidentResponse,
            "Circuit breaker pattern",
            "Prevent cascading failures with per-tool circuit breakers \
                (Closed/Open/HalfOpen) with configurable thresholds.",
            &[
                "CircuitBreakerManager (Closed/Open/HalfOpen)",
                "Configurable failure/success thresholds",
                "Exponential backoff on open state",
            ],
        );
        self.add_control(
            "CSA-IR-02",
            CsaAtfDomain::IncidentResponse,
            "Rate limiting and budget enforcement",
            "Enforce per-session call limits, time windows, and resource \
                budgets to contain runaway agent behavior.",
            &[
                "Per-session rate limiting with sliding windows",
                "Token budget tracking",
                "Workflow budget enforcement with DAG validation",
            ],
        );
        self.add_control(
            "CSA-IR-03",
            CsaAtfDomain::IncidentResponse,
            "Transport health and fallback",
            "Monitor transport health and provide smart fallback across \
                gRPC, WebSocket, HTTP, and stdio transports.",
            &[
                "TransportHealthTracker per-transport circuit breaker",
                "SmartFallbackChain (gRPC -> WS -> HTTP -> stdio)",
                "Per-attempt and total timeouts",
            ],
        );
        self.add_control(
            "CSA-IR-04",
            CsaAtfDomain::IncidentResponse,
            "Human-in-the-loop approval workflow",
            "Require explicit human approval for sensitive operations with \
                deduplication, expiry, and self-approval prevention.",
            &[
                "RequireApproval verdict type",
                "Approval store with dedup and expiry",
                "Self-approval prevention (homoglyph-aware, NFKC)",
            ],
        );
    }

    /// Populate detection-to-control mappings.
    fn populate_detection_mappings(&mut self) {
        // ── Identity & Authentication (CSA-IA) ──────────────────────────────
        // ToolAnnotationChange, ToolSquatting, SchemaPoisoning → IA controls
        self.map_detection(
            VellavetoDetection::ToolAnnotationChange,
            vec!["CSA-IA-01", "CSA-IA-03"],
        );
        self.map_detection(
            VellavetoDetection::ToolSquatting,
            vec!["CSA-IA-04"],
        );
        self.map_detection(
            VellavetoDetection::SchemaPoisoning,
            vec!["CSA-IA-03"],
        );
        self.map_detection(
            VellavetoDetection::ToolShadowing,
            vec!["CSA-IA-04"],
        );

        // ── Authorization & Access Control (CSA-AA) ─────────────────────────
        // ExcessiveAgency, UnauthorizedToolAccess → AA controls
        // PathTraversal, DnsRebinding → AA controls
        // ConfusedDeputy, PrivilegeEscalation → AA controls
        self.map_detection(
            VellavetoDetection::ExcessiveAgency,
            vec!["CSA-AA-01", "CSA-AA-03"],
        );
        self.map_detection(
            VellavetoDetection::UnauthorizedToolAccess,
            vec!["CSA-AA-01", "CSA-AA-02"],
        );
        self.map_detection(
            VellavetoDetection::PathTraversal,
            vec!["CSA-AA-01", "CSA-AA-04"],
        );
        self.map_detection(
            VellavetoDetection::DnsRebinding,
            vec!["CSA-AA-04"],
        );
        self.map_detection(
            VellavetoDetection::ConfusedDeputy,
            vec!["CSA-AA-03"],
        );
        self.map_detection(
            VellavetoDetection::PrivilegeEscalation,
            vec!["CSA-AA-02", "CSA-AA-03"],
        );
        self.map_detection(
            VellavetoDetection::UnauthorizedDelegation,
            vec!["CSA-AA-03"],
        );

        // ── Behavioral Monitoring (CSA-BM) ──────────────────────────────────
        // PromptInjection, IndirectInjection, UnicodeManipulation → BM controls
        // ShadowAgent, MemoryInjection, GoalDrift → BM controls
        self.map_detection(
            VellavetoDetection::PromptInjection,
            vec!["CSA-BM-01"],
        );
        self.map_detection(
            VellavetoDetection::IndirectInjection,
            vec!["CSA-BM-01"],
        );
        self.map_detection(
            VellavetoDetection::UnicodeManipulation,
            vec!["CSA-BM-01"],
        );
        self.map_detection(
            VellavetoDetection::SecondOrderInjection,
            vec!["CSA-BM-01"],
        );
        self.map_detection(
            VellavetoDetection::DelimiterInjection,
            vec!["CSA-BM-01"],
        );
        self.map_detection(
            VellavetoDetection::GlitchToken,
            vec!["CSA-BM-01"],
        );
        self.map_detection(
            VellavetoDetection::ShadowAgent,
            vec!["CSA-BM-03"],
        );
        self.map_detection(
            VellavetoDetection::MemoryInjection,
            vec!["CSA-BM-04"],
        );
        self.map_detection(
            VellavetoDetection::GoalDrift,
            vec!["CSA-BM-02"],
        );
        self.map_detection(
            VellavetoDetection::ContextFlooding,
            vec!["CSA-BM-02"],
        );

        // ── Data Protection (CSA-DP) ────────────────────────────────────────
        // SecretsInOutput, CovertChannel, DataLaundering → DP controls
        self.map_detection(
            VellavetoDetection::SecretsInOutput,
            vec!["CSA-DP-01", "CSA-DP-02"],
        );
        self.map_detection(
            VellavetoDetection::CovertChannel,
            vec!["CSA-DP-03"],
        );
        self.map_detection(
            VellavetoDetection::DataLaundering,
            vec!["CSA-DP-03"],
        );
        self.map_detection(
            VellavetoDetection::Steganography,
            vec!["CSA-DP-03"],
        );
        self.map_detection(
            VellavetoDetection::TokenSmuggling,
            vec!["CSA-DP-01"],
        );
        self.map_detection(
            VellavetoDetection::SamplingAttack,
            vec!["CSA-DP-04"],
        );

        // ── Incident Response (CSA-IR) ──────────────────────────────────────
        // CircuitBreakerTriggered, CascadingFailure → IR controls
        // RateLimitExceeded → IR controls
        self.map_detection(
            VellavetoDetection::CircuitBreakerTriggered,
            vec!["CSA-IR-01"],
        );
        self.map_detection(
            VellavetoDetection::CascadingFailure,
            vec!["CSA-IR-01", "CSA-IR-03"],
        );
        self.map_detection(
            VellavetoDetection::RateLimitExceeded,
            vec!["CSA-IR-02"],
        );
        self.map_detection(
            VellavetoDetection::WorkflowBudgetExceeded,
            vec!["CSA-IR-02"],
        );
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = CsaAtfRegistry::new();
        assert!(
            registry.total_controls() > 0,
            "Registry should have controls"
        );
    }

    #[test]
    fn test_default_trait() {
        let registry = CsaAtfRegistry::default();
        assert!(
            registry.total_controls() > 0,
            "Default registry should have controls"
        );
    }

    #[test]
    fn test_all_6_domains_populated() {
        let registry = CsaAtfRegistry::new();
        let domains = [
            CsaAtfDomain::IdentityAuthentication,
            CsaAtfDomain::AuthorizationAccessControl,
            CsaAtfDomain::BehavioralMonitoring,
            CsaAtfDomain::DataProtection,
            CsaAtfDomain::AuditAccountability,
            CsaAtfDomain::IncidentResponse,
        ];
        for domain in &domains {
            let controls = registry.get_controls_for_domain(*domain);
            assert!(
                !controls.is_empty(),
                "Domain {} should have at least one control",
                domain
            );
        }
    }

    #[test]
    fn test_4_controls_per_domain() {
        let registry = CsaAtfRegistry::new();
        let domains = [
            CsaAtfDomain::IdentityAuthentication,
            CsaAtfDomain::AuthorizationAccessControl,
            CsaAtfDomain::BehavioralMonitoring,
            CsaAtfDomain::DataProtection,
            CsaAtfDomain::AuditAccountability,
            CsaAtfDomain::IncidentResponse,
        ];
        for domain in &domains {
            let controls = registry.get_controls_for_domain(*domain);
            assert_eq!(
                controls.len(),
                4,
                "Domain {} should have exactly 4 controls, got {}",
                domain,
                controls.len()
            );
        }
    }

    #[test]
    fn test_total_controls_count() {
        let registry = CsaAtfRegistry::new();
        // 6 domains * 4 controls each = 24
        assert_eq!(
            registry.total_controls(),
            24,
            "Expected 24 controls across 6 trust domains"
        );
    }

    #[test]
    fn test_control_lookup_by_id() {
        let registry = CsaAtfRegistry::new();
        let control = registry.get_control("CSA-IA-01");
        assert!(control.is_some(), "CSA-IA-01 should exist");
        let c = control.expect("control should exist in test");
        assert_eq!(c.category, CsaAtfDomain::IdentityAuthentication);
        assert!(!c.name.is_empty());
        assert!(!c.mitigations.is_empty());
    }

    #[test]
    fn test_all_control_ids_follow_format() {
        let registry = CsaAtfRegistry::new();
        let expected_prefixes = ["CSA-IA-", "CSA-AA-", "CSA-BM-", "CSA-DP-", "CSA-AU-", "CSA-IR-"];
        for (id, _) in &registry.controls {
            assert!(
                expected_prefixes.iter().any(|p| id.starts_with(p)),
                "Control ID '{}' does not match expected CSA-XX-NN format",
                id
            );
        }
    }

    #[test]
    fn test_all_controls_have_mitigations() {
        let registry = CsaAtfRegistry::new();
        for (id, control) in &registry.controls {
            assert!(
                !control.mitigations.is_empty(),
                "Control {} should have at least one mitigation",
                id
            );
        }
    }

    #[test]
    fn test_detection_to_control_mapping_prompt_injection() {
        let registry = CsaAtfRegistry::new();
        let controls = registry.get_controls_for_detection(VellavetoDetection::PromptInjection);
        assert!(
            !controls.is_empty(),
            "PromptInjection should map to at least one control"
        );
        assert!(
            controls.iter().any(|c| c.id.starts_with("CSA-BM-")),
            "PromptInjection should map to a BM control"
        );
    }

    #[test]
    fn test_detection_to_control_mapping_path_traversal() {
        let registry = CsaAtfRegistry::new();
        let controls = registry.get_controls_for_detection(VellavetoDetection::PathTraversal);
        assert!(
            !controls.is_empty(),
            "PathTraversal should map to at least one control"
        );
        assert!(
            controls.iter().any(|c| c.id.starts_with("CSA-AA-")),
            "PathTraversal should map to an AA control"
        );
    }

    #[test]
    fn test_detection_to_control_mapping_circuit_breaker() {
        let registry = CsaAtfRegistry::new();
        let controls =
            registry.get_controls_for_detection(VellavetoDetection::CircuitBreakerTriggered);
        assert!(
            !controls.is_empty(),
            "CircuitBreakerTriggered should map to at least one control"
        );
        assert!(
            controls.iter().any(|c| c.id.starts_with("CSA-IR-")),
            "CircuitBreakerTriggered should map to an IR control"
        );
    }

    #[test]
    fn test_detection_to_control_mapping_secrets() {
        let registry = CsaAtfRegistry::new();
        let controls = registry.get_controls_for_detection(VellavetoDetection::SecretsInOutput);
        assert!(
            !controls.is_empty(),
            "SecretsInOutput should map to at least one control"
        );
        assert!(
            controls.iter().any(|c| c.id.starts_with("CSA-DP-")),
            "SecretsInOutput should map to a DP control"
        );
    }

    #[test]
    fn test_control_to_detection_mapping() {
        let registry = CsaAtfRegistry::new();
        let detections = registry.get_detections_for_control("CSA-BM-01");
        assert!(
            !detections.is_empty(),
            "CSA-BM-01 should be mapped from at least one detection"
        );
        assert!(
            detections.contains(&VellavetoDetection::PromptInjection),
            "CSA-BM-01 should be mapped from PromptInjection"
        );
    }

    #[test]
    fn test_coverage_report_generation() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(report.total_domains, 6);
        assert_eq!(report.total_controls, 24);
        assert!(report.covered_controls > 0);
        assert!(report.coverage_percent > 0.0);
        assert!(!report.domain_coverage.is_empty());
        assert!(!report.control_matrix.is_empty());
        assert!(!report.autonomy_coverage.is_empty());
    }

    #[test]
    fn test_full_coverage() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(
            report.covered_controls, report.total_controls,
            "All {} controls should be covered, but only {} are",
            report.total_controls, report.covered_controls
        );
        assert!(
            (report.coverage_percent - 100.0).abs() < 0.01,
            "Coverage should be 100%, got {:.1}%",
            report.coverage_percent
        );
        assert_eq!(
            report.covered_domains, 6,
            "All 6 domains should be fully covered"
        );
    }

    #[test]
    fn test_domain_coverage_breakdown() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(report.domain_coverage.len(), 6);
        for dc in &report.domain_coverage {
            assert!(
                dc.total_controls > 0,
                "Domain {} should have controls",
                dc.domain_name
            );
            assert!(
                (dc.coverage_percent - 100.0).abs() < 0.01,
                "Domain {} should have 100% coverage, got {:.1}%",
                dc.domain_name,
                dc.coverage_percent
            );
        }
    }

    #[test]
    fn test_autonomy_level_coverage() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(report.autonomy_coverage.len(), 4);

        // Level 1 requires IA + AA = 8 controls
        let level1 = &report.autonomy_coverage[0];
        assert_eq!(level1.level, AutonomyLevel::HumanInLoop);
        assert_eq!(level1.required_controls, 8);

        // Level 2 requires IA + AA + BM = 12 controls
        let level2 = &report.autonomy_coverage[1];
        assert_eq!(level2.level, AutonomyLevel::HumanOnLoop);
        assert_eq!(level2.required_controls, 12);

        // Level 3 requires IA + AA + BM + DP + AU = 20 controls
        let level3 = &report.autonomy_coverage[2];
        assert_eq!(level3.level, AutonomyLevel::HumanOverLoop);
        assert_eq!(level3.required_controls, 20);

        // Level 4 requires all 24 controls
        let level4 = &report.autonomy_coverage[3];
        assert_eq!(level4.level, AutonomyLevel::FullyAutonomous);
        assert_eq!(level4.required_controls, 24);
    }

    #[test]
    fn test_autonomy_all_levels_100_percent() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();

        for alc in &report.autonomy_coverage {
            assert!(
                (alc.coverage_percent - 100.0).abs() < 0.01,
                "Autonomy level {} should have 100% coverage, got {:.1}%",
                alc.level_name,
                alc.coverage_percent
            );
        }
    }

    #[test]
    fn test_control_matrix_sorted() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();

        for window in report.control_matrix.windows(2) {
            assert!(
                window[0].id <= window[1].id,
                "Control matrix should be sorted: {} > {}",
                window[0].id,
                window[1].id
            );
        }
    }

    #[test]
    fn test_control_matrix_count() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();
        assert_eq!(
            report.control_matrix.len(),
            24,
            "Control matrix should have 24 rows"
        );
    }

    #[test]
    fn test_report_validate_passes_for_valid_report() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();
        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_report_validate_rejects_nan_coverage() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.coverage_percent = f32::NAN;
        let err = report.validate().unwrap_err();
        assert!(err.contains("coverage_percent"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_negative_coverage() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.coverage_percent = -1.0;
        let err = report.validate().unwrap_err();
        assert!(err.contains("coverage_percent"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_over_100_coverage() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.coverage_percent = 101.0;
        let err = report.validate().unwrap_err();
        assert!(err.contains("coverage_percent"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_infinity_coverage() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.coverage_percent = f32::INFINITY;
        let err = report.validate().unwrap_err();
        assert!(err.contains("coverage_percent"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_nan_domain_coverage() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.domain_coverage[0].coverage_percent = f32::NAN;
        let err = report.validate().unwrap_err();
        assert!(err.contains("domain_coverage"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_nan_autonomy_coverage() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.autonomy_coverage[0].coverage_percent = f32::NAN;
        let err = report.validate().unwrap_err();
        assert!(err.contains("autonomy_coverage"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_excessive_domain_coverage() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        for _ in 0..25 {
            report.domain_coverage.push(DomainCoverage {
                domain: CsaAtfDomain::IncidentResponse,
                domain_name: "extra".to_string(),
                total_controls: 1,
                covered_controls: 1,
                coverage_percent: 100.0,
            });
        }
        let err = report.validate().unwrap_err();
        assert!(err.contains("domain_coverage"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_excessive_control_matrix() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        for i in 0..110 {
            report.control_matrix.push(ControlMatrixRow {
                id: format!("CSA-XX-{:03}", i),
                domain: CsaAtfDomain::IncidentResponse,
                name: "extra".to_string(),
                covered: true,
                mitigations: vec!["m".to_string()],
            });
        }
        let err = report.validate().unwrap_err();
        assert!(err.contains("control_matrix"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_excessive_mitigations() {
        let registry = CsaAtfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.control_matrix[0].mitigations = (0..60).map(|i| format!("m{}", i)).collect();
        let err = report.validate().unwrap_err();
        assert!(err.contains("mitigations"), "err: {}", err);
    }

    #[test]
    fn test_serde_roundtrip_report() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();

        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: CsaAtfCoverageReport =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(deserialized.total_controls, report.total_controls);
        assert_eq!(deserialized.covered_controls, report.covered_controls);
        assert_eq!(deserialized.total_domains, report.total_domains);
        assert_eq!(
            deserialized.domain_coverage.len(),
            report.domain_coverage.len()
        );
        assert_eq!(
            deserialized.autonomy_coverage.len(),
            report.autonomy_coverage.len()
        );
    }

    #[test]
    fn test_serde_roundtrip_control() {
        let control = CsaAtfControl {
            id: "CSA-IA-01".to_string(),
            category: CsaAtfDomain::IdentityAuthentication,
            name: "Test Control".to_string(),
            description: "Test".to_string(),
            mitigations: vec!["m1".to_string()],
        };
        let json = serde_json::to_string(&control).expect("serialize should succeed");
        let deserialized: CsaAtfControl =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.id, "CSA-IA-01");
        assert_eq!(deserialized.category, CsaAtfDomain::IdentityAuthentication);
    }

    #[test]
    fn test_serde_deny_unknown_fields_control() {
        let json = r#"{"id":"CSA-IA-01","category":"IdentityAuthentication","name":"x","description":"x","mitigations":[],"extra":"bad"}"#;
        let result: Result<CsaAtfControl, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Should reject unknown fields");
    }

    #[test]
    fn test_serde_deny_unknown_fields_report() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();
        let mut json: serde_json::Value =
            serde_json::to_value(&report).expect("serialize should succeed");
        json.as_object_mut()
            .expect("should be object in test")
            .insert("extra".to_string(), serde_json::json!("bad"));
        let result: Result<CsaAtfCoverageReport, _> = serde_json::from_value(json);
        assert!(result.is_err(), "Should reject unknown fields in report");
    }

    #[test]
    fn test_domain_display() {
        assert_eq!(
            CsaAtfDomain::IdentityAuthentication.to_string(),
            "Identity & Authentication"
        );
        assert_eq!(
            CsaAtfDomain::AuthorizationAccessControl.to_string(),
            "Authorization & Access Control"
        );
        assert_eq!(
            CsaAtfDomain::BehavioralMonitoring.to_string(),
            "Behavioral Monitoring"
        );
        assert_eq!(
            CsaAtfDomain::DataProtection.to_string(),
            "Data Protection"
        );
        assert_eq!(
            CsaAtfDomain::AuditAccountability.to_string(),
            "Audit & Accountability"
        );
        assert_eq!(
            CsaAtfDomain::IncidentResponse.to_string(),
            "Incident Response"
        );
    }

    #[test]
    fn test_autonomy_level_display() {
        assert_eq!(
            AutonomyLevel::HumanInLoop.to_string(),
            "Level 1: Human-in-Loop"
        );
        assert_eq!(
            AutonomyLevel::HumanOnLoop.to_string(),
            "Level 2: Human-on-Loop"
        );
        assert_eq!(
            AutonomyLevel::HumanOverLoop.to_string(),
            "Level 3: Human-over-Loop"
        );
        assert_eq!(
            AutonomyLevel::FullyAutonomous.to_string(),
            "Level 4: Fully Autonomous"
        );
    }

    #[test]
    fn test_no_duplicate_control_ids() {
        let registry = CsaAtfRegistry::new();
        let mut seen = std::collections::HashSet::new();
        for id in registry.controls.keys() {
            assert!(seen.insert(id.clone()), "Duplicate control ID: {}", id);
        }
    }

    #[test]
    fn test_detection_mappings_reference_valid_controls() {
        let registry = CsaAtfRegistry::new();
        for (detection, control_ids) in &registry.detection_mappings {
            for id in control_ids {
                assert!(
                    registry.controls.contains_key(id),
                    "Detection {:?} references non-existent control '{}'",
                    detection,
                    id
                );
            }
        }
    }

    #[test]
    fn test_coverage_report_string_contains_header() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();
        let report_str = report.to_report_string();

        assert!(report_str.contains("CSA Agentic Trust Framework Coverage Report"));
        assert!(report_str.contains("Coverage:"));
        assert!(report_str.contains("Trust Domain Breakdown:"));
        assert!(report_str.contains("Autonomy Level Readiness:"));
    }

    #[test]
    fn test_coverage_report_string_contains_domains() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();
        let report_str = report.to_report_string();

        assert!(report_str.contains("Identity & Authentication"));
        assert!(report_str.contains("Authorization & Access Control"));
        assert!(report_str.contains("Behavioral Monitoring"));
        assert!(report_str.contains("Data Protection"));
        assert!(report_str.contains("Audit & Accountability"));
        assert!(report_str.contains("Incident Response"));
    }

    #[test]
    fn test_coverage_report_string_contains_autonomy_levels() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();
        let report_str = report.to_report_string();

        assert!(report_str.contains("Level 1: Human-in-Loop"));
        assert!(report_str.contains("Level 2: Human-on-Loop"));
        assert!(report_str.contains("Level 3: Human-over-Loop"));
        assert!(report_str.contains("Level 4: Fully Autonomous"));
    }

    #[test]
    fn test_coverage_report_string_no_uncovered_section_when_full() {
        let registry = CsaAtfRegistry::new();
        let report = registry.generate_coverage_report();
        let report_str = report.to_report_string();

        // When coverage is 100%, there should be no "Uncovered Controls:" section
        assert!(
            !report_str.contains("Uncovered Controls:"),
            "Full coverage report should not list uncovered controls"
        );
    }

    #[test]
    fn test_nonexistent_control_returns_none() {
        let registry = CsaAtfRegistry::new();
        assert!(registry.get_control("CSA-XX-99").is_none());
    }

    #[test]
    fn test_unmapped_detection_returns_empty() {
        // Verify that a detection not in our mappings returns empty
        // (All detections should be mapped, but the API should still handle it gracefully)
        let registry = CsaAtfRegistry::new();
        let controls = registry.get_controls_for_detection(VellavetoDetection::PromptInjection);
        // PromptInjection IS mapped, so this should be non-empty
        assert!(!controls.is_empty());
    }

    #[test]
    fn test_detections_for_nonexistent_control_returns_empty() {
        let registry = CsaAtfRegistry::new();
        let detections = registry.get_detections_for_control("CSA-XX-99");
        assert!(detections.is_empty());
    }
}
