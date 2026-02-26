//! Singapore Model Governance Framework (MGF) for Agentic AI Compliance Registry.
//!
//! Maps Vellaveto detection capabilities to the Singapore MGF for Agentic AI
//! (January 2026 edition). The framework defines 4 governance dimensions:
//!
//! 1. **Risk Bounding** — Risk assessment, boundaries for autonomous actions,
//!    escalation protocols for high-risk decisions.
//! 2. **Human Accountability** — Operator accountability, audit trails,
//!    human oversight mechanisms, liability frameworks.
//! 3. **Technical Controls** — Identity verification, access control,
//!    monitoring, logging, fail-safe mechanisms.
//! 4. **End-User Responsibility** — Transparency, informed consent,
//!    grievance mechanisms, user agency.
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::singapore_mgf::SingaporeMgfRegistry;
//!
//! let registry = SingaporeMgfRegistry::new();
//! let report = registry.generate_coverage_report();
//! println!("Singapore MGF coverage: {:.1}%", report.coverage_percent);
//! ```
//!
//! Reference: Singapore IMDA — Model AI Governance Framework for Generative AI
//! and Agentic AI (January 2026).

use crate::atlas::VellavetoDetection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Validation Constants ────────────────────────────────────────────────────

/// Maximum number of requirements in the registry (current spec: 20).
const MAX_MGF_REQUIREMENTS: usize = 100;

/// Maximum number of dimensions (current spec: 4).
const MAX_MGF_DIMENSIONS: usize = 10;

/// Maximum mitigations per requirement.
const MAX_MITIGATIONS_PER_REQUIREMENT: usize = 50;

/// Maximum length of a requirement ID string.
const MAX_REQUIREMENT_ID_LEN: usize = 64;

/// Maximum length of a requirement name string.
const MAX_REQUIREMENT_NAME_LEN: usize = 256;

/// Maximum length of a requirement description string.
const MAX_REQUIREMENT_DESCRIPTION_LEN: usize = 2048;

/// Singapore MGF governance dimensions (4 pillars).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MgfDimension {
    /// Risk assessment, boundaries for autonomous actions, escalation protocols.
    RiskBounding,
    /// Operator accountability, audit trails, human oversight, liability.
    HumanAccountability,
    /// Identity verification, access control, monitoring, logging, fail-safes.
    TechnicalControls,
    /// Transparency, informed consent, grievance mechanisms, user agency.
    EndUserResponsibility,
}

impl std::fmt::Display for MgfDimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RiskBounding => write!(f, "Risk Bounding"),
            Self::HumanAccountability => write!(f, "Human Accountability"),
            Self::TechnicalControls => write!(f, "Technical Controls"),
            Self::EndUserResponsibility => write!(f, "End-User Responsibility"),
        }
    }
}

/// A single governance requirement within a dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MgfRequirement {
    /// Requirement identifier (e.g., "SGP-RB-01").
    pub id: String,
    /// Parent dimension.
    pub category: MgfDimension,
    /// Human-readable name.
    pub name: String,
    /// Description of the governance requirement.
    pub description: String,
    /// Vellaveto capabilities that address this requirement.
    pub mitigations: Vec<String>,
}

/// Per-dimension coverage breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionCoverage {
    /// MGF dimension.
    pub dimension: MgfDimension,
    /// Dimension display name.
    pub dimension_name: String,
    /// Total requirements in this dimension.
    pub total_requirements: usize,
    /// Requirements with at least one Vellaveto mitigation.
    pub covered_requirements: usize,
    /// Coverage percentage for this dimension.
    pub coverage_percent: f32,
}

/// A single row in the requirement coverage matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementMatrixRow {
    /// Requirement ID.
    pub id: String,
    /// Parent dimension.
    pub dimension: MgfDimension,
    /// Requirement name.
    pub name: String,
    /// Whether this requirement is covered.
    pub covered: bool,
    /// Vellaveto mitigations (empty if uncovered).
    pub mitigations: Vec<String>,
}

/// Singapore MGF coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MgfCoverageReport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Total MGF dimensions (4).
    pub total_dimensions: usize,
    /// Dimensions with full coverage.
    pub covered_dimensions: usize,
    /// Total requirements across all dimensions.
    pub total_requirements: usize,
    /// Requirement IDs with at least one Vellaveto detection or mitigation.
    pub covered_requirements: Vec<String>,
    /// Requirement IDs without any Vellaveto detection or mitigation.
    pub uncovered_requirements: Vec<String>,
    /// Overall coverage percentage.
    pub coverage_percent: f32,
    /// Per-dimension breakdown.
    pub dimension_coverage: Vec<DimensionCoverage>,
    /// Coverage matrix: one row per requirement.
    pub requirement_matrix: Vec<RequirementMatrixRow>,
}

impl MgfCoverageReport {
    /// Validate bounds on deserialized report data.
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
        if self.dimension_coverage.len() > MAX_MGF_DIMENSIONS {
            return Err(format!(
                "dimension_coverage has {} entries, max is {}",
                self.dimension_coverage.len(),
                MAX_MGF_DIMENSIONS,
            ));
        }
        if self.requirement_matrix.len() > MAX_MGF_REQUIREMENTS {
            return Err(format!(
                "requirement_matrix has {} entries, max is {}",
                self.requirement_matrix.len(),
                MAX_MGF_REQUIREMENTS,
            ));
        }
        for dc in &self.dimension_coverage {
            if !dc.coverage_percent.is_finite()
                || dc.coverage_percent < 0.0
                || dc.coverage_percent > 100.0
            {
                return Err(format!(
                    "dimension_coverage[{}].coverage_percent out of range: {}",
                    dc.dimension_name, dc.coverage_percent
                ));
            }
        }
        for row in &self.requirement_matrix {
            if row.mitigations.len() > MAX_MITIGATIONS_PER_REQUIREMENT {
                return Err(format!(
                    "requirement_matrix[{}].mitigations has {} entries, max is {}",
                    row.id,
                    row.mitigations.len(),
                    MAX_MITIGATIONS_PER_REQUIREMENT,
                ));
            }
        }
        if self.covered_requirements.len().saturating_add(self.uncovered_requirements.len())
            > MAX_MGF_REQUIREMENTS
        {
            return Err(format!(
                "total requirement IDs ({} + {}) exceeds max {}",
                self.covered_requirements.len(),
                self.uncovered_requirements.len(),
                MAX_MGF_REQUIREMENTS,
            ));
        }
        Ok(())
    }

    /// Generate a human-readable report string.
    pub fn to_report_string(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Singapore MGF for Agentic AI — Coverage Report ===\n\n");
        report.push_str(&format!(
            "Coverage: {:.1}% ({}/{} requirements across {}/{} dimensions)\n\n",
            self.coverage_percent,
            self.covered_requirements.len(),
            self.total_requirements,
            self.covered_dimensions,
            self.total_dimensions,
        ));

        report.push_str("Dimension Breakdown:\n");
        for dim in &self.dimension_coverage {
            report.push_str(&format!(
                "  {} — {:.1}% ({}/{})\n",
                dim.dimension_name,
                dim.coverage_percent,
                dim.covered_requirements,
                dim.total_requirements,
            ));
        }

        if !self.uncovered_requirements.is_empty() {
            report.push_str("\nUncovered Requirements:\n");
            for id in &self.uncovered_requirements {
                report.push_str(&format!("  - {id}\n"));
            }
        }

        report
    }
}

/// Singapore MGF for Agentic AI compliance registry.
///
/// Maps all 4 MGF governance dimensions and their requirements to Vellaveto
/// detection capabilities, generating coverage reports for compliance dashboards.
pub struct SingaporeMgfRegistry {
    /// All registered requirements keyed by ID.
    requirements: HashMap<String, MgfRequirement>,
    /// Mapping from Vellaveto detection to MGF requirement IDs.
    detection_mappings: HashMap<VellavetoDetection, Vec<String>>,
}

impl Default for SingaporeMgfRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SingaporeMgfRegistry {
    /// Create a new registry populated with all MGF requirements and mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            requirements: HashMap::new(),
            detection_mappings: HashMap::new(),
        };
        registry.populate_requirements();
        registry.populate_detection_mappings();
        registry
    }

    /// Get a requirement by ID.
    pub fn get_requirement(&self, id: &str) -> Option<&MgfRequirement> {
        self.requirements.get(id)
    }

    /// Get all requirements for a dimension.
    pub fn get_requirements_for_dimension(
        &self,
        dimension: MgfDimension,
    ) -> Vec<&MgfRequirement> {
        self.requirements
            .values()
            .filter(|r| r.category == dimension)
            .collect()
    }

    /// Get all requirements mapped to a specific Vellaveto detection.
    pub fn get_requirements_for_detection(
        &self,
        detection: VellavetoDetection,
    ) -> Vec<&MgfRequirement> {
        self.detection_mappings
            .get(&detection)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.requirements.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all detection types that map to a given requirement.
    pub fn get_detections_for_requirement(
        &self,
        requirement_id: &str,
    ) -> Vec<VellavetoDetection> {
        self.detection_mappings
            .iter()
            .filter(|(_, ids)| ids.iter().any(|id| id == requirement_id))
            .map(|(d, _)| *d)
            .collect()
    }

    /// Total number of requirements.
    pub fn total_requirements(&self) -> usize {
        self.requirements.len()
    }

    /// Generate a coverage report across all dimensions.
    pub fn generate_coverage_report(&self) -> MgfCoverageReport {
        // Collect requirement IDs covered by detection mappings
        let mut covered_set: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for ids in self.detection_mappings.values() {
            for id in ids {
                covered_set.insert(id.as_str());
            }
        }
        // Also count requirements with non-empty mitigations (structural coverage)
        for (id, req) in &self.requirements {
            if !req.mitigations.is_empty() {
                covered_set.insert(id.as_str());
            }
        }

        let mut covered_requirements = Vec::new();
        let mut uncovered_requirements = Vec::new();

        for id in self.requirements.keys() {
            if covered_set.contains(id.as_str()) {
                covered_requirements.push(id.clone());
            } else {
                uncovered_requirements.push(id.clone());
            }
        }

        covered_requirements.sort();
        uncovered_requirements.sort();

        let all_dimensions = [
            MgfDimension::RiskBounding,
            MgfDimension::HumanAccountability,
            MgfDimension::TechnicalControls,
            MgfDimension::EndUserResponsibility,
        ];

        let mut dimension_coverage = Vec::new();
        let mut covered_dimensions = 0usize;

        for dim in &all_dimensions {
            let dim_reqs: Vec<&MgfRequirement> = self
                .requirements
                .values()
                .filter(|r| &r.category == dim)
                .collect();
            let total = dim_reqs.len();
            let covered = dim_reqs
                .iter()
                .filter(|r| covered_set.contains(r.id.as_str()))
                .count();
            let pct = if total > 0 {
                (covered as f32 / total as f32) * 100.0
            } else {
                0.0
            };
            if covered == total && total > 0 {
                covered_dimensions = covered_dimensions.saturating_add(1);
            }
            dimension_coverage.push(DimensionCoverage {
                dimension: *dim,
                dimension_name: dim.to_string(),
                total_requirements: total,
                covered_requirements: covered,
                coverage_percent: pct,
            });
        }

        // Build requirement matrix (sorted by ID)
        let mut matrix: Vec<RequirementMatrixRow> = self
            .requirements
            .values()
            .map(|r| RequirementMatrixRow {
                id: r.id.clone(),
                dimension: r.category,
                name: r.name.clone(),
                covered: covered_set.contains(r.id.as_str()),
                mitigations: r.mitigations.clone(),
            })
            .collect();
        matrix.sort_by(|a, b| a.id.cmp(&b.id));

        let total_requirements = self.requirements.len();
        let coverage_percent = if total_requirements > 0 {
            (covered_requirements.len() as f32 / total_requirements as f32) * 100.0
        } else {
            0.0
        };

        MgfCoverageReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_dimensions: all_dimensions.len(),
            covered_dimensions,
            total_requirements,
            covered_requirements,
            uncovered_requirements,
            coverage_percent,
            dimension_coverage,
            requirement_matrix: matrix,
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    fn add_requirement(
        &mut self,
        id: &str,
        category: MgfDimension,
        name: &str,
        description: &str,
        mitigations: &[&str],
    ) {
        debug_assert!(id.len() <= MAX_REQUIREMENT_ID_LEN);
        debug_assert!(name.len() <= MAX_REQUIREMENT_NAME_LEN);
        debug_assert!(description.len() <= MAX_REQUIREMENT_DESCRIPTION_LEN);
        debug_assert!(mitigations.len() <= MAX_MITIGATIONS_PER_REQUIREMENT);
        self.requirements.insert(
            id.to_string(),
            MgfRequirement {
                id: id.to_string(),
                category,
                name: name.to_string(),
                description: description.to_string(),
                mitigations: mitigations.iter().map(|s| s.to_string()).collect(),
            },
        );
    }

    fn map_detection(&mut self, detection: VellavetoDetection, requirement_ids: Vec<&str>) {
        self.detection_mappings.insert(
            detection,
            requirement_ids.iter().map(|s| s.to_string()).collect(),
        );
    }

    /// Populate all Singapore MGF requirements across 4 dimensions.
    fn populate_requirements(&mut self) {
        // ── Dimension 1: Risk Bounding ──────────────────────────────────────
        self.add_requirement(
            "SGP-RB-01",
            MgfDimension::RiskBounding,
            "Autonomous action boundaries",
            "Define and enforce boundaries for autonomous agent actions, including \
             maximum scope of operations, resource limits, and escalation thresholds \
             for high-risk decisions that exceed agent authority.",
            &[
                "Policy engine with glob/regex/domain-based action boundaries",
                "Per-session call limits with time windows",
                "Workflow budget enforcement (token/call/time budgets)",
            ],
        );
        self.add_requirement(
            "SGP-RB-02",
            MgfDimension::RiskBounding,
            "Risk assessment for agent operations",
            "Perform runtime risk assessment of agent tool invocations, evaluating \
             the potential impact of each action against defined risk thresholds \
             before permitting execution.",
            &[
                "ABAC engine with Cedar-style risk evaluation",
                "Tool sensitivity classification",
                "Context-aware policy evaluation with risk scoring",
            ],
        );
        self.add_requirement(
            "SGP-RB-03",
            MgfDimension::RiskBounding,
            "Escalation protocols",
            "Implement escalation protocols that require human approval for actions \
             exceeding predefined risk thresholds, including structured approval \
             workflows with timeout and expiry mechanisms.",
            &[
                "RequireApproval verdict with structured approval workflow",
                "Approval store with dedup, expiry, and self-approval prevention",
                "Human-in-the-loop escalation for sensitive operations",
            ],
        );
        self.add_requirement(
            "SGP-RB-04",
            MgfDimension::RiskBounding,
            "Circuit breaker and fail-safe mechanisms",
            "Deploy circuit breakers and fail-safe mechanisms that halt agent \
             operations when error rates exceed safe thresholds, preventing \
             cascading failures and limiting blast radius.",
            &[
                "CircuitBreakerManager (Closed/Open/HalfOpen states)",
                "Per-tool failure tracking with configurable thresholds",
                "Workflow budget enforcement with automatic halt",
            ],
        );
        self.add_requirement(
            "SGP-RB-05",
            MgfDimension::RiskBounding,
            "Resource and budget constraints",
            "Enforce resource consumption limits including call counts, token \
             budgets, time windows, and concurrent operation caps to prevent \
             excessive resource utilization by agents.",
            &[
                "Per-session rate limiting across all transports",
                "Token budget tracking with enforcement",
                "Sliding window rate limiter with saturating counters",
            ],
        );

        // ── Dimension 2: Human Accountability ───────────────────────────────
        self.add_requirement(
            "SGP-HA-01",
            MgfDimension::HumanAccountability,
            "Tamper-evident audit trail",
            "Maintain a tamper-evident, cryptographically verifiable audit trail \
             of all agent decisions and actions, ensuring accountability through \
             immutable records.",
            &[
                "SHA-256 hash chain with Merkle tree inclusion proofs",
                "Ed25519-signed checkpoints for tamper detection",
                "Append-only audit log with rotation manifests",
            ],
        );
        self.add_requirement(
            "SGP-HA-02",
            MgfDimension::HumanAccountability,
            "Operator accountability and identity binding",
            "Establish clear operator accountability by binding agent actions to \
             verified human identities through attestation, delegation chains, \
             and non-repudiation mechanisms.",
            &[
                "Agent identity attestation (ETDI + DID:PLC)",
                "Capability delegation with monotonic attenuation",
                "Accountability attestation with identity federation",
            ],
        );
        self.add_requirement(
            "SGP-HA-03",
            MgfDimension::HumanAccountability,
            "Human oversight mechanisms",
            "Provide mechanisms for human oversight of agent operations, including \
             real-time monitoring dashboards, approval workflows, and the ability \
             to intervene in or halt agent operations.",
            &[
                "Admin console with real-time monitoring",
                "Approval workflow with human-in-the-loop",
                "Policy lifecycle management (Draft/Active/Archived)",
            ],
        );
        self.add_requirement(
            "SGP-HA-04",
            MgfDimension::HumanAccountability,
            "Cross-request behavioral tracking",
            "Track agent behavior across requests to detect goal drift, data \
             laundering, and other patterns that indicate deviation from intended \
             operation, enabling retrospective accountability.",
            &[
                "Memory poisoning detection with fingerprint tracking",
                "Goal drift detection via behavioral anomaly (EMA)",
                "Cross-request data flow tracking",
            ],
        );
        self.add_requirement(
            "SGP-HA-05",
            MgfDimension::HumanAccountability,
            "Compliance evidence generation",
            "Automatically generate compliance evidence packs for regulatory \
             frameworks including EU AI Act, SOC 2, ISO 42001, and DORA, \
             supporting audit and liability assessments.",
            &[
                "Evidence pack generation (EU AI Act, SOC 2, ISO 42001, DORA)",
                "Zero-knowledge audit proofs (Pedersen + Groth16)",
                "Cross-framework gap analysis",
            ],
        );

        // ── Dimension 3: Technical Controls ─────────────────────────────────
        self.add_requirement(
            "SGP-TC-01",
            MgfDimension::TechnicalControls,
            "Injection attack defense",
            "Detect and block prompt injection attacks including direct injection, \
             indirect injection via tool responses, Unicode evasion techniques, \
             and multimodal injection payloads.",
            &[
                "Aho-Corasick injection scanner with NFKC normalization",
                "Response injection scanning for indirect attacks",
                "Multimodal injection detection (PNG/JPEG/PDF/audio/video)",
            ],
        );
        self.add_requirement(
            "SGP-TC-02",
            MgfDimension::TechnicalControls,
            "Access control and policy enforcement",
            "Enforce granular access control policies on all agent tool invocations, \
             including path-based rules, domain allowlists/blocklists, IP-based \
             restrictions, and attribute-based access control.",
            &[
                "Policy engine with glob/regex/domain matching",
                "ABAC engine with forbid-overrides semantics",
                "Path traversal protection with normalization",
                "DNS rebinding defense with private IP blocking",
            ],
        );
        self.add_requirement(
            "SGP-TC-03",
            MgfDimension::TechnicalControls,
            "Identity verification and authentication",
            "Verify agent and tool identities through cryptographic authentication, \
             including OAuth 2.1/JWT validation, ETDI tool signatures, and \
             agent attestation chains.",
            &[
                "OAuth 2.1/JWT/JWKS validation with audience/scope checking",
                "ETDI tool signatures (Ed25519) with version pinning",
                "Agent identity attestation and DID:PLC binding",
            ],
        );
        self.add_requirement(
            "SGP-TC-04",
            MgfDimension::TechnicalControls,
            "Tool integrity and supply chain security",
            "Verify the integrity of MCP tools and detect manipulation including \
             rug-pull attacks, tool squatting, schema poisoning, and supply chain \
             compromise.",
            &[
                "Tool annotation change detection (rug-pull defense)",
                "Tool squatting detection (Levenshtein + homoglyph)",
                "Schema poisoning detection with lineage tracking",
                "Binary integrity verification (SHA-256)",
            ],
        );
        self.add_requirement(
            "SGP-TC-05",
            MgfDimension::TechnicalControls,
            "Monitoring, logging, and anomaly detection",
            "Implement comprehensive monitoring and logging across all transports \
             with anomaly detection for shadow agents, memory poisoning, behavioral \
             drift, and unauthorized operations.",
            &[
                "Shadow agent detection with bounded tracking",
                "Memory poisoning detection with response fingerprinting",
                "Behavioral anomaly detection (EMA-based)",
                "Audit logging across HTTP/WebSocket/gRPC/stdio/SSE",
            ],
        );

        // ── Dimension 4: End-User Responsibility ────────────────────────────
        self.add_requirement(
            "SGP-ER-01",
            MgfDimension::EndUserResponsibility,
            "Transparency of agent decisions",
            "Provide transparency into agent decision-making through observable \
             verdicts, execution graphs, and detailed audit records that explain \
             why actions were allowed, denied, or escalated.",
            &[
                "Verdict explanations with deny reasons",
                "Execution graph SVG export for decision visualization",
                "Detailed audit entries with metadata and context",
            ],
        );
        self.add_requirement(
            "SGP-ER-02",
            MgfDimension::EndUserResponsibility,
            "Data protection and secret redaction",
            "Protect end-user data by detecting and redacting secrets, PII, and \
             sensitive information in tool parameters, responses, and audit logs, \
             preventing inadvertent data exposure.",
            &[
                "DLP scanning with 5-layer decode (URL/Base64/Unicode/hex/nested)",
                "PII redaction engine with configurable levels",
                "Sensitive key redaction in audit logs",
            ],
        );
        self.add_requirement(
            "SGP-ER-03",
            MgfDimension::EndUserResponsibility,
            "Covert channel and exfiltration prevention",
            "Detect and block covert data exfiltration channels including \
             steganographic techniques, cross-request data laundering, and \
             unauthorized outbound data flows.",
            &[
                "Covert channel detection",
                "Steganography detection in multimodal content",
                "Cross-request data flow tracking",
            ],
        );
        self.add_requirement(
            "SGP-ER-04",
            MgfDimension::EndUserResponsibility,
            "Informed consent and user agency",
            "Support informed consent mechanisms by providing clear notification \
             of agent capabilities, enforcing user-defined constraints, and \
             offering structured approval workflows for sensitive actions.",
            &[
                "RequireApproval verdict for user consent",
                "Elicitation schema validation with injection scanning",
                "Policy templates for user-defined constraints",
            ],
        );
        self.add_requirement(
            "SGP-ER-05",
            MgfDimension::EndUserResponsibility,
            "Grievance and audit review mechanisms",
            "Provide mechanisms for audit review, compliance evidence export, and \
             grievance resolution through tamper-evident logs, cross-framework \
             gap analysis, and exportable compliance evidence packs.",
            &[
                "Audit export (CEF/JSONL/webhook/syslog)",
                "Compliance evidence packs (EU AI Act, SOC 2, DORA)",
                "Cross-framework gap analysis for coverage verification",
            ],
        );
    }

    /// Populate mappings from Vellaveto detections to MGF requirements.
    fn populate_detection_mappings(&mut self) {
        // ── Risk Bounding mappings ──────────────────────────────────────────
        self.map_detection(
            VellavetoDetection::ExcessiveAgency,
            vec!["SGP-RB-01", "SGP-RB-02"],
        );
        self.map_detection(
            VellavetoDetection::WorkflowBudgetExceeded,
            vec!["SGP-RB-01", "SGP-RB-05"],
        );
        self.map_detection(
            VellavetoDetection::CircuitBreakerTriggered,
            vec!["SGP-RB-04"],
        );
        self.map_detection(
            VellavetoDetection::CascadingFailure,
            vec!["SGP-RB-04"],
        );
        self.map_detection(
            VellavetoDetection::RateLimitExceeded,
            vec!["SGP-RB-05"],
        );

        // ── Human Accountability mappings ───────────────────────────────────
        self.map_detection(
            VellavetoDetection::DataLaundering,
            vec!["SGP-HA-04"],
        );
        self.map_detection(
            VellavetoDetection::GoalDrift,
            vec!["SGP-HA-04"],
        );
        self.map_detection(
            VellavetoDetection::MemoryInjection,
            vec!["SGP-HA-04"],
        );

        // ── Technical Controls mappings ─────────────────────────────────────
        self.map_detection(
            VellavetoDetection::PromptInjection,
            vec!["SGP-TC-01"],
        );
        self.map_detection(
            VellavetoDetection::IndirectInjection,
            vec!["SGP-TC-01"],
        );
        self.map_detection(
            VellavetoDetection::UnicodeManipulation,
            vec!["SGP-TC-01"],
        );
        self.map_detection(
            VellavetoDetection::DelimiterInjection,
            vec!["SGP-TC-01"],
        );
        self.map_detection(
            VellavetoDetection::PathTraversal,
            vec!["SGP-TC-02"],
        );
        self.map_detection(
            VellavetoDetection::DnsRebinding,
            vec!["SGP-TC-02"],
        );
        self.map_detection(
            VellavetoDetection::UnauthorizedToolAccess,
            vec!["SGP-TC-02"],
        );
        self.map_detection(
            VellavetoDetection::ToolAnnotationChange,
            vec!["SGP-TC-04"],
        );
        self.map_detection(
            VellavetoDetection::ToolSquatting,
            vec!["SGP-TC-04"],
        );
        self.map_detection(
            VellavetoDetection::SchemaPoisoning,
            vec!["SGP-TC-04"],
        );
        self.map_detection(
            VellavetoDetection::ToolShadowing,
            vec!["SGP-TC-04"],
        );
        self.map_detection(
            VellavetoDetection::ShadowAgent,
            vec!["SGP-TC-05"],
        );

        // ── End-User Responsibility mappings ────────────────────────────────
        self.map_detection(
            VellavetoDetection::SecretsInOutput,
            vec!["SGP-ER-02"],
        );
        self.map_detection(
            VellavetoDetection::CovertChannel,
            vec!["SGP-ER-03"],
        );
        self.map_detection(
            VellavetoDetection::Steganography,
            vec!["SGP-ER-03"],
        );

        // ── Cross-dimension mappings ────────────────────────────────────────
        // ConfusedDeputy spans risk bounding (escalation) and technical controls
        self.map_detection(
            VellavetoDetection::ConfusedDeputy,
            vec!["SGP-RB-03", "SGP-TC-03"],
        );
        // PrivilegeEscalation spans risk bounding and technical controls
        self.map_detection(
            VellavetoDetection::PrivilegeEscalation,
            vec!["SGP-RB-02", "SGP-TC-03"],
        );
        // UnauthorizedDelegation maps to identity and accountability
        self.map_detection(
            VellavetoDetection::UnauthorizedDelegation,
            vec!["SGP-TC-03", "SGP-HA-02"],
        );
        // SecondOrderInjection maps to both injection defense and monitoring
        self.map_detection(
            VellavetoDetection::SecondOrderInjection,
            vec!["SGP-TC-01", "SGP-TC-05"],
        );
        // TokenSmuggling maps to authentication controls
        self.map_detection(
            VellavetoDetection::TokenSmuggling,
            vec!["SGP-TC-03"],
        );
        // ContextFlooding maps to risk bounding (resource constraints)
        self.map_detection(
            VellavetoDetection::ContextFlooding,
            vec!["SGP-RB-05"],
        );
        // GlitchToken maps to injection defense
        self.map_detection(
            VellavetoDetection::GlitchToken,
            vec!["SGP-TC-01"],
        );
        // SamplingAttack maps to technical controls (monitoring)
        self.map_detection(
            VellavetoDetection::SamplingAttack,
            vec!["SGP-TC-05"],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = SingaporeMgfRegistry::new();
        assert!(
            registry.total_requirements() > 0,
            "Registry should have requirements"
        );
        assert!(
            !registry.detection_mappings.is_empty(),
            "Registry should have detection mappings"
        );
    }

    #[test]
    fn test_all_4_dimensions_populated() {
        let registry = SingaporeMgfRegistry::new();
        let dimensions = [
            MgfDimension::RiskBounding,
            MgfDimension::HumanAccountability,
            MgfDimension::TechnicalControls,
            MgfDimension::EndUserResponsibility,
        ];
        for dim in &dimensions {
            let reqs = registry.get_requirements_for_dimension(*dim);
            assert!(
                !reqs.is_empty(),
                "Dimension {} should have at least one requirement",
                dim
            );
        }
    }

    #[test]
    fn test_5_requirements_per_dimension() {
        let registry = SingaporeMgfRegistry::new();
        let dimensions = [
            MgfDimension::RiskBounding,
            MgfDimension::HumanAccountability,
            MgfDimension::TechnicalControls,
            MgfDimension::EndUserResponsibility,
        ];
        for dim in &dimensions {
            let reqs = registry.get_requirements_for_dimension(*dim);
            assert_eq!(
                reqs.len(),
                5,
                "Dimension {} should have exactly 5 requirements, got {}",
                dim,
                reqs.len(),
            );
        }
    }

    #[test]
    fn test_total_requirements_count() {
        let registry = SingaporeMgfRegistry::new();
        // 5 per dimension * 4 dimensions = 20
        assert_eq!(
            registry.total_requirements(),
            20,
            "Expected 20 requirements across 4 dimensions"
        );
    }

    #[test]
    fn test_requirement_lookup_by_id() {
        let registry = SingaporeMgfRegistry::new();
        let req = registry.get_requirement("SGP-RB-01");
        assert!(req.is_some(), "SGP-RB-01 should exist");
        let r = req.expect("requirement should exist");
        assert_eq!(r.category, MgfDimension::RiskBounding);
        assert!(!r.name.is_empty());
        assert!(!r.mitigations.is_empty());
    }

    #[test]
    fn test_all_requirement_ids_valid_format() {
        let registry = SingaporeMgfRegistry::new();
        for (id, req) in &registry.requirements {
            assert!(
                id.starts_with("SGP-"),
                "Requirement ID '{}' should start with 'SGP-'",
                id
            );
            assert_eq!(id, &req.id, "Requirement ID key/value mismatch");
            assert!(
                id.len() <= MAX_REQUIREMENT_ID_LEN,
                "Requirement ID '{}' exceeds max length",
                id
            );
        }
    }

    #[test]
    fn test_all_requirements_have_mitigations() {
        let registry = SingaporeMgfRegistry::new();
        for (id, req) in &registry.requirements {
            assert!(
                !req.mitigations.is_empty(),
                "Requirement {} should have at least one mitigation",
                id
            );
        }
    }

    #[test]
    fn test_detection_to_requirement_mapping() {
        let registry = SingaporeMgfRegistry::new();
        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::PromptInjection);
        assert!(
            !reqs.is_empty(),
            "PromptInjection should map to at least one requirement"
        );
        assert!(
            reqs.iter().any(|r| r.id == "SGP-TC-01"),
            "PromptInjection should map to SGP-TC-01"
        );
    }

    #[test]
    fn test_requirement_to_detection_mapping() {
        let registry = SingaporeMgfRegistry::new();
        let detections = registry.get_detections_for_requirement("SGP-TC-01");
        assert!(
            !detections.is_empty(),
            "SGP-TC-01 should be mapped from at least one detection"
        );
        assert!(
            detections.contains(&VellavetoDetection::PromptInjection),
            "SGP-TC-01 should be mapped from PromptInjection"
        );
    }

    #[test]
    fn test_risk_bounding_detection_mappings() {
        let registry = SingaporeMgfRegistry::new();

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::ExcessiveAgency);
        assert!(reqs.iter().any(|r| r.id.starts_with("SGP-RB-")));

        let reqs = registry
            .get_requirements_for_detection(VellavetoDetection::WorkflowBudgetExceeded);
        assert!(reqs.iter().any(|r| r.id.starts_with("SGP-RB-")));

        let reqs = registry
            .get_requirements_for_detection(VellavetoDetection::CircuitBreakerTriggered);
        assert!(reqs.iter().any(|r| r.id == "SGP-RB-04"));

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::CascadingFailure);
        assert!(reqs.iter().any(|r| r.id == "SGP-RB-04"));
    }

    #[test]
    fn test_technical_controls_detection_mappings() {
        let registry = SingaporeMgfRegistry::new();

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::PathTraversal);
        assert!(reqs.iter().any(|r| r.id == "SGP-TC-02"));

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::DnsRebinding);
        assert!(reqs.iter().any(|r| r.id == "SGP-TC-02"));

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::ToolAnnotationChange);
        assert!(reqs.iter().any(|r| r.id == "SGP-TC-04"));

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::ToolSquatting);
        assert!(reqs.iter().any(|r| r.id == "SGP-TC-04"));

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::ShadowAgent);
        assert!(reqs.iter().any(|r| r.id == "SGP-TC-05"));
    }

    #[test]
    fn test_end_user_detection_mappings() {
        let registry = SingaporeMgfRegistry::new();

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::SecretsInOutput);
        assert!(reqs.iter().any(|r| r.id == "SGP-ER-02"));

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::CovertChannel);
        assert!(reqs.iter().any(|r| r.id == "SGP-ER-03"));
    }

    #[test]
    fn test_human_accountability_detection_mappings() {
        let registry = SingaporeMgfRegistry::new();

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::DataLaundering);
        assert!(reqs.iter().any(|r| r.id == "SGP-HA-04"));

        let reqs =
            registry.get_requirements_for_detection(VellavetoDetection::GoalDrift);
        assert!(reqs.iter().any(|r| r.id == "SGP-HA-04"));
    }

    #[test]
    fn test_coverage_report_generation() {
        let registry = SingaporeMgfRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(report.total_dimensions, 4);
        assert_eq!(report.total_requirements, 20);
        assert!(report.coverage_percent > 0.0);
        assert!(!report.covered_requirements.is_empty());
        assert!(!report.dimension_coverage.is_empty());
        assert!(!report.requirement_matrix.is_empty());
    }

    #[test]
    fn test_full_coverage() {
        let registry = SingaporeMgfRegistry::new();
        let report = registry.generate_coverage_report();

        // All 20 requirements should be covered (all have mitigations)
        assert_eq!(
            report.covered_requirements.len(),
            report.total_requirements,
            "All {} requirements should be covered, but only {} are. Uncovered: {:?}",
            report.total_requirements,
            report.covered_requirements.len(),
            report.uncovered_requirements,
        );
        assert!(
            (report.coverage_percent - 100.0).abs() < 0.01,
            "Coverage should be 100%, got {:.1}%",
            report.coverage_percent
        );
    }

    #[test]
    fn test_all_dimensions_covered() {
        let registry = SingaporeMgfRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(
            report.covered_dimensions, 4,
            "All 4 dimensions should be fully covered"
        );
        assert_eq!(report.dimension_coverage.len(), 4);
        for dc in &report.dimension_coverage {
            assert!(
                dc.total_requirements > 0,
                "Dimension {} should have requirements",
                dc.dimension_name
            );
            assert!(
                (dc.coverage_percent - 100.0).abs() < 0.01,
                "Dimension {} should have 100% coverage, got {:.1}%",
                dc.dimension_name,
                dc.coverage_percent
            );
        }
    }

    #[test]
    fn test_requirement_matrix_sorted() {
        let registry = SingaporeMgfRegistry::new();
        let report = registry.generate_coverage_report();

        for window in report.requirement_matrix.windows(2) {
            assert!(
                window[0].id <= window[1].id,
                "Requirement matrix should be sorted: {} > {}",
                window[0].id,
                window[1].id
            );
        }
    }

    #[test]
    fn test_requirement_matrix_count() {
        let registry = SingaporeMgfRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(
            report.requirement_matrix.len(),
            20,
            "Requirement matrix should have 20 rows"
        );
    }

    #[test]
    fn test_coverage_report_string() {
        let registry = SingaporeMgfRegistry::new();
        let report = registry.generate_coverage_report();
        let report_str = report.to_report_string();

        assert!(report_str.contains("Singapore MGF for Agentic AI"));
        assert!(report_str.contains("Coverage:"));
        assert!(report_str.contains("Dimension Breakdown:"));
        assert!(report_str.contains("Risk Bounding"));
        assert!(report_str.contains("Human Accountability"));
        assert!(report_str.contains("Technical Controls"));
        assert!(report_str.contains("End-User Responsibility"));
    }

    #[test]
    fn test_dimension_display() {
        assert_eq!(
            format!("{}", MgfDimension::RiskBounding),
            "Risk Bounding"
        );
        assert_eq!(
            format!("{}", MgfDimension::HumanAccountability),
            "Human Accountability"
        );
        assert_eq!(
            format!("{}", MgfDimension::TechnicalControls),
            "Technical Controls"
        );
        assert_eq!(
            format!("{}", MgfDimension::EndUserResponsibility),
            "End-User Responsibility"
        );
    }

    #[test]
    fn test_serde_roundtrip_report() {
        let registry = SingaporeMgfRegistry::new();
        let report = registry.generate_coverage_report();

        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: MgfCoverageReport =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(deserialized.total_dimensions, report.total_dimensions);
        assert_eq!(deserialized.total_requirements, report.total_requirements);
        assert_eq!(
            deserialized.dimension_coverage.len(),
            report.dimension_coverage.len()
        );
        assert_eq!(
            deserialized.requirement_matrix.len(),
            report.requirement_matrix.len()
        );
    }

    #[test]
    fn test_serde_roundtrip_requirement() {
        let req = MgfRequirement {
            id: "SGP-RB-01".to_string(),
            category: MgfDimension::RiskBounding,
            name: "Test Requirement".to_string(),
            description: "Test description".to_string(),
            mitigations: vec!["m1".to_string(), "m2".to_string()],
        };
        let json = serde_json::to_string(&req).expect("serialize should succeed");
        let deserialized: MgfRequirement =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.id, "SGP-RB-01");
        assert_eq!(deserialized.category, MgfDimension::RiskBounding);
    }

    #[test]
    fn test_serde_deny_unknown_fields() {
        let json = r#"{"id":"X","category":"RiskBounding","name":"N","description":"D","mitigations":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<MgfRequirement>(json);
        assert!(result.is_err(), "Should reject unknown fields");
    }

    #[test]
    fn test_default_trait() {
        let registry = SingaporeMgfRegistry::default();
        assert_eq!(registry.total_requirements(), 20);
    }

    #[test]
    fn test_no_duplicate_requirement_ids() {
        let registry = SingaporeMgfRegistry::new();
        let mut seen = std::collections::HashSet::new();
        for id in registry.requirements.keys() {
            assert!(
                seen.insert(id.clone()),
                "Duplicate requirement ID: {}",
                id
            );
        }
    }

    #[test]
    fn test_detection_mappings_reference_valid_requirements() {
        let registry = SingaporeMgfRegistry::new();
        for (detection, req_ids) in &registry.detection_mappings {
            for id in req_ids {
                assert!(
                    registry.requirements.contains_key(id),
                    "Detection {:?} references non-existent requirement '{}'",
                    detection,
                    id
                );
            }
        }
    }

    // ── Validate() tests ────────────────────────────────────────────────────

    #[test]
    fn test_report_validate_passes_for_valid_report() {
        let registry = SingaporeMgfRegistry::new();
        let report = registry.generate_coverage_report();
        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_report_validate_rejects_nan_coverage() {
        let registry = SingaporeMgfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.coverage_percent = f32::NAN;
        let err = report.validate().unwrap_err();
        assert!(err.contains("coverage_percent"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_negative_coverage() {
        let registry = SingaporeMgfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.coverage_percent = -1.0;
        let err = report.validate().unwrap_err();
        assert!(err.contains("coverage_percent"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_over_100_coverage() {
        let registry = SingaporeMgfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.coverage_percent = 101.0;
        let err = report.validate().unwrap_err();
        assert!(err.contains("coverage_percent"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_infinity_coverage() {
        let registry = SingaporeMgfRegistry::new();
        let mut report = registry.generate_coverage_report();
        report.coverage_percent = f32::INFINITY;
        let err = report.validate().unwrap_err();
        assert!(err.contains("coverage_percent"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_nan_dimension_coverage() {
        let registry = SingaporeMgfRegistry::new();
        let mut report = registry.generate_coverage_report();
        if let Some(dc) = report.dimension_coverage.first_mut() {
            dc.coverage_percent = f32::NAN;
        }
        let err = report.validate().unwrap_err();
        assert!(err.contains("dimension_coverage"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_oversized_matrix() {
        let registry = SingaporeMgfRegistry::new();
        let mut report = registry.generate_coverage_report();
        // Overflow the matrix beyond MAX_MGF_REQUIREMENTS
        for i in 0..=MAX_MGF_REQUIREMENTS {
            report.requirement_matrix.push(RequirementMatrixRow {
                id: format!("OVERFLOW-{}", i),
                dimension: MgfDimension::RiskBounding,
                name: "overflow".to_string(),
                covered: false,
                mitigations: vec![],
            });
        }
        let err = report.validate().unwrap_err();
        assert!(err.contains("requirement_matrix"), "err: {}", err);
    }

    #[test]
    fn test_report_validate_rejects_oversized_mitigations() {
        let registry = SingaporeMgfRegistry::new();
        let mut report = registry.generate_coverage_report();
        if let Some(row) = report.requirement_matrix.first_mut() {
            row.mitigations = (0..=MAX_MITIGATIONS_PER_REQUIREMENT)
                .map(|i| format!("mit-{}", i))
                .collect();
        }
        let err = report.validate().unwrap_err();
        assert!(err.contains("mitigations"), "err: {}", err);
    }
}
