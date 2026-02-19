//! OWASP Agentic Security Index (ASI) Compliance Registry.
//!
//! Maps Vellaveto detection capabilities to the OWASP Top 10 for Agentic
//! Applications (2026 edition). Covers ASI01–ASI10 categories.
//!
//! # Usage
//!
//! ```
//! use vellaveto_audit::owasp_asi::OwaspAsiRegistry;
//!
//! let registry = OwaspAsiRegistry::new();
//! let report = registry.generate_coverage_report();
//! assert!(report.coverage_percent >= 90.0);
//! ```
//!
//! Reference: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::atlas::VellavetoDetection;

/// OWASP Agentic Security Index categories (ASI01–ASI10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AsiCategory {
    /// ASI01: Prompt Injection
    Asi01,
    /// ASI02: Confused Deputy Problem
    Asi02,
    /// ASI03: Tool Manipulation
    Asi03,
    /// ASI04: Insufficient Access Controls
    Asi04,
    /// ASI05: Insecure Tool Output Handling
    Asi05,
    /// ASI06: Memory Poisoning
    Asi06,
    /// ASI07: Excessive Agency
    Asi07,
    /// ASI08: Cascading Failures
    Asi08,
    /// ASI09: Trust Boundary Violations
    Asi09,
    /// ASI10: Shadow AI/Agent Operations
    Asi10,
}

impl std::fmt::Display for AsiCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Asi01 => write!(f, "ASI01: Prompt Injection"),
            Self::Asi02 => write!(f, "ASI02: Confused Deputy Problem"),
            Self::Asi03 => write!(f, "ASI03: Tool Manipulation"),
            Self::Asi04 => write!(f, "ASI04: Insufficient Access Controls"),
            Self::Asi05 => write!(f, "ASI05: Insecure Tool Output Handling"),
            Self::Asi06 => write!(f, "ASI06: Memory Poisoning"),
            Self::Asi07 => write!(f, "ASI07: Excessive Agency"),
            Self::Asi08 => write!(f, "ASI08: Cascading Failures"),
            Self::Asi09 => write!(f, "ASI09: Trust Boundary Violations"),
            Self::Asi10 => write!(f, "ASI10: Shadow AI/Agent Operations"),
        }
    }
}

/// A single ASI control/mitigation within a category.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsiControl {
    /// Control identifier (e.g., "ASI01-C01").
    pub id: String,
    /// Parent category.
    pub category: AsiCategory,
    /// Human-readable name.
    pub name: String,
    /// Description of the control.
    pub description: String,
    /// Vellaveto capabilities that implement this control.
    pub vellaveto_mitigations: Vec<String>,
}

/// Per-category coverage breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryCoverage {
    /// ASI category.
    pub category: AsiCategory,
    /// Category display name.
    pub category_name: String,
    /// Total controls in this category.
    pub total_controls: usize,
    /// Controls with at least one Vellaveto mitigation.
    pub covered_controls: usize,
    /// Coverage percentage for this category.
    pub coverage_percent: f32,
}

/// OWASP ASI coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsiCoverageReport {
    /// Report generation timestamp (RFC 3339).
    pub generated_at: String,
    /// Total ASI categories (10).
    pub total_categories: usize,
    /// Categories with full coverage.
    pub covered_categories: usize,
    /// Total controls across all categories.
    pub total_controls: usize,
    /// Controls with at least one Vellaveto mitigation.
    pub covered_controls: usize,
    /// Overall coverage percentage.
    pub coverage_percent: f32,
    /// Per-category breakdown.
    pub category_coverage: Vec<CategoryCoverage>,
    /// Coverage matrix: one row per control.
    pub control_matrix: Vec<ControlMatrixRow>,
}

/// A single row in the control coverage matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlMatrixRow {
    /// Control ID.
    pub id: String,
    /// Parent category.
    pub category: AsiCategory,
    /// Control name.
    pub name: String,
    /// Whether this control is covered.
    pub covered: bool,
    /// Vellaveto mitigations (empty if uncovered).
    pub mitigations: Vec<String>,
}

/// OWASP ASI compliance registry.
///
/// Maps all 10 ASI categories and their controls to Vellaveto detection
/// capabilities, generating coverage reports for compliance dashboards.
pub struct OwaspAsiRegistry {
    /// All controls, keyed by control ID.
    controls: HashMap<String, AsiControl>,
    /// Detection-to-control mappings.
    detection_mappings: HashMap<VellavetoDetection, Vec<String>>,
}

impl Default for OwaspAsiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OwaspAsiRegistry {
    /// Create a new registry populated with all ASI controls and mappings.
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
    pub fn get_control(&self, id: &str) -> Option<&AsiControl> {
        self.controls.get(id)
    }

    /// Get all controls for a category.
    pub fn get_controls_for_category(&self, category: AsiCategory) -> Vec<&AsiControl> {
        self.controls
            .values()
            .filter(|c| c.category == category)
            .collect()
    }

    /// Get all controls mapped to a detection type.
    pub fn get_controls_for_detection(
        &self,
        detection: VellavetoDetection,
    ) -> Vec<&AsiControl> {
        self.detection_mappings
            .get(&detection)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.controls.get(id))
                    .collect()
            })
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

    /// Total number of controls.
    pub fn total_controls(&self) -> usize {
        self.controls.len()
    }

    /// Generate a coverage report.
    pub fn generate_coverage_report(&self) -> AsiCoverageReport {
        // Collect covered control IDs from detection mappings
        let mut covered_ids: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for ids in self.detection_mappings.values() {
            for id in ids {
                covered_ids.insert(id.as_str());
            }
        }
        // Also count controls with non-empty mitigations (structural coverage)
        for (id, control) in &self.controls {
            if !control.vellaveto_mitigations.is_empty() {
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

        // Per-category breakdown
        let categories = [
            AsiCategory::Asi01,
            AsiCategory::Asi02,
            AsiCategory::Asi03,
            AsiCategory::Asi04,
            AsiCategory::Asi05,
            AsiCategory::Asi06,
            AsiCategory::Asi07,
            AsiCategory::Asi08,
            AsiCategory::Asi09,
            AsiCategory::Asi10,
        ];

        let mut category_coverage = Vec::new();
        let mut covered_categories = 0usize;

        for cat in &categories {
            let cat_controls: Vec<&AsiControl> = self
                .controls
                .values()
                .filter(|c| c.category == *cat)
                .collect();
            let cat_total = cat_controls.len();
            let cat_covered = cat_controls
                .iter()
                .filter(|c| covered_ids.contains(c.id.as_str()))
                .count();
            let cat_pct = if cat_total > 0 {
                (cat_covered as f32 / cat_total as f32) * 100.0
            } else {
                0.0
            };
            if cat_covered == cat_total && cat_total > 0 {
                covered_categories += 1;
            }
            category_coverage.push(CategoryCoverage {
                category: *cat,
                category_name: cat.to_string(),
                total_controls: cat_total,
                covered_controls: cat_covered,
                coverage_percent: cat_pct,
            });
        }

        // Build control matrix (sorted by ID)
        let mut matrix: Vec<ControlMatrixRow> = self
            .controls
            .values()
            .map(|c| ControlMatrixRow {
                id: c.id.clone(),
                category: c.category,
                name: c.name.clone(),
                covered: covered_ids.contains(c.id.as_str()),
                mitigations: c.vellaveto_mitigations.clone(),
            })
            .collect();
        matrix.sort_by(|a, b| a.id.cmp(&b.id));

        AsiCoverageReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_categories: categories.len(),
            covered_categories,
            total_controls,
            covered_controls: covered_count,
            coverage_percent,
            category_coverage,
            control_matrix: matrix,
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────

    fn add_control(
        &mut self,
        id: &str,
        category: AsiCategory,
        name: &str,
        description: &str,
        mitigations: &[&str],
    ) {
        self.controls.insert(
            id.to_string(),
            AsiControl {
                id: id.to_string(),
                category,
                name: name.to_string(),
                description: description.to_string(),
                vellaveto_mitigations: mitigations.iter().map(|s| s.to_string()).collect(),
            },
        );
    }

    fn map_detection(&mut self, detection: VellavetoDetection, control_ids: Vec<&str>) {
        self.detection_mappings.insert(
            detection,
            control_ids.iter().map(|s| s.to_string()).collect(),
        );
    }

    /// Populate all ASI controls across 10 categories.
    fn populate_controls(&mut self) {
        // ── ASI01: Prompt Injection ──────────────────────────────────────
        self.add_control(
            "ASI01-C01",
            AsiCategory::Asi01,
            "Direct injection detection",
            "Detect and block direct prompt injection attempts in user input",
            &[
                "Aho-Corasick injection scanner",
                "NFKC Unicode normalization",
                "Whitespace-normalized pattern matching",
            ],
        );
        self.add_control(
            "ASI01-C02",
            AsiCategory::Asi01,
            "Indirect injection detection",
            "Detect prompt injection payloads embedded in tool responses",
            &[
                "Response injection scanning",
                "Tool description scanning for hidden payloads",
            ],
        );
        self.add_control(
            "ASI01-C03",
            AsiCategory::Asi01,
            "Multimodal injection detection",
            "Detect injection payloads in images, audio, and video",
            &[
                "PNG/JPEG metadata extraction",
                "PDF content inspection",
                "WAV/MP3 tag parsing",
                "MP4/WebM metadata extraction",
                "Steganography detection",
            ],
        );
        self.add_control(
            "ASI01-C04",
            AsiCategory::Asi01,
            "Semantic injection detection",
            "Detect semantically disguised injection using TF-IDF analysis",
            &[
                "TF-IDF semantic analysis",
                "Semantic guardrails (LLM-based)",
            ],
        );

        // ── ASI02: Confused Deputy Problem ──────────────────────────────
        self.add_control(
            "ASI02-C01",
            AsiCategory::Asi02,
            "Delegation chain validation",
            "Validate and limit delegation chains to prevent confused deputy attacks",
            &[
                "Deputy validator with max_delegation_depth",
                "HMAC-signed X-MCP-Call-Chain entries",
                "Self-delegation rejection",
            ],
        );
        self.add_control(
            "ASI02-C02",
            AsiCategory::Asi02,
            "Capability-based access control",
            "Enforce capability tokens with delegation constraints",
            &[
                "Capability delegation tokens",
                "Temporal ordering validation",
                "Bounded delegation depth",
            ],
        );
        self.add_control(
            "ASI02-C03",
            AsiCategory::Asi02,
            "Identity attestation",
            "Verify agent identity through attestation chains",
            &[
                "Agent identity attestation (ETDI)",
                "DID:PLC identity binding",
                "Identity federation with JWKS/OIDC",
            ],
        );

        // ── ASI03: Tool Manipulation ────────────────────────────────────
        self.add_control(
            "ASI03-C01",
            AsiCategory::Asi03,
            "Tool rug-pull detection",
            "Detect runtime changes to tool annotations after initial tools/list",
            &[
                "Tool annotation change detection (rug-pull)",
                "Flagged tool blocking across all transports",
            ],
        );
        self.add_control(
            "ASI03-C02",
            AsiCategory::Asi03,
            "Tool squatting defense",
            "Detect tool names that are deceptively similar to legitimate tools",
            &[
                "Levenshtein distance name similarity",
                "Homoglyph detection (Unicode confusables)",
                "Tool registry with trust scoring",
            ],
        );
        self.add_control(
            "ASI03-C03",
            AsiCategory::Asi03,
            "Schema poisoning detection",
            "Detect unexpected mutations in tool schemas over time",
            &[
                "Schema lineage tracker",
                "Mutation threshold alerting",
                "Minimum observation baseline",
            ],
        );
        self.add_control(
            "ASI03-C04",
            AsiCategory::Asi03,
            "Tool version pinning",
            "Cryptographic verification of tool integrity via ETDI",
            &[
                "ETDI tool signatures (Ed25519)",
                "Rekor transparency log integration",
                "Version pinning validation",
            ],
        );

        // ── ASI04: Insufficient Access Controls ─────────────────────────
        self.add_control(
            "ASI04-C01",
            AsiCategory::Asi04,
            "Policy-based access control",
            "Enforce granular policies on tool invocations with path and domain rules",
            &[
                "Policy engine with glob/regex/domain matching",
                "Path traversal protection",
                "Fail-closed evaluation",
            ],
        );
        self.add_control(
            "ASI04-C02",
            AsiCategory::Asi04,
            "ABAC engine",
            "Attribute-based access control with forbid-overrides",
            &[
                "ABAC engine with Cedar-style evaluation",
                "Forbid-overrides semantics",
                "IDNA domain normalization",
            ],
        );
        self.add_control(
            "ASI04-C03",
            AsiCategory::Asi04,
            "Approval workflow",
            "Human-in-the-loop approval for sensitive operations",
            &[
                "RequireApproval verdict type",
                "Approval store with dedup and expiry",
                "Self-approval prevention (homoglyph-aware)",
            ],
        );
        self.add_control(
            "ASI04-C04",
            AsiCategory::Asi04,
            "OAuth/JWT enforcement",
            "Validate OAuth 2.1 tokens with scope and audience checking",
            &[
                "OAuth 2.1/JWT/JWKS validation",
                "Token expiry checking across all transports",
                "RFC 8707 resource indicators",
            ],
        );

        // ── ASI05: Insecure Tool Output Handling ────────────────────────
        self.add_control(
            "ASI05-C01",
            AsiCategory::Asi05,
            "DLP scanning",
            "Scan tool parameters and responses for secrets and sensitive data",
            &[
                "5-layer decode DLP (URL/Base64/Unicode/hex/nested)",
                "Parameter and response DLP scanning",
                "Configurable pattern sets",
            ],
        );
        self.add_control(
            "ASI05-C02",
            AsiCategory::Asi05,
            "Output schema validation",
            "Validate tool output against registered JSON schemas",
            &[
                "OutputSchemaRegistry with per-tool schemas",
                "structuredContent validation",
                "Schema violation blocking (configurable)",
            ],
        );
        self.add_control(
            "ASI05-C03",
            AsiCategory::Asi05,
            "Response redaction",
            "Redact sensitive data from audit logs and tool responses",
            &[
                "PII redaction engine",
                "Configurable redaction levels",
                "Custom Debug impls on security types",
            ],
        );

        // ── ASI06: Memory Poisoning ─────────────────────────────────────
        self.add_control(
            "ASI06-C01",
            AsiCategory::Asi06,
            "Memory poisoning detection",
            "Detect replayed response data in subsequent tool call parameters",
            &[
                "Memory tracker with response fingerprinting",
                "Cross-request data flow tracking",
                "Tainted response exclusion from tracker",
            ],
        );
        self.add_control(
            "ASI06-C02",
            AsiCategory::Asi06,
            "Goal drift detection",
            "Detect agent goal drift through behavioral analysis",
            &[
                "Goal tracker with intent chain analysis",
                "Behavioral anomaly detection (EMA)",
                "Trust decay on corrupt timestamps",
            ],
        );
        self.add_control(
            "ASI06-C03",
            AsiCategory::Asi06,
            "Context integrity",
            "Ensure context state cannot be tampered with across requests",
            &[
                "StatelessContextBlob with HMAC-SHA256",
                "Session guard with violation tracking",
                "Nonce replay detection",
            ],
        );

        // ── ASI07: Excessive Agency ─────────────────────────────────────
        self.add_control(
            "ASI07-C01",
            AsiCategory::Asi07,
            "Least-agency enforcement",
            "Track and enforce minimum required permissions for each agent",
            &[
                "LeastAgencyTracker with auto-revocation",
                "Permission usage monitoring",
                "Unused permission reporting",
            ],
        );
        self.add_control(
            "ASI07-C02",
            AsiCategory::Asi07,
            "Workflow-level constraints",
            "Enforce DAG-based tool transition rules and forbidden sequences",
            &[
                "RequiredActionSequence (ordered/unordered prerequisites)",
                "ForbiddenActionSequence (exfiltration pattern detection)",
                "WorkflowTemplate (DAG with Kahn's algorithm validation)",
            ],
        );
        self.add_control(
            "ASI07-C03",
            AsiCategory::Asi07,
            "Rate and budget limiting",
            "Enforce call limits, time windows, and resource budgets",
            &[
                "Per-session call limits with time windows",
                "Token budget tracking",
                "Rate limiting on all transports",
            ],
        );

        // ── ASI08: Cascading Failures ───────────────────────────────────
        self.add_control(
            "ASI08-C01",
            AsiCategory::Asi08,
            "Circuit breaker",
            "Prevent cascading failures with per-tool circuit breakers",
            &[
                "CircuitBreakerManager (Closed/Open/HalfOpen)",
                "Configurable failure/success thresholds",
                "Exponential backoff",
            ],
        );
        self.add_control(
            "ASI08-C02",
            AsiCategory::Asi08,
            "Cross-transport fallback",
            "Graceful degradation across transport types with health tracking",
            &[
                "TransportHealthTracker per-transport circuit breaker",
                "SmartFallbackChain (gRPC → WS → HTTP → stdio)",
                "Per-attempt and total timeouts",
            ],
        );
        self.add_control(
            "ASI08-C03",
            AsiCategory::Asi08,
            "Multi-agent communication monitoring",
            "Monitor and control agent-to-agent communication patterns",
            &[
                "A2A protocol security",
                "Call chain depth limiting",
                "Agent trust graph with session bounds",
            ],
        );

        // ── ASI09: Trust Boundary Violations ────────────────────────────
        self.add_control(
            "ASI09-C01",
            AsiCategory::Asi09,
            "Network boundary enforcement",
            "Enforce domain allowlists and IP-based policies",
            &[
                "Domain allowlist/blocklist with IDNA normalization",
                "IP-based rules (private IP blocking, CIDR ranges)",
                "DNS rebinding defense",
            ],
        );
        self.add_control(
            "ASI09-C02",
            AsiCategory::Asi09,
            "SSRF prevention",
            "Prevent server-side request forgery through URL validation",
            &[
                "URL host parser with userinfo/@/IPv6 protection",
                "Private IP validation on JWKS URIs",
                "Backend URL scheme validation",
            ],
        );
        self.add_control(
            "ASI09-C03",
            AsiCategory::Asi09,
            "Supply chain verification",
            "Verify integrity of MCP server binaries before execution",
            &[
                "Binary integrity verification (SHA-256)",
                "Environment clearing for child processes",
                "Stdio command injection prevention",
            ],
        );

        // ── ASI10: Shadow AI/Agent Operations ───────────────────────────
        self.add_control(
            "ASI10-C01",
            AsiCategory::Asi10,
            "Shadow AI discovery",
            "Detect unregistered agents and unapproved tools",
            &[
                "ShadowAiDiscoveryEngine (passive detection)",
                "Unregistered agent tracking (max 1000)",
                "Unapproved tool tracking (max 500)",
            ],
        );
        self.add_control(
            "ASI10-C02",
            AsiCategory::Asi10,
            "Shadow agent detection",
            "Detect rogue agents in multi-agent environments",
            &[
                "ShadowAgentDetector with bounded tracking",
                "Agent registration enforcement",
                "Unknown MCP server tracking",
            ],
        );
        self.add_control(
            "ASI10-C03",
            AsiCategory::Asi10,
            "Governance enforcement",
            "Enforce agent registration and tool approval policies",
            &[
                "GovernanceConfig with require_agent_registration",
                "Governance API endpoints",
                "Audit events for shadow AI lifecycle",
            ],
        );
    }

    /// Populate detection-to-control mappings.
    fn populate_detection_mappings(&mut self) {
        // ASI01: Prompt Injection
        self.map_detection(
            VellavetoDetection::PromptInjection,
            vec!["ASI01-C01", "ASI01-C04"],
        );
        self.map_detection(
            VellavetoDetection::IndirectInjection,
            vec!["ASI01-C02"],
        );
        self.map_detection(
            VellavetoDetection::SecondOrderInjection,
            vec!["ASI01-C02"],
        );
        self.map_detection(
            VellavetoDetection::UnicodeManipulation,
            vec!["ASI01-C01"],
        );
        self.map_detection(
            VellavetoDetection::DelimiterInjection,
            vec!["ASI01-C01"],
        );
        self.map_detection(
            VellavetoDetection::Steganography,
            vec!["ASI01-C03"],
        );

        // ASI02: Confused Deputy
        self.map_detection(
            VellavetoDetection::ConfusedDeputy,
            vec!["ASI02-C01"],
        );
        self.map_detection(
            VellavetoDetection::UnauthorizedDelegation,
            vec!["ASI02-C01", "ASI02-C02"],
        );
        self.map_detection(
            VellavetoDetection::PrivilegeEscalation,
            vec!["ASI02-C01", "ASI02-C03"],
        );

        // ASI03: Tool Manipulation
        self.map_detection(
            VellavetoDetection::ToolAnnotationChange,
            vec!["ASI03-C01"],
        );
        self.map_detection(
            VellavetoDetection::ToolSquatting,
            vec!["ASI03-C02"],
        );
        self.map_detection(
            VellavetoDetection::ToolShadowing,
            vec!["ASI03-C02"],
        );
        self.map_detection(
            VellavetoDetection::SchemaPoisoning,
            vec!["ASI03-C03"],
        );

        // ASI05: Insecure Tool Output
        self.map_detection(
            VellavetoDetection::SecretsInOutput,
            vec!["ASI05-C01"],
        );
        self.map_detection(
            VellavetoDetection::CovertChannel,
            vec!["ASI05-C01", "ASI05-C02"],
        );

        // ASI06: Memory Poisoning
        self.map_detection(
            VellavetoDetection::DataLaundering,
            vec!["ASI06-C01"],
        );
        self.map_detection(
            VellavetoDetection::MemoryInjection,
            vec!["ASI06-C01", "ASI06-C03"],
        );
        self.map_detection(
            VellavetoDetection::GoalDrift,
            vec!["ASI06-C02"],
        );

        // ASI07: Excessive Agency
        self.map_detection(
            VellavetoDetection::ExcessiveAgency,
            vec!["ASI07-C01"],
        );
        self.map_detection(
            VellavetoDetection::WorkflowBudgetExceeded,
            vec!["ASI07-C02", "ASI07-C03"],
        );
        self.map_detection(
            VellavetoDetection::UnauthorizedToolAccess,
            vec!["ASI07-C01", "ASI04-C01"],
        );

        // ASI08: Cascading Failures
        self.map_detection(
            VellavetoDetection::CircuitBreakerTriggered,
            vec!["ASI08-C01"],
        );
        self.map_detection(
            VellavetoDetection::CascadingFailure,
            vec!["ASI08-C01", "ASI08-C02"],
        );

        // ASI09: Trust Boundary Violations
        self.map_detection(
            VellavetoDetection::PathTraversal,
            vec!["ASI09-C01"],
        );
        self.map_detection(
            VellavetoDetection::DnsRebinding,
            vec!["ASI09-C01", "ASI09-C02"],
        );

        // ASI10: Shadow AI/Agent Operations
        self.map_detection(
            VellavetoDetection::ShadowAgent,
            vec!["ASI10-C01", "ASI10-C02"],
        );

        // Cross-category: Rate limiting applies to ASI04 and ASI07
        self.map_detection(
            VellavetoDetection::RateLimitExceeded,
            vec!["ASI04-C01", "ASI07-C03"],
        );

        // Cross-category: Token smuggling and context flooding
        self.map_detection(
            VellavetoDetection::TokenSmuggling,
            vec!["ASI01-C01", "ASI09-C01"],
        );
        self.map_detection(
            VellavetoDetection::ContextFlooding,
            vec!["ASI07-C03"],
        );
        self.map_detection(
            VellavetoDetection::GlitchToken,
            vec!["ASI01-C01"],
        );
        self.map_detection(
            VellavetoDetection::SamplingAttack,
            vec!["ASI07-C01"],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = OwaspAsiRegistry::new();
        assert!(
            registry.total_controls() > 0,
            "Registry should have controls"
        );
    }

    #[test]
    fn test_all_10_categories_populated() {
        let registry = OwaspAsiRegistry::new();
        let categories = [
            AsiCategory::Asi01,
            AsiCategory::Asi02,
            AsiCategory::Asi03,
            AsiCategory::Asi04,
            AsiCategory::Asi05,
            AsiCategory::Asi06,
            AsiCategory::Asi07,
            AsiCategory::Asi08,
            AsiCategory::Asi09,
            AsiCategory::Asi10,
        ];
        for cat in &categories {
            let controls = registry.get_controls_for_category(*cat);
            assert!(
                !controls.is_empty(),
                "Category {} should have at least one control",
                cat
            );
        }
    }

    #[test]
    fn test_total_controls_count() {
        let registry = OwaspAsiRegistry::new();
        // 4 + 3 + 4 + 4 + 3 + 3 + 3 + 3 + 3 + 3 = 33
        assert_eq!(
            registry.total_controls(),
            33,
            "Expected 33 controls across 10 categories"
        );
    }

    #[test]
    fn test_control_lookup_by_id() {
        let registry = OwaspAsiRegistry::new();
        let control = registry.get_control("ASI01-C01");
        assert!(control.is_some(), "ASI01-C01 should exist");
        let c = control.unwrap();
        assert_eq!(c.category, AsiCategory::Asi01);
        assert!(!c.name.is_empty());
        assert!(!c.vellaveto_mitigations.is_empty());
    }

    #[test]
    fn test_all_controls_have_mitigations() {
        let registry = OwaspAsiRegistry::new();
        for (id, control) in &registry.controls {
            assert!(
                !control.vellaveto_mitigations.is_empty(),
                "Control {} should have at least one mitigation",
                id
            );
        }
    }

    #[test]
    fn test_detection_to_control_mapping() {
        let registry = OwaspAsiRegistry::new();
        let controls = registry.get_controls_for_detection(VellavetoDetection::PromptInjection);
        assert!(
            !controls.is_empty(),
            "PromptInjection should map to at least one control"
        );
    }

    #[test]
    fn test_control_to_detection_mapping() {
        let registry = OwaspAsiRegistry::new();
        let detections = registry.get_detections_for_control("ASI01-C01");
        assert!(
            !detections.is_empty(),
            "ASI01-C01 should be mapped from at least one detection"
        );
    }

    #[test]
    fn test_coverage_report_generation() {
        let registry = OwaspAsiRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(report.total_categories, 10);
        assert_eq!(report.total_controls, 33);
        assert!(report.covered_controls > 0);
        assert!(report.coverage_percent > 0.0);
        assert!(!report.category_coverage.is_empty());
        assert!(!report.control_matrix.is_empty());
    }

    #[test]
    fn test_full_coverage() {
        let registry = OwaspAsiRegistry::new();
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
            report.covered_categories, 10,
            "All 10 categories should be fully covered"
        );
    }

    #[test]
    fn test_category_coverage_breakdown() {
        let registry = OwaspAsiRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(report.category_coverage.len(), 10);
        for cc in &report.category_coverage {
            assert!(
                cc.total_controls > 0,
                "Category {} should have controls",
                cc.category_name
            );
            assert!(
                (cc.coverage_percent - 100.0).abs() < 0.01,
                "Category {} should have 100% coverage, got {:.1}%",
                cc.category_name,
                cc.coverage_percent
            );
        }
    }

    #[test]
    fn test_control_matrix_sorted() {
        let registry = OwaspAsiRegistry::new();
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
    fn test_serde_roundtrip() {
        let registry = OwaspAsiRegistry::new();
        let report = registry.generate_coverage_report();

        let json = serde_json::to_string(&report).expect("serialize");
        let deserialized: AsiCoverageReport =
            serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.total_controls, report.total_controls);
        assert_eq!(deserialized.covered_controls, report.covered_controls);
        assert_eq!(
            deserialized.category_coverage.len(),
            report.category_coverage.len()
        );
    }

    #[test]
    fn test_category_display() {
        assert_eq!(
            AsiCategory::Asi01.to_string(),
            "ASI01: Prompt Injection"
        );
        assert_eq!(
            AsiCategory::Asi10.to_string(),
            "ASI10: Shadow AI/Agent Operations"
        );
    }

    #[test]
    fn test_no_duplicate_control_ids() {
        let registry = OwaspAsiRegistry::new();
        let mut seen = std::collections::HashSet::new();
        for id in registry.controls.keys() {
            assert!(
                seen.insert(id.clone()),
                "Duplicate control ID: {}",
                id
            );
        }
    }

    #[test]
    fn test_detection_mappings_reference_valid_controls() {
        let registry = OwaspAsiRegistry::new();
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
}
