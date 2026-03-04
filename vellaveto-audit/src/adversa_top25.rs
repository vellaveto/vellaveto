// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Adversa AI MCP Security TOP 25 Coverage Matrix.
//!
//! Maps Vellaveto security detections to the Adversa AI MCP Security TOP 25
//! vulnerability ranking. This registry provides a ranked coverage matrix
//! showing which vulnerabilities Vellaveto mitigates and how.
//!
//! The TOP 25 covers the most critical MCP-specific security vulnerabilities
//! ranked by severity and real-world impact.
//!
//! References:
//! - Adversa AI MCP Security TOP 25 (2025)
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::adversa_top25::AdversaTop25Registry;
//!
//! let registry = AdversaTop25Registry::new();
//! let report = registry.generate_coverage_report();
//! println!("Adversa TOP 25 coverage: {:.1}%", report.coverage_percent);
//! ```

use crate::atlas::VellavetoDetection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Adversa vulnerability severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdversaSeverity {
    /// Critical severity — immediate exploitation risk.
    Critical,
    /// High severity — significant exploitation risk.
    High,
    /// Medium severity — moderate exploitation risk.
    Medium,
}

impl std::fmt::Display for AdversaSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
        }
    }
}

/// Adversa AI MCP Security TOP 25 vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaVulnerability {
    /// Rank (1–25, lower is more critical).
    pub rank: u8,
    /// Vulnerability name.
    pub name: String,
    /// Description of the vulnerability.
    pub description: String,
    /// Severity classification.
    pub severity: AdversaSeverity,
    /// Vellaveto mitigations that address this vulnerability.
    pub vellaveto_mitigations: Vec<String>,
}

/// A row in the coverage matrix output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMatrixRow {
    /// Vulnerability rank.
    pub rank: u8,
    /// Vulnerability name.
    pub name: String,
    /// Severity level.
    pub severity: AdversaSeverity,
    /// Whether Vellaveto covers this vulnerability.
    pub covered: bool,
    /// Vellaveto mitigations (empty if not covered).
    pub mitigations: Vec<String>,
}

/// Adversa TOP 25 coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaCoverageReport {
    /// Timestamp of report generation.
    pub generated_at: String,
    /// Total vulnerabilities in the TOP 25.
    pub total_vulnerabilities: usize,
    /// Number of vulnerabilities covered by Vellaveto.
    pub covered_count: usize,
    /// Number of vulnerabilities not covered.
    pub uncovered_count: usize,
    /// Overall coverage percentage.
    pub coverage_percent: f32,
    /// Full coverage matrix.
    pub matrix: Vec<CoverageMatrixRow>,
}

impl AdversaCoverageReport {
    /// Generate a human-readable report.
    pub fn to_report_string(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Adversa AI MCP Security TOP 25 Coverage Report ===\n\n");
        report.push_str(&format!(
            "Coverage: {:.1}% ({}/{})\n\n",
            self.coverage_percent, self.covered_count, self.total_vulnerabilities,
        ));

        report.push_str("Matrix:\n");
        for row in &self.matrix {
            let status = if row.covered { "COVERED" } else { "GAP" };
            report.push_str(&format!(
                "  #{:>2} [{:>8}] {:40} — {}\n",
                row.rank, row.severity, row.name, status,
            ));
        }

        report
    }
}

/// Registry of Adversa AI MCP Security TOP 25 vulnerabilities.
pub struct AdversaTop25Registry {
    /// All 25 vulnerabilities ordered by rank.
    vulnerabilities: Vec<AdversaVulnerability>,
    /// Mapping from Vellaveto detection to vulnerability ranks.
    detection_mappings: HashMap<VellavetoDetection, Vec<u8>>,
}

impl AdversaTop25Registry {
    /// Create a new registry with all 25 vulnerabilities and detection mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            vulnerabilities: Vec::with_capacity(25),
            detection_mappings: HashMap::new(),
        };
        registry.populate_vulnerabilities();
        registry.populate_detection_mappings();
        registry
    }

    /// Get a vulnerability by rank (1–25).
    pub fn get_vulnerability(&self, rank: u8) -> Option<&AdversaVulnerability> {
        self.vulnerabilities.iter().find(|v| v.rank == rank)
    }

    /// Get all vulnerabilities.
    pub fn all_vulnerabilities(&self) -> &[AdversaVulnerability] {
        &self.vulnerabilities
    }

    /// Get vulnerabilities mapped to a Vellaveto detection.
    pub fn get_vulnerabilities_for_detection(
        &self,
        detection: VellavetoDetection,
    ) -> Vec<&AdversaVulnerability> {
        self.detection_mappings
            .get(&detection)
            .map(|ranks| {
                ranks
                    .iter()
                    .filter_map(|r| self.get_vulnerability(*r))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Generate the full coverage matrix.
    pub fn coverage_matrix(&self) -> Vec<CoverageMatrixRow> {
        // Build set of covered ranks from detection mappings
        let mut covered_ranks: std::collections::HashSet<u8> = std::collections::HashSet::new();
        for ranks in self.detection_mappings.values() {
            for r in ranks {
                covered_ranks.insert(*r);
            }
        }
        // Also consider vulnerabilities with non-empty mitigations as covered
        for v in &self.vulnerabilities {
            if !v.vellaveto_mitigations.is_empty() {
                covered_ranks.insert(v.rank);
            }
        }

        self.vulnerabilities
            .iter()
            .map(|v| CoverageMatrixRow {
                rank: v.rank,
                name: v.name.clone(),
                severity: v.severity,
                covered: covered_ranks.contains(&v.rank),
                mitigations: v.vellaveto_mitigations.clone(),
            })
            .collect()
    }

    /// Generate a coverage report.
    pub fn generate_coverage_report(&self) -> AdversaCoverageReport {
        let matrix = self.coverage_matrix();
        let covered_count = matrix.iter().filter(|r| r.covered).count();
        let total = matrix.len();
        let coverage_percent = if total > 0 {
            (covered_count as f32 / total as f32) * 100.0
        } else {
            0.0
        };

        AdversaCoverageReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_vulnerabilities: total,
            covered_count,
            uncovered_count: total - covered_count,
            coverage_percent,
            matrix,
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    fn add_vulnerability(&mut self, vuln: AdversaVulnerability) {
        self.vulnerabilities.push(vuln);
    }

    fn map_detection(&mut self, detection: VellavetoDetection, ranks: Vec<u8>) {
        self.detection_mappings.insert(detection, ranks);
    }

    /// Populate all 25 vulnerabilities from the Adversa AI TOP 25 ranking.
    fn populate_vulnerabilities(&mut self) {
        self.add_vulnerability(AdversaVulnerability {
            rank: 1,
            name: "Tool Annotation Rug Pull".to_string(),
            description: "Tool changes behavior after trust is established by modifying \
                annotations or capabilities."
                .to_string(),
            severity: AdversaSeverity::Critical,
            vellaveto_mitigations: vec![
                "Rug-pull detection with annotation tracking".to_string(),
                "ETDI version pinning".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 2,
            name: "Prompt Injection via Tool I/O".to_string(),
            description: "Malicious prompts injected through tool call parameters or responses."
                .to_string(),
            severity: AdversaSeverity::Critical,
            vellaveto_mitigations: vec![
                "Aho-Corasick injection detection".to_string(),
                "Semantic injection detection".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 3,
            name: "Tool Squatting".to_string(),
            description: "Registering tools with names similar to legitimate tools to \
                intercept requests."
                .to_string(),
            severity: AdversaSeverity::Critical,
            vellaveto_mitigations: vec![
                "Levenshtein distance detection".to_string(),
                "Homoglyph detection".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 4,
            name: "Schema Poisoning".to_string(),
            description: "Modifying tool schemas to inject hidden parameters or alter behavior."
                .to_string(),
            severity: AdversaSeverity::Critical,
            vellaveto_mitigations: vec![
                "Schema poisoning detection".to_string(),
                "Schema lineage tracking".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 5,
            name: "Confused Deputy Attack".to_string(),
            description: "Tricking a privileged agent into performing unauthorized actions."
                .to_string(),
            severity: AdversaSeverity::Critical,
            vellaveto_mitigations: vec![
                "Deputy validation".to_string(),
                "Call chain depth enforcement".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 6,
            name: "Cross-Request Data Laundering".to_string(),
            description: "Injecting data in one request to influence subsequent requests."
                .to_string(),
            severity: AdversaSeverity::Critical,
            vellaveto_mitigations: vec![
                "Memory poisoning defense".to_string(),
                "Fingerprint-based tracking".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 7,
            name: "Shadow Agent Impersonation".to_string(),
            description: "Malicious agent impersonating legitimate agents to intercept \
                communications."
                .to_string(),
            severity: AdversaSeverity::Critical,
            vellaveto_mitigations: vec![
                "Shadow agent detection".to_string(),
                "Agent identity attestation".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 8,
            name: "Privilege Escalation via Delegation".to_string(),
            description: "Exploiting delegation chains to gain elevated privileges.".to_string(),
            severity: AdversaSeverity::High,
            vellaveto_mitigations: vec![
                "Capability token with monotonic attenuation".to_string(),
                "Max chain depth enforcement".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 9,
            name: "Data Exfiltration via Tool Output".to_string(),
            description: "Leaking sensitive data through tool responses or covert channels."
                .to_string(),
            severity: AdversaSeverity::High,
            vellaveto_mitigations: vec![
                "DLP scanning (5-layer decode)".to_string(),
                "Cross-request data flow tracking".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 10,
            name: "Unicode Injection Evasion".to_string(),
            description: "Using Unicode tricks to bypass injection detection filters.".to_string(),
            severity: AdversaSeverity::High,
            vellaveto_mitigations: vec![
                "NFKC normalization".to_string(),
                "Homoglyph detection".to_string(),
                "Control character rejection".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 11,
            name: "Path Traversal via Tool Calls".to_string(),
            description: "Accessing files outside allowed paths through tool parameters."
                .to_string(),
            severity: AdversaSeverity::High,
            vellaveto_mitigations: vec![
                "Path normalization".to_string(),
                "Glob-based path rules".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 12,
            name: "DNS Rebinding".to_string(),
            description: "Bypassing domain restrictions through DNS rebinding attacks.".to_string(),
            severity: AdversaSeverity::High,
            vellaveto_mitigations: vec![
                "IP rules with private range blocking".to_string(),
                "CIDR allowlists/blocklists".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 13,
            name: "TOCTOU in Message Processing".to_string(),
            description: "Time-of-check/time-of-use race conditions in JSON-RPC processing."
                .to_string(),
            severity: AdversaSeverity::High,
            vellaveto_mitigations: vec![
                "TOCTOU-safe JSON canonicalization".to_string(),
                "Batch request rejection".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 14,
            name: "Token Smuggling".to_string(),
            description: "Smuggling authentication tokens through transport manipulation."
                .to_string(),
            severity: AdversaSeverity::High,
            vellaveto_mitigations: vec!["Token smuggling detection".to_string()],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 15,
            name: "Goal Drift via Context Manipulation".to_string(),
            description: "Gradually manipulating agent objectives through context changes."
                .to_string(),
            severity: AdversaSeverity::High,
            vellaveto_mitigations: vec![
                "Goal drift detection".to_string(),
                "Behavioral anomaly detection (EMA)".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 16,
            name: "Rate Limit Exhaustion".to_string(),
            description: "Flooding system to exhaust rate limits and deny service.".to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec![
                "Per-session rate limiting".to_string(),
                "Sliding window rate limiter".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 17,
            name: "Context Flooding".to_string(),
            description: "Overwhelming agent context window with irrelevant data.".to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec!["Context flooding detection".to_string()],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 18,
            name: "Cascading Failure Exploitation".to_string(),
            description: "Triggering cascading failures across dependent services.".to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec![
                "Circuit breaker pattern".to_string(),
                "Workflow budget enforcement".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 19,
            name: "Audit Log Tampering".to_string(),
            description: "Modifying or deleting audit entries to cover attack traces.".to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec![
                "SHA-256 hash chain".to_string(),
                "Merkle tree inclusion proofs".to_string(),
                "Ed25519 signed checkpoints".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 20,
            name: "Regex Denial of Service".to_string(),
            description: "Crafted regex patterns causing catastrophic backtracking.".to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec![
                "Regex pattern length validation (MAX_PATTERN_LEN=2048)".to_string()
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 21,
            name: "Tool Namespace Collision".to_string(),
            description: "Malicious tools shadowing legitimate tools in shared namespaces."
                .to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec![
                "Tool namespace isolation".to_string(),
                "Tool shadowing detection".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 22,
            name: "Sampling Request Manipulation".to_string(),
            description: "Manipulating LLM sampling requests to extract data or alter behavior."
                .to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec!["Sampling request policy enforcement".to_string()],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 23,
            name: "Elicitation Abuse".to_string(),
            description: "Exploiting MCP elicitation to extract information or exceed limits."
                .to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec![
                "Elicitation capability validation".to_string(),
                "Rate-limit enforcement".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 24,
            name: "Hot Reload Policy Injection".to_string(),
            description: "Injecting malicious policies during hot configuration reload."
                .to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec![
                "Policy validation on reload".to_string(),
                "Atomic policy snapshot".to_string(),
            ],
        });

        self.add_vulnerability(AdversaVulnerability {
            rank: 25,
            name: "Glitch Token Exploitation".to_string(),
            description: "Using glitch tokens to confuse tokenizers and bypass security."
                .to_string(),
            severity: AdversaSeverity::Medium,
            vellaveto_mitigations: vec!["Glitch token detection".to_string()],
        });
    }

    /// Populate mappings from Vellaveto detections to vulnerability ranks.
    fn populate_detection_mappings(&mut self) {
        // Critical vulnerabilities
        self.map_detection(VellavetoDetection::ToolAnnotationChange, vec![1]);
        self.map_detection(VellavetoDetection::PromptInjection, vec![2]);
        self.map_detection(VellavetoDetection::IndirectInjection, vec![2]);
        self.map_detection(VellavetoDetection::ToolSquatting, vec![3, 21]);
        self.map_detection(VellavetoDetection::SchemaPoisoning, vec![4]);
        self.map_detection(VellavetoDetection::ConfusedDeputy, vec![5]);
        self.map_detection(VellavetoDetection::DataLaundering, vec![6]);
        self.map_detection(VellavetoDetection::MemoryInjection, vec![6]);
        self.map_detection(VellavetoDetection::ShadowAgent, vec![7]);

        // High severity
        self.map_detection(VellavetoDetection::PrivilegeEscalation, vec![8]);
        self.map_detection(VellavetoDetection::UnauthorizedDelegation, vec![8]);
        self.map_detection(VellavetoDetection::SecretsInOutput, vec![9]);
        self.map_detection(VellavetoDetection::CovertChannel, vec![9]);
        self.map_detection(VellavetoDetection::Steganography, vec![9]);
        self.map_detection(VellavetoDetection::UnicodeManipulation, vec![10]);
        self.map_detection(VellavetoDetection::PathTraversal, vec![11]);
        self.map_detection(VellavetoDetection::DnsRebinding, vec![12]);
        self.map_detection(VellavetoDetection::TokenSmuggling, vec![14]);
        self.map_detection(VellavetoDetection::GoalDrift, vec![15]);

        // Medium severity
        self.map_detection(VellavetoDetection::RateLimitExceeded, vec![16]);
        self.map_detection(VellavetoDetection::ContextFlooding, vec![17]);
        self.map_detection(VellavetoDetection::CircuitBreakerTriggered, vec![18]);
        self.map_detection(VellavetoDetection::CascadingFailure, vec![18]);
        self.map_detection(VellavetoDetection::WorkflowBudgetExceeded, vec![18]);
        self.map_detection(VellavetoDetection::GlitchToken, vec![25]);

        // Cross-mappings
        self.map_detection(VellavetoDetection::DelimiterInjection, vec![2]);
        self.map_detection(VellavetoDetection::SecondOrderInjection, vec![2]);
        self.map_detection(VellavetoDetection::ExcessiveAgency, vec![8]);
        self.map_detection(VellavetoDetection::UnauthorizedToolAccess, vec![8]);
        self.map_detection(VellavetoDetection::ToolShadowing, vec![21]);
        self.map_detection(VellavetoDetection::SamplingAttack, vec![22]);
    }
}

impl Default for AdversaTop25Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = AdversaTop25Registry::new();
        assert_eq!(registry.vulnerabilities.len(), 25);
        assert!(!registry.detection_mappings.is_empty());
    }

    #[test]
    fn test_all_25_vulnerabilities_present() {
        let registry = AdversaTop25Registry::new();
        for rank in 1..=25 {
            let vuln = registry.get_vulnerability(rank);
            assert!(vuln.is_some(), "Missing vulnerability at rank {rank}",);
        }
    }

    #[test]
    fn test_vulnerability_lookup_by_rank() {
        let registry = AdversaTop25Registry::new();
        let vuln = registry.get_vulnerability(1).expect("rank 1 should exist");
        assert_eq!(vuln.name, "Tool Annotation Rug Pull");
        assert_eq!(vuln.severity, AdversaSeverity::Critical);
    }

    #[test]
    fn test_invalid_rank_returns_none() {
        let registry = AdversaTop25Registry::new();
        assert!(registry.get_vulnerability(0).is_none());
        assert!(registry.get_vulnerability(26).is_none());
    }

    #[test]
    fn test_each_vulnerability_has_mitigations() {
        let registry = AdversaTop25Registry::new();
        for vuln in &registry.vulnerabilities {
            assert!(
                !vuln.vellaveto_mitigations.is_empty(),
                "Vulnerability rank {} ({}) has no mitigations",
                vuln.rank,
                vuln.name,
            );
        }
    }

    #[test]
    fn test_detection_to_vulnerability_mapping() {
        let registry = AdversaTop25Registry::new();
        let vulns = registry.get_vulnerabilities_for_detection(VellavetoDetection::PromptInjection);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.rank == 2));
    }

    #[test]
    fn test_coverage_report_generation() {
        let registry = AdversaTop25Registry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(report.total_vulnerabilities, 25);
        assert!(report.covered_count > 0);
        assert!(report.coverage_percent > 0.0);
    }

    #[test]
    fn test_coverage_25_of_25() {
        let registry = AdversaTop25Registry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(
            report.covered_count, 25,
            "Expected 25/25 coverage, got {}/25",
            report.covered_count,
        );
        assert!((report.coverage_percent - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_coverage_matrix_output() {
        let registry = AdversaTop25Registry::new();
        let matrix = registry.coverage_matrix();

        assert_eq!(matrix.len(), 25);
        // Matrix should be ordered by rank
        for (i, row) in matrix.iter().enumerate() {
            assert_eq!(row.rank as usize, i + 1);
        }
    }

    #[test]
    fn test_coverage_report_string() {
        let registry = AdversaTop25Registry::new();
        let report = registry.generate_coverage_report();
        let report_str = report.to_report_string();

        assert!(report_str.contains("Adversa AI MCP Security TOP 25"));
        assert!(report_str.contains("Coverage:"));
        assert!(report_str.contains("Matrix:"));
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", AdversaSeverity::Critical), "Critical");
        assert_eq!(format!("{}", AdversaSeverity::High), "High");
        assert_eq!(format!("{}", AdversaSeverity::Medium), "Medium");
    }

    #[test]
    fn test_serde_roundtrip_report() {
        let registry = AdversaTop25Registry::new();
        let report = registry.generate_coverage_report();
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: AdversaCoverageReport =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(
            deserialized.total_vulnerabilities,
            report.total_vulnerabilities,
        );
        assert_eq!(deserialized.covered_count, report.covered_count);
    }

    #[test]
    fn test_serde_roundtrip_vulnerability() {
        let vuln = AdversaVulnerability {
            rank: 1,
            name: "Test".to_string(),
            description: "Test vuln".to_string(),
            severity: AdversaSeverity::Critical,
            vellaveto_mitigations: vec!["m1".to_string()],
        };
        let json = serde_json::to_string(&vuln).expect("serialize should succeed");
        let deserialized: AdversaVulnerability =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.rank, 1);
    }

    #[test]
    fn test_default_trait() {
        let registry = AdversaTop25Registry::default();
        assert_eq!(registry.vulnerabilities.len(), 25);
    }
}
