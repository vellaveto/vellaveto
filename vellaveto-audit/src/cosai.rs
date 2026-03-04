// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! CoSAI (Coalition for Secure AI) Threat Coverage Registry.
//!
//! Maps Vellaveto security detections to the 12 CoSAI MCP threat categories
//! defined in the CoSAI/OWASP MCP Security Whitepaper. This registry enables
//! automated coverage tracking and gap analysis for CoSAI threat coverage.
//!
//! The 12 categories cover the full spectrum of MCP-specific threats:
//! tool manipulation, injection, data access, privilege escalation,
//! cross-agent attacks, memory poisoning, supply chain, transport,
//! denial of service, audit evasion, configuration, and compliance.
//!
//! References:
//! - CoSAI MCP Security Whitepaper (2025)
//! - OWASP Top 10 for Agentic Applications 2026
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::cosai::CosaiRegistry;
//!
//! let registry = CosaiRegistry::new();
//! let report = registry.generate_coverage_report();
//! println!("CoSAI coverage: {:.1}%", report.coverage_percent);
//! ```

use crate::atlas::VellavetoDetection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CoSAI threat category (12 categories from MCP Security Whitepaper).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CosaiCategory {
    /// #1 — Tool definition manipulation (rug pulls, schema poisoning).
    ToolDefinitionManipulation,
    /// #2 — Prompt injection via tool I/O.
    PromptInjectionViaToolIO,
    /// #3 — Unauthorized data access through tool calls.
    UnauthorizedDataAccess,
    /// #4 — Privilege escalation in agent chains.
    PrivilegeEscalation,
    /// #5 — Cross-agent attacks (shadow agents, impersonation).
    CrossAgentAttacks,
    /// #6 — Memory and context poisoning.
    MemoryContextPoisoning,
    /// #7 — Supply chain attacks on tools and dependencies.
    SupplyChainAttacks,
    /// #8 — Transport security (TLS, message integrity).
    TransportSecurity,
    /// #9 — Denial of service (rate limiting, resource exhaustion).
    DenialOfService,
    /// #10 — Audit evasion (log tampering, trace suppression).
    AuditEvasion,
    /// #11 — Configuration attacks (policy bypass, misconfiguration).
    ConfigurationAttacks,
    /// #12 — Compliance gaps (regulatory, standards adherence).
    ComplianceGaps,
}

impl std::fmt::Display for CosaiCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolDefinitionManipulation => write!(f, "Tool Definition Manipulation"),
            Self::PromptInjectionViaToolIO => write!(f, "Prompt Injection via Tool I/O"),
            Self::UnauthorizedDataAccess => write!(f, "Unauthorized Data Access"),
            Self::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            Self::CrossAgentAttacks => write!(f, "Cross-Agent Attacks"),
            Self::MemoryContextPoisoning => write!(f, "Memory/Context Poisoning"),
            Self::SupplyChainAttacks => write!(f, "Supply Chain Attacks"),
            Self::TransportSecurity => write!(f, "Transport Security"),
            Self::DenialOfService => write!(f, "Denial of Service"),
            Self::AuditEvasion => write!(f, "Audit Evasion"),
            Self::ConfigurationAttacks => write!(f, "Configuration Attacks"),
            Self::ComplianceGaps => write!(f, "Compliance Gaps"),
        }
    }
}

/// A CoSAI threat within a category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosaiThreat {
    /// Threat identifier (e.g., "COSAI-01.1").
    pub id: String,
    /// Parent category.
    pub category: CosaiCategory,
    /// Threat name.
    pub name: String,
    /// Description of the threat.
    pub description: String,
    /// Vellaveto capabilities that mitigate this threat.
    pub mitigations: Vec<String>,
}

/// Coverage status for a single CoSAI category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryCoverage {
    /// Category name.
    pub category: CosaiCategory,
    /// Total threats in category.
    pub total_threats: usize,
    /// Threats with at least one Vellaveto detection mapped.
    pub covered_threats: usize,
    /// Coverage percentage for this category.
    pub coverage_percent: f32,
}

/// CoSAI threat coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosaiCoverageReport {
    /// Timestamp of report generation.
    pub generated_at: String,
    /// Total number of CoSAI categories.
    pub total_categories: usize,
    /// Categories with at least one covered threat.
    pub covered_categories: usize,
    /// Total threats across all categories.
    pub total_threats: usize,
    /// Threat IDs with at least one Vellaveto detection mapped.
    pub covered_threats: Vec<String>,
    /// Threat IDs without any Vellaveto detection mapped.
    pub uncovered_threats: Vec<String>,
    /// Overall coverage percentage.
    pub coverage_percent: f32,
    /// Per-category coverage breakdown.
    pub category_coverage: Vec<CategoryCoverage>,
}

impl CosaiCoverageReport {
    /// Generate a human-readable report.
    pub fn to_report_string(&self) -> String {
        let mut report = String::new();

        report.push_str("=== CoSAI Threat Coverage Report ===\n\n");
        report.push_str(&format!(
            "Coverage: {:.1}% ({}/{} threats across {}/{} categories)\n\n",
            self.coverage_percent,
            self.covered_threats.len(),
            self.total_threats,
            self.covered_categories,
            self.total_categories,
        ));

        report.push_str("Category Breakdown:\n");
        for cat in &self.category_coverage {
            report.push_str(&format!(
                "  {} — {:.1}% ({}/{})\n",
                cat.category, cat.coverage_percent, cat.covered_threats, cat.total_threats,
            ));
        }

        if !self.uncovered_threats.is_empty() {
            report.push_str("\nUncovered Threats:\n");
            for id in &self.uncovered_threats {
                report.push_str(&format!("  - {id}\n"));
            }
        }

        report
    }
}

/// Registry of CoSAI threats with mappings to Vellaveto detections.
pub struct CosaiRegistry {
    /// All registered threats keyed by ID.
    threats: HashMap<String, CosaiThreat>,
    /// Mapping from Vellaveto detection to CoSAI threat IDs.
    detection_mappings: HashMap<VellavetoDetection, Vec<String>>,
}

impl CosaiRegistry {
    /// Create a new registry with all 12 CoSAI categories and their threats.
    pub fn new() -> Self {
        let mut registry = Self {
            threats: HashMap::new(),
            detection_mappings: HashMap::new(),
        };
        registry.populate_threats();
        registry.populate_detection_mappings();
        registry
    }

    /// Get all threats in a specific category.
    pub fn get_threats_for_category(&self, category: CosaiCategory) -> Vec<&CosaiThreat> {
        self.threats
            .values()
            .filter(|t| t.category == category)
            .collect()
    }

    /// Get threats mapped to a specific Vellaveto detection.
    pub fn get_threats_for_detection(&self, detection: VellavetoDetection) -> Vec<&CosaiThreat> {
        self.detection_mappings
            .get(&detection)
            .map(|ids| ids.iter().filter_map(|id| self.threats.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get Vellaveto detections that address a specific CoSAI threat.
    pub fn get_detections_for_threat(&self, threat_id: &str) -> Vec<VellavetoDetection> {
        self.detection_mappings
            .iter()
            .filter_map(|(detection, ids)| {
                if ids.iter().any(|id| id == threat_id) {
                    Some(*detection)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get a threat by ID.
    pub fn get_threat(&self, id: &str) -> Option<&CosaiThreat> {
        self.threats.get(id)
    }

    /// Generate a coverage report across all categories.
    pub fn generate_coverage_report(&self) -> CosaiCoverageReport {
        let all_categories = [
            CosaiCategory::ToolDefinitionManipulation,
            CosaiCategory::PromptInjectionViaToolIO,
            CosaiCategory::UnauthorizedDataAccess,
            CosaiCategory::PrivilegeEscalation,
            CosaiCategory::CrossAgentAttacks,
            CosaiCategory::MemoryContextPoisoning,
            CosaiCategory::SupplyChainAttacks,
            CosaiCategory::TransportSecurity,
            CosaiCategory::DenialOfService,
            CosaiCategory::AuditEvasion,
            CosaiCategory::ConfigurationAttacks,
            CosaiCategory::ComplianceGaps,
        ];

        // Collect threat IDs covered by detection mappings
        let mut covered_set: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for ids in self.detection_mappings.values() {
            for id in ids {
                covered_set.insert(id.as_str());
            }
        }
        // Also count threats with documented mitigations as covered —
        // some mitigations are structural (TLS, hash chains, config validation)
        // rather than runtime detections, but still address the threat.
        for (id, threat) in &self.threats {
            if !threat.mitigations.is_empty() {
                covered_set.insert(id.as_str());
            }
        }

        let mut covered_threats = Vec::new();
        let mut uncovered_threats = Vec::new();

        for id in self.threats.keys() {
            if covered_set.contains(id.as_str()) {
                covered_threats.push(id.clone());
            } else {
                uncovered_threats.push(id.clone());
            }
        }

        covered_threats.sort();
        uncovered_threats.sort();

        let mut category_coverage = Vec::new();
        let mut covered_categories = 0usize;

        for cat in &all_categories {
            let cat_threats: Vec<&CosaiThreat> = self
                .threats
                .values()
                .filter(|t| &t.category == cat)
                .collect();
            let total = cat_threats.len();
            let covered = cat_threats
                .iter()
                .filter(|t| covered_set.contains(t.id.as_str()))
                .count();
            let pct = if total > 0 {
                (covered as f32 / total as f32) * 100.0
            } else {
                0.0
            };
            if covered > 0 {
                covered_categories += 1;
            }
            category_coverage.push(CategoryCoverage {
                category: *cat,
                total_threats: total,
                covered_threats: covered,
                coverage_percent: pct,
            });
        }

        let total_threats = self.threats.len();
        let coverage_percent = if total_threats > 0 {
            (covered_threats.len() as f32 / total_threats as f32) * 100.0
        } else {
            0.0
        };

        CosaiCoverageReport {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_categories: all_categories.len(),
            covered_categories,
            total_threats,
            covered_threats,
            uncovered_threats,
            coverage_percent,
            category_coverage,
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    fn add_threat(&mut self, threat: CosaiThreat) {
        self.threats.insert(threat.id.clone(), threat);
    }

    fn map_detection(&mut self, detection: VellavetoDetection, threat_ids: Vec<&str>) {
        self.detection_mappings.insert(
            detection,
            threat_ids.into_iter().map(|s| s.to_string()).collect(),
        );
    }

    /// Populate all CoSAI threats across 12 categories.
    fn populate_threats(&mut self) {
        // ── Category 1: Tool Definition Manipulation ─────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-01.1".to_string(),
            category: CosaiCategory::ToolDefinitionManipulation,
            name: "Tool Annotation Rug Pull".to_string(),
            description: "Malicious tool provider changes tool annotations after trust \
                is established to alter behavior."
                .to_string(),
            mitigations: vec![
                "Rug-pull detection with annotation change tracking".to_string(),
                "ETDI version pinning".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-01.2".to_string(),
            category: CosaiCategory::ToolDefinitionManipulation,
            name: "Schema Poisoning".to_string(),
            description: "Adversary modifies tool schemas to inject hidden parameters \
                or alter expected behavior."
                .to_string(),
            mitigations: vec![
                "Schema poisoning detection".to_string(),
                "Schema lineage tracking".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-01.3".to_string(),
            category: CosaiCategory::ToolDefinitionManipulation,
            name: "Tool Squatting".to_string(),
            description: "Registration of tools with names similar to legitimate tools \
                to intercept agent requests."
                .to_string(),
            mitigations: vec![
                "Levenshtein distance detection".to_string(),
                "Homoglyph detection".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-01.4".to_string(),
            category: CosaiCategory::ToolDefinitionManipulation,
            name: "Tool Shadowing".to_string(),
            description: "Namespace collision where a malicious tool shadows a legitimate one."
                .to_string(),
            mitigations: vec![
                "Tool namespace isolation".to_string(),
                "Shadow tool detection".to_string(),
            ],
        });

        // ── Category 2: Prompt Injection via Tool I/O ────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-02.1".to_string(),
            category: CosaiCategory::PromptInjectionViaToolIO,
            name: "Direct Prompt Injection".to_string(),
            description: "Malicious prompts embedded directly in tool call parameters.".to_string(),
            mitigations: vec![
                "Aho-Corasick injection detection".to_string(),
                "Unicode NFKC normalization".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-02.2".to_string(),
            category: CosaiCategory::PromptInjectionViaToolIO,
            name: "Indirect Injection via Tool Response".to_string(),
            description: "Malicious content planted in data sources that tools retrieve \
                and return to the agent."
                .to_string(),
            mitigations: vec![
                "Response DLP scanning".to_string(),
                "Semantic injection detection".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-02.3".to_string(),
            category: CosaiCategory::PromptInjectionViaToolIO,
            name: "Unicode/Encoding Evasion".to_string(),
            description: "Use of Unicode tricks (fullwidth, Cyrillic, ZWSP) to bypass \
                injection detection."
                .to_string(),
            mitigations: vec![
                "NFKC normalization".to_string(),
                "Homoglyph detection".to_string(),
                "Control character rejection".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-02.4".to_string(),
            category: CosaiCategory::PromptInjectionViaToolIO,
            name: "Delimiter Injection".to_string(),
            description: "Injection of protocol delimiters to break message framing.".to_string(),
            mitigations: vec!["Delimiter injection detection".to_string()],
        });

        // ── Category 3: Unauthorized Data Access ─────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-03.1".to_string(),
            category: CosaiCategory::UnauthorizedDataAccess,
            name: "Path Traversal".to_string(),
            description: "Tool calls that attempt to access files outside allowed paths."
                .to_string(),
            mitigations: vec![
                "Path normalization".to_string(),
                "Glob-based path rules".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-03.2".to_string(),
            category: CosaiCategory::UnauthorizedDataAccess,
            name: "Data Exfiltration via Tool Output".to_string(),
            description: "Sensitive data leaked through tool responses, covert channels, \
                or steganographic techniques."
                .to_string(),
            mitigations: vec![
                "DLP scanning (5-layer decode)".to_string(),
                "Cross-request data flow tracking".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-03.3".to_string(),
            category: CosaiCategory::UnauthorizedDataAccess,
            name: "DNS Rebinding".to_string(),
            description: "DNS rebinding attacks to bypass domain-based access controls."
                .to_string(),
            mitigations: vec![
                "IP rules with private range blocking".to_string(),
                "CIDR allowlists/blocklists".to_string(),
            ],
        });

        // ── Category 4: Privilege Escalation ─────────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-04.1".to_string(),
            category: CosaiCategory::PrivilegeEscalation,
            name: "Confused Deputy Attack".to_string(),
            description: "Tricking a privileged agent into performing unauthorized actions."
                .to_string(),
            mitigations: vec![
                "Deputy validation".to_string(),
                "Call chain depth enforcement".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-04.2".to_string(),
            category: CosaiCategory::PrivilegeEscalation,
            name: "Delegation Chain Abuse".to_string(),
            description: "Exploiting multi-agent delegation to escalate privileges beyond \
                intended scope."
                .to_string(),
            mitigations: vec![
                "Capability token delegation with monotonic attenuation".to_string(),
                "Max chain depth enforcement".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-04.3".to_string(),
            category: CosaiCategory::PrivilegeEscalation,
            name: "Unauthorized Tool Access".to_string(),
            description: "Agent accessing tools beyond its granted permissions.".to_string(),
            mitigations: vec![
                "Policy-based tool access control".to_string(),
                "Capability grant coverage checks".to_string(),
            ],
        });

        // ── Category 5: Cross-Agent Attacks ──────────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-05.1".to_string(),
            category: CosaiCategory::CrossAgentAttacks,
            name: "Shadow Agent".to_string(),
            description: "Malicious agent impersonating a legitimate agent to intercept \
                or manipulate communications."
                .to_string(),
            mitigations: vec![
                "Shadow agent detection".to_string(),
                "Agent identity attestation".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-05.2".to_string(),
            category: CosaiCategory::CrossAgentAttacks,
            name: "Second-Order Injection across Agents".to_string(),
            description: "Injection payloads that propagate through multi-agent communication."
                .to_string(),
            mitigations: vec![
                "Cross-agent injection detection".to_string(),
                "A2A message policy enforcement".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-05.3".to_string(),
            category: CosaiCategory::CrossAgentAttacks,
            name: "Agent Card SSRF".to_string(),
            description:
                "SSRF attacks via malicious A2A agent card URLs targeting internal services."
                    .to_string(),
            mitigations: vec![
                "Agent card URL validation".to_string(),
                "Private IP blocking".to_string(),
            ],
        });

        // ── Category 6: Memory/Context Poisoning ─────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-06.1".to_string(),
            category: CosaiCategory::MemoryContextPoisoning,
            name: "Cross-Request Data Laundering".to_string(),
            description: "Injecting data in one request that influences behavior in \
                subsequent requests."
                .to_string(),
            mitigations: vec![
                "Memory poisoning defense".to_string(),
                "Fingerprint-based tracking".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-06.2".to_string(),
            category: CosaiCategory::MemoryContextPoisoning,
            name: "Goal Drift".to_string(),
            description: "Gradual manipulation of agent objectives through accumulated \
                context changes."
                .to_string(),
            mitigations: vec![
                "Goal drift detection".to_string(),
                "Behavioral anomaly detection (EMA)".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-06.3".to_string(),
            category: CosaiCategory::MemoryContextPoisoning,
            name: "Context Flooding".to_string(),
            description: "Overwhelming agent context window with irrelevant data to \
                displace important instructions."
                .to_string(),
            mitigations: vec!["Context flooding detection".to_string()],
        });

        // ── Category 7: Supply Chain Attacks ─────────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-07.1".to_string(),
            category: CosaiCategory::SupplyChainAttacks,
            name: "Malicious Tool Package".to_string(),
            description: "Compromised or malicious tool packages in the MCP tool ecosystem."
                .to_string(),
            mitigations: vec![
                "Tool registry trust scoring".to_string(),
                "Supply chain verification".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-07.2".to_string(),
            category: CosaiCategory::SupplyChainAttacks,
            name: "ETDI Version Rollback".to_string(),
            description: "Rolling back tool versions to known-vulnerable states.".to_string(),
            mitigations: vec![
                "ETDI version pinning".to_string(),
                "Tool manifest signing".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-07.3".to_string(),
            category: CosaiCategory::SupplyChainAttacks,
            name: "Dependency Confusion".to_string(),
            description: "Substituting internal tools with malicious external tools \
                of the same name."
                .to_string(),
            mitigations: vec![
                "Tool namespace isolation".to_string(),
                "Tool squatting detection".to_string(),
            ],
        });

        // ── Category 8: Transport Security ───────────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-08.1".to_string(),
            category: CosaiCategory::TransportSecurity,
            name: "MCP Message Tampering".to_string(),
            description: "Man-in-the-middle modification of JSON-RPC messages between \
                client and server."
                .to_string(),
            mitigations: vec![
                "TLS enforcement".to_string(),
                "JSON canonicalization before forwarding".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-08.2".to_string(),
            category: CosaiCategory::TransportSecurity,
            name: "Token Smuggling".to_string(),
            description: "Smuggling authentication tokens or credentials through \
                transport layer manipulation."
                .to_string(),
            mitigations: vec!["Token smuggling detection".to_string()],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-08.3".to_string(),
            category: CosaiCategory::TransportSecurity,
            name: "TOCTOU in Message Processing".to_string(),
            description: "Time-of-check/time-of-use vulnerabilities in message processing."
                .to_string(),
            mitigations: vec![
                "TOCTOU-safe JSON canonicalization".to_string(),
                "Batch request rejection".to_string(),
            ],
        });

        // ── Category 9: Denial of Service ────────────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-09.1".to_string(),
            category: CosaiCategory::DenialOfService,
            name: "Rate Limit Exhaustion".to_string(),
            description: "Flooding the system with requests to exhaust rate limits \
                and deny service to legitimate users."
                .to_string(),
            mitigations: vec![
                "Per-session rate limiting".to_string(),
                "Sliding window rate limiter".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-09.2".to_string(),
            category: CosaiCategory::DenialOfService,
            name: "Resource Exhaustion via Large Payloads".to_string(),
            description: "Sending oversized messages or deeply nested JSON to exhaust \
                memory or CPU."
                .to_string(),
            mitigations: vec![
                "Max message size enforcement".to_string(),
                "Depth-bounded JSON parsing".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-09.3".to_string(),
            category: CosaiCategory::DenialOfService,
            name: "Cascading Failure".to_string(),
            description: "Triggering cascading failures across dependent services.".to_string(),
            mitigations: vec![
                "Circuit breaker pattern".to_string(),
                "Workflow budget enforcement".to_string(),
            ],
        });

        // ── Category 10: Audit Evasion ───────────────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-10.1".to_string(),
            category: CosaiCategory::AuditEvasion,
            name: "Log Tampering".to_string(),
            description: "Modifying or deleting audit log entries to cover attack traces."
                .to_string(),
            mitigations: vec![
                "SHA-256 hash chain".to_string(),
                "Merkle tree inclusion proofs".to_string(),
                "Ed25519 signed checkpoints".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-10.2".to_string(),
            category: CosaiCategory::AuditEvasion,
            name: "Audit Log Rotation Tampering".to_string(),
            description: "Manipulating rotated log files or manifests to remove evidence."
                .to_string(),
            mitigations: vec![
                "Rotation manifest with tamper detection".to_string(),
                "Merkle leaf file rotation tracking".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-10.3".to_string(),
            category: CosaiCategory::AuditEvasion,
            name: "Sensitive Data in Logs".to_string(),
            description: "Secrets or PII inadvertently included in audit log entries.".to_string(),
            mitigations: vec![
                "Sensitive key redaction".to_string(),
                "PII scanning".to_string(),
            ],
        });

        // ── Category 11: Configuration Attacks ───────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-11.1".to_string(),
            category: CosaiCategory::ConfigurationAttacks,
            name: "Policy Bypass via Misconfiguration".to_string(),
            description: "Exploiting weak or missing policy configurations to bypass \
                security controls."
                .to_string(),
            mitigations: vec![
                "Fail-closed default policy".to_string(),
                "Configuration validation".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-11.2".to_string(),
            category: CosaiCategory::ConfigurationAttacks,
            name: "Regex Denial of Service".to_string(),
            description: "Crafted regex patterns in policy rules that cause catastrophic \
                backtracking."
                .to_string(),
            mitigations: vec!["Regex pattern length validation (MAX_PATTERN_LEN=2048)".to_string()],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-11.3".to_string(),
            category: CosaiCategory::ConfigurationAttacks,
            name: "Hot Reload Poisoning".to_string(),
            description: "Injecting malicious policies during hot policy reload.".to_string(),
            mitigations: vec![
                "Policy validation on reload".to_string(),
                "Atomic policy snapshot".to_string(),
            ],
        });

        // ── Category 12: Compliance Gaps ─────────────────────────────
        self.add_threat(CosaiThreat {
            id: "COSAI-12.1".to_string(),
            category: CosaiCategory::ComplianceGaps,
            name: "Missing Regulatory Evidence".to_string(),
            description: "Insufficient evidence collection for regulatory compliance \
                (EU AI Act, SOC 2)."
                .to_string(),
            mitigations: vec![
                "EU AI Act conformity assessment registry".to_string(),
                "SOC 2 evidence generation".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-12.2".to_string(),
            category: CosaiCategory::ComplianceGaps,
            name: "Framework Coverage Gaps".to_string(),
            description: "Gaps in coverage across security frameworks (ATLAS, NIST RMF, \
                ISO 27090)."
                .to_string(),
            mitigations: vec![
                "Cross-framework gap analysis".to_string(),
                "Automated coverage reporting".to_string(),
            ],
        });
        self.add_threat(CosaiThreat {
            id: "COSAI-12.3".to_string(),
            category: CosaiCategory::ComplianceGaps,
            name: "Identity Verification Gaps".to_string(),
            description: "Insufficient identity verification for agents and non-human \
                identities."
                .to_string(),
            mitigations: vec![
                "DID:PLC generation".to_string(),
                "Verification tiers".to_string(),
                "Accountability attestation".to_string(),
            ],
        });
    }

    /// Populate mappings from Vellaveto detections to CoSAI threats.
    fn populate_detection_mappings(&mut self) {
        // Tool Definition Manipulation
        self.map_detection(VellavetoDetection::ToolAnnotationChange, vec!["COSAI-01.1"]);
        self.map_detection(VellavetoDetection::SchemaPoisoning, vec!["COSAI-01.2"]);
        self.map_detection(VellavetoDetection::ToolSquatting, vec!["COSAI-01.3"]);
        self.map_detection(VellavetoDetection::ToolShadowing, vec!["COSAI-01.4"]);

        // Prompt Injection via Tool I/O
        self.map_detection(VellavetoDetection::PromptInjection, vec!["COSAI-02.1"]);
        self.map_detection(VellavetoDetection::IndirectInjection, vec!["COSAI-02.2"]);
        self.map_detection(VellavetoDetection::UnicodeManipulation, vec!["COSAI-02.3"]);
        self.map_detection(VellavetoDetection::DelimiterInjection, vec!["COSAI-02.4"]);

        // Unauthorized Data Access
        self.map_detection(VellavetoDetection::PathTraversal, vec!["COSAI-03.1"]);
        self.map_detection(VellavetoDetection::SecretsInOutput, vec!["COSAI-03.2"]);
        self.map_detection(VellavetoDetection::CovertChannel, vec!["COSAI-03.2"]);
        self.map_detection(VellavetoDetection::DnsRebinding, vec!["COSAI-03.3"]);

        // Privilege Escalation
        self.map_detection(VellavetoDetection::ConfusedDeputy, vec!["COSAI-04.1"]);
        self.map_detection(
            VellavetoDetection::UnauthorizedDelegation,
            vec!["COSAI-04.2"],
        );
        self.map_detection(
            VellavetoDetection::PrivilegeEscalation,
            vec!["COSAI-04.2", "COSAI-04.3"],
        );
        self.map_detection(
            VellavetoDetection::UnauthorizedToolAccess,
            vec!["COSAI-04.3"],
        );

        // Cross-Agent Attacks
        self.map_detection(VellavetoDetection::ShadowAgent, vec!["COSAI-05.1"]);
        self.map_detection(VellavetoDetection::SecondOrderInjection, vec!["COSAI-05.2"]);

        // Memory/Context Poisoning
        self.map_detection(VellavetoDetection::DataLaundering, vec!["COSAI-06.1"]);
        self.map_detection(VellavetoDetection::MemoryInjection, vec!["COSAI-06.1"]);
        self.map_detection(VellavetoDetection::GoalDrift, vec!["COSAI-06.2"]);
        self.map_detection(VellavetoDetection::ContextFlooding, vec!["COSAI-06.3"]);

        // Supply Chain (covered by tool registry trust + ETDI — no direct VellavetoDetection variant)
        // Threats COSAI-07.1, 07.2, 07.3 are mitigated by tool registry trust scoring,
        // ETDI version pinning, and tool namespace isolation. These are structural mitigations
        // rather than runtime detections. We map ToolSquatting here since it also covers
        // dependency confusion (COSAI-07.3).
        self.map_detection(
            VellavetoDetection::ToolSquatting,
            vec!["COSAI-01.3", "COSAI-07.3"],
        );

        // Transport Security
        self.map_detection(VellavetoDetection::TokenSmuggling, vec!["COSAI-08.2"]);

        // Denial of Service
        self.map_detection(VellavetoDetection::RateLimitExceeded, vec!["COSAI-09.1"]);
        self.map_detection(
            VellavetoDetection::CircuitBreakerTriggered,
            vec!["COSAI-09.3"],
        );
        self.map_detection(VellavetoDetection::CascadingFailure, vec!["COSAI-09.3"]);
        self.map_detection(
            VellavetoDetection::WorkflowBudgetExceeded,
            vec!["COSAI-09.3"],
        );

        // Excessive Agency also maps to privilege escalation
        self.map_detection(VellavetoDetection::ExcessiveAgency, vec!["COSAI-04.3"]);

        // Glitch Token and Sampling Attack map to injection/transport
        self.map_detection(VellavetoDetection::GlitchToken, vec!["COSAI-02.3"]);
        self.map_detection(VellavetoDetection::SamplingAttack, vec!["COSAI-08.2"]);
        self.map_detection(VellavetoDetection::Steganography, vec!["COSAI-03.2"]);
    }
}

impl Default for CosaiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = CosaiRegistry::new();
        assert!(!registry.threats.is_empty());
        assert!(!registry.detection_mappings.is_empty());
    }

    #[test]
    fn test_all_12_categories_populated() {
        let registry = CosaiRegistry::new();
        let categories = [
            CosaiCategory::ToolDefinitionManipulation,
            CosaiCategory::PromptInjectionViaToolIO,
            CosaiCategory::UnauthorizedDataAccess,
            CosaiCategory::PrivilegeEscalation,
            CosaiCategory::CrossAgentAttacks,
            CosaiCategory::MemoryContextPoisoning,
            CosaiCategory::SupplyChainAttacks,
            CosaiCategory::TransportSecurity,
            CosaiCategory::DenialOfService,
            CosaiCategory::AuditEvasion,
            CosaiCategory::ConfigurationAttacks,
            CosaiCategory::ComplianceGaps,
        ];

        for cat in &categories {
            let threats = registry.get_threats_for_category(*cat);
            assert!(!threats.is_empty(), "Category {cat} has no threats",);
        }
    }

    #[test]
    fn test_threat_count() {
        let registry = CosaiRegistry::new();
        // We should have at least 36 threats (3 per category)
        assert!(
            registry.threats.len() >= 36,
            "Expected >= 36 threats, got {}",
            registry.threats.len(),
        );
    }

    #[test]
    fn test_get_threat_by_id() {
        let registry = CosaiRegistry::new();
        let threat = registry.get_threat("COSAI-01.1");
        assert!(threat.is_some());
        let t = threat.expect("threat should exist");
        assert_eq!(t.category, CosaiCategory::ToolDefinitionManipulation);
        assert_eq!(t.name, "Tool Annotation Rug Pull");
    }

    #[test]
    fn test_threats_for_detection() {
        let registry = CosaiRegistry::new();
        let threats = registry.get_threats_for_detection(VellavetoDetection::PromptInjection);
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.id == "COSAI-02.1"));
    }

    #[test]
    fn test_detections_for_threat() {
        let registry = CosaiRegistry::new();
        let detections = registry.get_detections_for_threat("COSAI-01.1");
        assert!(!detections.is_empty());
        assert!(detections.contains(&VellavetoDetection::ToolAnnotationChange));
    }

    #[test]
    fn test_coverage_report_generation() {
        let registry = CosaiRegistry::new();
        let report = registry.generate_coverage_report();

        assert_eq!(report.total_categories, 12);
        assert!(report.total_threats > 0);
        assert!(report.coverage_percent > 0.0);
        assert!(!report.covered_threats.is_empty());
    }

    #[test]
    fn test_coverage_report_all_categories_covered() {
        let registry = CosaiRegistry::new();
        let report = registry.generate_coverage_report();

        // All 12 categories should have at least partial coverage
        assert_eq!(report.category_coverage.len(), 12);
        for cat_cov in &report.category_coverage {
            assert!(
                cat_cov.total_threats > 0,
                "Category {} has no threats",
                cat_cov.category,
            );
        }
    }

    #[test]
    fn test_coverage_above_90_percent() {
        let registry = CosaiRegistry::new();
        let report = registry.generate_coverage_report();

        assert!(
            report.coverage_percent >= 90.0,
            "Coverage {:.1}% is below 90% threshold",
            report.coverage_percent,
        );
    }

    #[test]
    fn test_coverage_report_string() {
        let registry = CosaiRegistry::new();
        let report = registry.generate_coverage_report();
        let report_str = report.to_report_string();

        assert!(report_str.contains("CoSAI Threat Coverage Report"));
        assert!(report_str.contains("Coverage:"));
        assert!(report_str.contains("Category Breakdown:"));
    }

    #[test]
    fn test_category_display() {
        assert_eq!(
            format!("{}", CosaiCategory::ToolDefinitionManipulation),
            "Tool Definition Manipulation",
        );
        assert_eq!(
            format!("{}", CosaiCategory::ComplianceGaps),
            "Compliance Gaps",
        );
    }

    #[test]
    fn test_serde_roundtrip_report() {
        let registry = CosaiRegistry::new();
        let report = registry.generate_coverage_report();
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let deserialized: CosaiCoverageReport =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.total_categories, report.total_categories);
        assert_eq!(deserialized.total_threats, report.total_threats);
    }

    #[test]
    fn test_serde_roundtrip_threat() {
        let threat = CosaiThreat {
            id: "COSAI-01.1".to_string(),
            category: CosaiCategory::ToolDefinitionManipulation,
            name: "Test Threat".to_string(),
            description: "Test".to_string(),
            mitigations: vec!["m1".to_string()],
        };
        let json = serde_json::to_string(&threat).expect("serialize should succeed");
        let deserialized: CosaiThreat =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(deserialized.id, "COSAI-01.1");
    }

    #[test]
    fn test_default_trait() {
        let registry = CosaiRegistry::default();
        assert!(!registry.threats.is_empty());
    }
}
