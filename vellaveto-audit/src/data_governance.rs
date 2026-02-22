//! Data governance registry for EU AI Act Article 10 compliance.
//!
//! Tracks data classification, provenance, processing purpose, and retention
//! for each tool category. Provides default mappings for common tool types
//! and supports glob-pattern overrides from configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vellaveto_types::compliance::{DataClassification, DataGovernanceRecord, ProcessingPurpose};

/// Summary of data governance records.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataGovernanceSummary {
    /// Total number of tool mappings.
    pub total_mappings: usize,
    /// Breakdown by classification.
    pub classification_counts: HashMap<String, usize>,
    /// Breakdown by purpose.
    pub purpose_counts: HashMap<String, usize>,
    /// All tool mappings.
    pub mappings: Vec<DataGovernanceRecord>,
}

/// Registry of data governance records for Art 10 compliance.
pub struct DataGovernanceRegistry {
    mappings: HashMap<String, DataGovernanceRecord>,
}

impl DataGovernanceRegistry {
    /// Create a new registry with default tool classifications.
    pub fn new() -> Self {
        let mut registry = Self {
            mappings: HashMap::new(),
        };
        registry.populate_defaults();
        registry
    }

    /// Maximum tool name length for glob matching to prevent O(p*t) DP allocation.
    /// SECURITY (FIND-R178-002): Enforces the documented GAP-S08 guard.
    const MAX_TOOL_NAME_LEN: usize = 256;

    /// Get a record by exact tool name, falling back to glob matching.
    pub fn get_record(&self, tool_name: &str) -> Option<&DataGovernanceRecord> {
        // Exact match first
        if let Some(record) = self.mappings.get(tool_name) {
            return Some(record);
        }
        // SECURITY (FIND-R178-002): Reject oversized tool names before DP allocation.
        if tool_name.len() > Self::MAX_TOOL_NAME_LEN {
            tracing::warn!(
                tool_name_len = tool_name.len(),
                max = Self::MAX_TOOL_NAME_LEN,
                "Data governance: tool name exceeds maximum length for glob matching"
            );
            return None;
        }
        // Glob fallback
        for (pattern, record) in &self.mappings {
            if glob_match(pattern, tool_name) {
                return Some(record);
            }
        }
        None
    }

    /// Return all mappings.
    pub fn all_mappings(&self) -> Vec<&DataGovernanceRecord> {
        self.mappings.values().collect()
    }

    /// Generate a summary of all data governance records.
    pub fn generate_summary(&self) -> DataGovernanceSummary {
        let mut classification_counts: HashMap<String, usize> = HashMap::new();
        let mut purpose_counts: HashMap<String, usize> = HashMap::new();

        for record in self.mappings.values() {
            for class in &record.classifications {
                *classification_counts.entry(class.to_string()).or_insert(0) += 1;
            }
            *purpose_counts
                .entry(record.purpose.to_string())
                .or_insert(0) += 1;
        }

        DataGovernanceSummary {
            total_mappings: self.mappings.len(),
            classification_counts,
            purpose_counts,
            mappings: self.mappings.values().cloned().collect(),
        }
    }

    fn populate_defaults(&mut self) {
        // Filesystem tools
        self.mappings.insert(
            "filesystem.*".to_string(),
            DataGovernanceRecord {
                tool: "filesystem.*".to_string(),
                classifications: vec![DataClassification::Input, DataClassification::Output],
                purpose: ProcessingPurpose::ToolExecution,
                provenance: Some("user-provided file paths".to_string()),
                retention_days: Some(365),
            },
        );

        // Database tools
        self.mappings.insert(
            "database.*".to_string(),
            DataGovernanceRecord {
                tool: "database.*".to_string(),
                classifications: vec![
                    DataClassification::Input,
                    DataClassification::Output,
                    DataClassification::Personal,
                ],
                purpose: ProcessingPurpose::ToolExecution,
                provenance: Some("database queries and results".to_string()),
                retention_days: Some(365),
            },
        );

        // HTTP tools
        self.mappings.insert(
            "http.*".to_string(),
            DataGovernanceRecord {
                tool: "http.*".to_string(),
                classifications: vec![DataClassification::Input, DataClassification::Output],
                purpose: ProcessingPurpose::ToolExecution,
                provenance: Some("external API requests and responses".to_string()),
                retention_days: Some(365),
            },
        );

        // Vellaveto internal tools
        self.mappings.insert(
            "vellaveto.*".to_string(),
            DataGovernanceRecord {
                tool: "vellaveto.*".to_string(),
                classifications: vec![
                    DataClassification::Operational,
                    DataClassification::NonPersonal,
                ],
                purpose: ProcessingPurpose::SecurityAudit,
                provenance: Some("system-generated security events".to_string()),
                retention_days: Some(730),
            },
        );
    }
}

impl Default for DataGovernanceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple glob matching supporting `*` and `?`.
///
/// ## Memory (GAP-S08)
///
/// Uses a 2D dynamic programming table of size `O(pattern.len() * text.len())`.
/// For typical tool names (< 256 chars) and glob patterns (< 64 chars), this is
/// under 16 KB. Callers should validate that neither `pattern` nor `text` exceeds
/// reasonable bounds to prevent excessive memory allocation with adversarial inputs.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (plen, tlen) = (p.len(), t.len());

    let mut dp = vec![vec![false; tlen + 1]; plen + 1];
    dp[0][0] = true;

    for i in 1..=plen {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=plen {
        for j in 1..=tlen {
            if p[i - 1] == '*' {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else if p[i - 1] == '?' || p[i - 1] == t[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }

    dp[plen][tlen]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = DataGovernanceRegistry::new();
        assert!(!registry.mappings.is_empty());
        assert!(registry.mappings.len() >= 4);
    }

    #[test]
    fn test_exact_match() {
        let registry = DataGovernanceRegistry::new();
        let record = registry.get_record("filesystem.*");
        assert!(record.is_some());
        assert_eq!(record.unwrap().purpose, ProcessingPurpose::ToolExecution);
    }

    #[test]
    fn test_glob_match_filesystem() {
        let registry = DataGovernanceRegistry::new();
        let record = registry.get_record("filesystem.read_file");
        assert!(record.is_some());
        let r = record.unwrap();
        assert!(r.classifications.contains(&DataClassification::Input));
    }

    #[test]
    fn test_glob_match_http() {
        let registry = DataGovernanceRegistry::new();
        let record = registry.get_record("http.get");
        assert!(record.is_some());
    }

    #[test]
    fn test_glob_match_vellaveto() {
        let registry = DataGovernanceRegistry::new();
        let record = registry.get_record("vellaveto.audit");
        assert!(record.is_some());
        assert_eq!(record.unwrap().purpose, ProcessingPurpose::SecurityAudit);
    }

    #[test]
    fn test_no_match() {
        let registry = DataGovernanceRegistry::new();
        let record = registry.get_record("unknown_tool");
        assert!(record.is_none());
    }

    #[test]
    fn test_all_mappings() {
        let registry = DataGovernanceRegistry::new();
        let all = registry.all_mappings();
        assert!(all.len() >= 4);
    }

    #[test]
    fn test_generate_summary() {
        let registry = DataGovernanceRegistry::new();
        let summary = registry.generate_summary();
        assert!(summary.total_mappings >= 4);
        assert!(!summary.classification_counts.is_empty());
        assert!(!summary.purpose_counts.is_empty());
        assert!(!summary.mappings.is_empty());
    }

    #[test]
    fn test_summary_serde_roundtrip() {
        let registry = DataGovernanceRegistry::new();
        let summary = registry.generate_summary();
        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: DataGovernanceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_mappings, summary.total_mappings);
    }

    #[test]
    fn test_default_retention_days() {
        let registry = DataGovernanceRegistry::new();
        for record in registry.all_mappings() {
            assert!(record.retention_days.is_some());
            assert!(record.retention_days.unwrap() >= 365);
        }
    }

    #[test]
    fn test_provenance_populated() {
        let registry = DataGovernanceRegistry::new();
        for record in registry.all_mappings() {
            assert!(
                record.provenance.is_some(),
                "Tool {} should have provenance",
                record.tool
            );
        }
    }

    // ── R178 tool name length validation ────────────────────────────────

    #[test]
    fn test_get_record_tool_name_at_max_length() {
        let registry = DataGovernanceRegistry::new();
        let name = "a".repeat(DataGovernanceRegistry::MAX_TOOL_NAME_LEN);
        // Should not be rejected by length guard; returns None because no glob matches
        assert!(registry.get_record(&name).is_none());
    }

    #[test]
    fn test_get_record_tool_name_exceeds_max_length() {
        let registry = DataGovernanceRegistry::new();
        let name = "a".repeat(DataGovernanceRegistry::MAX_TOOL_NAME_LEN + 1);
        // Should be rejected by length guard before glob matching
        assert!(registry.get_record(&name).is_none());
    }

    #[test]
    fn test_get_record_oversized_tool_name_returns_none() {
        let registry = DataGovernanceRegistry::new();
        let name = "filesystem.".to_string() + &"x".repeat(5000);
        // Even though it starts with "filesystem.", the length guard rejects it
        assert!(registry.get_record(&name).is_none());
    }
}
