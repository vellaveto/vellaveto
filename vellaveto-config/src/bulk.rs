// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Bulk policy operations — batch import/export of policies.
//!
//! Phase 70: Provides validated import from JSON with per-policy findings,
//! export to JSON and TOML, and pre-import validation (duplicate IDs,
//! empty fields, priority range).

use vellaveto_types::Policy;

/// Maximum number of policies in a single import batch.
///
/// SECURITY: Bounds memory usage during bulk import. Attacker-controlled
/// input will attempt to maximize batch size.
pub const MAX_IMPORT_POLICIES: usize = 1000;

/// Maximum size of import payload in bytes (1 MiB).
///
/// SECURITY: Prevents memory exhaustion from oversized import payloads.
pub const MAX_IMPORT_SIZE: usize = 1_048_576;

/// Minimum valid priority value for warning threshold.
const MIN_PRIORITY_WARN: i32 = -1000;

/// Maximum valid priority value for warning threshold.
const MAX_PRIORITY_WARN: i32 = 1000;

/// Supported export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Toml,
    Json,
}

/// A validation finding during import.
#[derive(Debug, Clone)]
pub struct ImportFinding {
    pub index: usize,
    pub policy_id: String,
    pub severity: ImportSeverity,
    pub message: String,
}

/// Severity level for import findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportSeverity {
    Error,
    Warning,
}

/// Result of importing policies.
#[derive(Debug, Clone)]
pub struct ImportResult {
    pub policies: Vec<Policy>,
    pub findings: Vec<ImportFinding>,
    pub imported_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
}

/// Result of exporting policies.
#[derive(Debug, Clone)]
pub struct ExportResult {
    pub content: String,
    pub format: ExportFormat,
    pub policy_count: usize,
}

/// Bulk import/export operations for policies.
pub struct BulkOperations;

impl BulkOperations {
    /// Export policies to the specified format.
    ///
    /// Returns an `ExportResult` containing the serialized content.
    /// Fails if serialization produces an error.
    pub fn export(policies: &[Policy], format: ExportFormat) -> Result<ExportResult, String> {
        match format {
            ExportFormat::Json => {
                let content = serde_json::to_string_pretty(policies)
                    .map_err(|e| format!("JSON serialization failed: {e}"))?;
                Ok(ExportResult {
                    content,
                    format: ExportFormat::Json,
                    policy_count: policies.len(),
                })
            }
            ExportFormat::Toml => {
                let mut out = String::new();
                for policy in policies {
                    out.push_str("[[policies]]\n");
                    // Escape double-quotes in values for TOML string literals
                    out.push_str(&format!("id = \"{}\"\n", escape_toml_string(&policy.id)));
                    out.push_str(&format!(
                        "name = \"{}\"\n",
                        escape_toml_string(&policy.name)
                    ));
                    out.push_str(&format!("priority = {}\n", policy.priority));
                    match &policy.policy_type {
                        vellaveto_types::PolicyType::Allow => {
                            out.push_str("policy_type = \"Allow\"\n");
                        }
                        vellaveto_types::PolicyType::Deny => {
                            out.push_str("policy_type = \"Deny\"\n");
                        }
                        vellaveto_types::PolicyType::Conditional { .. } => {
                            out.push_str("policy_type = \"Conditional\"\n");
                        }
                        _ => {
                            out.push_str("policy_type = \"Unknown\"\n");
                        }
                    }
                    out.push('\n');
                }
                Ok(ExportResult {
                    content: out,
                    format: ExportFormat::Toml,
                    policy_count: policies.len(),
                })
            }
        }
    }

    /// Import policies from a JSON string with validation.
    ///
    /// Validates input size, parses JSON, and runs per-policy validation.
    /// Policies with Error-level findings are excluded from the result set.
    pub fn import_json(input: &str) -> ImportResult {
        let mut findings = Vec::new();

        // Check input size
        if input.len() > MAX_IMPORT_SIZE {
            findings.push(ImportFinding {
                index: 0,
                policy_id: String::new(),
                severity: ImportSeverity::Error,
                message: format!(
                    "Import payload size {} exceeds maximum {}",
                    input.len(),
                    MAX_IMPORT_SIZE
                ),
            });
            return ImportResult {
                policies: Vec::new(),
                findings: vec_with_counts(findings),
                imported_count: 0,
                error_count: 1,
                warning_count: 0,
            };
        }

        // Parse JSON
        let parsed: Vec<Policy> = match serde_json::from_str(input) {
            Ok(v) => v,
            Err(e) => {
                findings.push(ImportFinding {
                    index: 0,
                    policy_id: String::new(),
                    severity: ImportSeverity::Error,
                    message: format!("JSON parse error: {e}"),
                });
                return ImportResult {
                    policies: Vec::new(),
                    findings: vec_with_counts(findings),
                    imported_count: 0,
                    error_count: 1,
                    warning_count: 0,
                };
            }
        };

        // Check batch size limit
        if parsed.len() > MAX_IMPORT_POLICIES {
            findings.push(ImportFinding {
                index: 0,
                policy_id: String::new(),
                severity: ImportSeverity::Error,
                message: format!(
                    "Batch contains {} policies, maximum is {}",
                    parsed.len(),
                    MAX_IMPORT_POLICIES
                ),
            });
            return ImportResult {
                policies: Vec::new(),
                findings: vec_with_counts(findings),
                imported_count: 0,
                error_count: 1,
                warning_count: 0,
            };
        }

        // Validate each policy
        let validation_findings = Self::validate_import(&parsed);
        findings.extend(validation_findings);

        // Collect indices of policies with errors to exclude them
        let mut error_indices = std::collections::HashSet::new();
        for f in &findings {
            if f.severity == ImportSeverity::Error {
                error_indices.insert(f.index);
            }
        }

        let accepted: Vec<Policy> = parsed
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !error_indices.contains(i))
            .map(|(_, p)| p)
            .collect();

        let error_count = findings
            .iter()
            .filter(|f| f.severity == ImportSeverity::Error)
            .count();
        let warning_count = findings
            .iter()
            .filter(|f| f.severity == ImportSeverity::Warning)
            .count();
        let imported_count = accepted.len();

        ImportResult {
            policies: accepted,
            findings,
            imported_count,
            error_count,
            warning_count,
        }
    }

    /// Validate a set of policies for import.
    ///
    /// Checks for:
    /// - Empty policy IDs (Error)
    /// - Empty policy names (Error)
    /// - Duplicate policy IDs (Error on second occurrence)
    /// - Priority out of recommended range (Warning)
    /// - Control characters in id/name (Error)
    pub fn validate_import(policies: &[Policy]) -> Vec<ImportFinding> {
        let mut findings = Vec::new();
        let mut seen_ids: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

        for (i, policy) in policies.iter().enumerate() {
            // Empty ID check
            if policy.id.is_empty() {
                findings.push(ImportFinding {
                    index: i,
                    policy_id: String::new(),
                    severity: ImportSeverity::Error,
                    message: "Policy ID is empty".to_string(),
                });
            } else {
                // Control character check on ID
                if vellaveto_types::has_dangerous_chars(&policy.id) {
                    findings.push(ImportFinding {
                        index: i,
                        policy_id: policy.id.clone(),
                        severity: ImportSeverity::Error,
                        message: "Policy ID contains control or format characters".to_string(),
                    });
                }

                // Duplicate ID check
                if let Some(&first_idx) = seen_ids.get(policy.id.as_str()) {
                    findings.push(ImportFinding {
                        index: i,
                        policy_id: policy.id.clone(),
                        severity: ImportSeverity::Error,
                        message: format!(
                            "Duplicate policy ID '{}' (first seen at index {})",
                            policy.id, first_idx
                        ),
                    });
                } else {
                    seen_ids.insert(&policy.id, i);
                }
            }

            // Empty name check
            if policy.name.is_empty() {
                findings.push(ImportFinding {
                    index: i,
                    policy_id: policy.id.clone(),
                    severity: ImportSeverity::Error,
                    message: "Policy name is empty".to_string(),
                });
            } else if vellaveto_types::has_dangerous_chars(&policy.name) {
                findings.push(ImportFinding {
                    index: i,
                    policy_id: policy.id.clone(),
                    severity: ImportSeverity::Error,
                    message: "Policy name contains control or format characters".to_string(),
                });
            }

            // Priority range warning
            if policy.priority < MIN_PRIORITY_WARN || policy.priority > MAX_PRIORITY_WARN {
                findings.push(ImportFinding {
                    index: i,
                    policy_id: policy.id.clone(),
                    severity: ImportSeverity::Warning,
                    message: format!(
                        "Priority {} is outside recommended range [{}, {}]",
                        policy.priority, MIN_PRIORITY_WARN, MAX_PRIORITY_WARN
                    ),
                });
            }
        }

        findings
    }
}

/// Escape a string for inclusion in a TOML quoted string.
///
/// SECURITY (R229-CFG-2): Escape all ASCII control characters (0x00-0x1F, 0x7F)
/// via Unicode escape sequences, not just \n, \t, \r. Unescaped control chars
/// can break TOML parsers or inject invisible content.
fn escape_toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            // R229-CFG-2: Escape remaining ASCII control chars via \uXXXX.
            c if c.is_ascii_control() => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

/// Helper to return findings with proper counts (used internally).
fn vec_with_counts(findings: Vec<ImportFinding>) -> Vec<ImportFinding> {
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::{Policy, PolicyType};

    fn make_policy(id: &str, name: &str, priority: i32, policy_type: PolicyType) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            policy_type,
            priority,
            path_rules: None,
            network_rules: None,
        }
    }

    #[test]
    fn test_bulk_export_json_empty() {
        let result = BulkOperations::export(&[], ExportFormat::Json).unwrap();
        assert_eq!(result.format, ExportFormat::Json);
        assert_eq!(result.policy_count, 0);
        assert_eq!(result.content, "[]");
    }

    #[test]
    fn test_bulk_export_json_roundtrip() {
        let policies = vec![
            make_policy("p1", "Allow reads", 10, PolicyType::Allow),
            make_policy("p2", "Deny writes", 20, PolicyType::Deny),
        ];
        let result = BulkOperations::export(&policies, ExportFormat::Json).unwrap();
        assert_eq!(result.policy_count, 2);
        // Verify roundtrip
        let parsed: Vec<Policy> = serde_json::from_str(&result.content).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "p1");
        assert_eq!(parsed[1].id, "p2");
    }

    #[test]
    fn test_bulk_export_toml_basic() {
        let policies = vec![make_policy("p1", "Test Policy", 5, PolicyType::Allow)];
        let result = BulkOperations::export(&policies, ExportFormat::Toml).unwrap();
        assert_eq!(result.format, ExportFormat::Toml);
        assert_eq!(result.policy_count, 1);
        assert!(result.content.contains("[[policies]]"));
        assert!(result.content.contains("id = \"p1\""));
        assert!(result.content.contains("name = \"Test Policy\""));
        assert!(result.content.contains("priority = 5"));
    }

    #[test]
    fn test_bulk_export_toml_escapes_quotes() {
        let policies = vec![make_policy(
            "p1",
            "Policy \"with quotes\"",
            0,
            PolicyType::Deny,
        )];
        let result = BulkOperations::export(&policies, ExportFormat::Toml).unwrap();
        assert!(result.content.contains("\\\"with quotes\\\""));
    }

    #[test]
    fn test_bulk_import_json_valid() {
        let policies = vec![
            make_policy("p1", "Allow reads", 10, PolicyType::Allow),
            make_policy("p2", "Deny writes", 20, PolicyType::Deny),
        ];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert_eq!(result.imported_count, 2);
        assert_eq!(result.error_count, 0);
        assert_eq!(result.warning_count, 0);
        assert_eq!(result.policies.len(), 2);
    }

    #[test]
    fn test_bulk_import_json_invalid_json() {
        let result = BulkOperations::import_json("not valid json{{{");
        assert_eq!(result.imported_count, 0);
        assert_eq!(result.error_count, 1);
        assert!(result.findings[0].message.contains("JSON parse error"));
    }

    #[test]
    fn test_bulk_import_json_empty_id() {
        let policies = vec![make_policy("", "Valid Name", 5, PolicyType::Allow)];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.imported_count, 0);
        assert!(result
            .findings
            .iter()
            .any(|f| f.message == "Policy ID is empty"));
    }

    #[test]
    fn test_bulk_import_json_empty_name() {
        let policies = vec![make_policy("p1", "", 5, PolicyType::Allow)];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.imported_count, 0);
        assert!(result
            .findings
            .iter()
            .any(|f| f.message == "Policy name is empty"));
    }

    #[test]
    fn test_bulk_import_json_duplicate_ids() {
        let policies = vec![
            make_policy("dup", "First", 1, PolicyType::Allow),
            make_policy("dup", "Second", 2, PolicyType::Deny),
        ];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert_eq!(result.error_count, 1);
        // Only the first should be imported, the duplicate is rejected
        assert_eq!(result.imported_count, 1);
        assert_eq!(result.policies[0].name, "First");
    }

    #[test]
    fn test_bulk_import_json_priority_warning() {
        let policies = vec![make_policy("p1", "High Priority", 2000, PolicyType::Allow)];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert_eq!(result.warning_count, 1);
        assert_eq!(result.error_count, 0);
        // Warnings do not prevent import
        assert_eq!(result.imported_count, 1);
    }

    #[test]
    fn test_bulk_import_json_negative_priority_warning() {
        let policies = vec![make_policy("p1", "Low Priority", -1500, PolicyType::Allow)];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert_eq!(result.warning_count, 1);
        assert_eq!(result.imported_count, 1);
    }

    #[test]
    fn test_bulk_import_json_exceeds_max_size() {
        // Create a payload that exceeds MAX_IMPORT_SIZE
        let oversized = "x".repeat(MAX_IMPORT_SIZE + 1);
        let result = BulkOperations::import_json(&oversized);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.imported_count, 0);
        assert!(result.findings[0].message.contains("exceeds maximum"));
    }

    #[test]
    fn test_bulk_import_json_exceeds_max_policies() {
        // Build a vector with more than MAX_IMPORT_POLICIES entries
        let mut policies = Vec::new();
        for i in 0..=MAX_IMPORT_POLICIES {
            policies.push(make_policy(
                &format!("p{i}"),
                &format!("Policy {i}"),
                0,
                PolicyType::Allow,
            ));
        }
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.imported_count, 0);
        assert!(result.findings[0].message.contains("maximum is"));
    }

    #[test]
    fn test_bulk_import_json_control_chars_in_id() {
        let policies = vec![make_policy("p\x001", "Valid Name", 0, PolicyType::Allow)];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert!(result.findings.iter().any(|f| {
            f.severity == ImportSeverity::Error
                && f.message.contains("control or format characters")
        }));
    }

    #[test]
    fn test_bulk_import_json_control_chars_in_name() {
        let policies = vec![make_policy("p1", "Bad\x00Name", 0, PolicyType::Allow)];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert!(result.findings.iter().any(|f| {
            f.severity == ImportSeverity::Error
                && f.message.contains("control or format characters")
        }));
    }

    #[test]
    fn test_bulk_validate_import_mixed_findings() {
        let policies = vec![
            make_policy("", "No ID", 0, PolicyType::Allow), // Error: empty ID
            make_policy("p2", "Good", 500, PolicyType::Allow), // OK
            make_policy("p3", "", 0, PolicyType::Deny),     // Error: empty name
            make_policy("p4", "Big Priority", 5000, PolicyType::Allow), // Warning: priority out of range
        ];
        let findings = BulkOperations::validate_import(&policies);
        let errors = findings
            .iter()
            .filter(|f| f.severity == ImportSeverity::Error)
            .count();
        let warnings = findings
            .iter()
            .filter(|f| f.severity == ImportSeverity::Warning)
            .count();
        assert_eq!(errors, 2);
        assert_eq!(warnings, 1);
    }

    #[test]
    fn test_bulk_export_json_then_import_roundtrip() {
        let policies = vec![
            make_policy("alpha", "Alpha Policy", 10, PolicyType::Allow),
            make_policy("beta", "Beta Policy", -5, PolicyType::Deny),
        ];
        let exported = BulkOperations::export(&policies, ExportFormat::Json).unwrap();
        let imported = BulkOperations::import_json(&exported.content);
        assert_eq!(imported.imported_count, 2);
        assert_eq!(imported.error_count, 0);
        assert_eq!(imported.policies[0].id, "alpha");
        assert_eq!(imported.policies[1].id, "beta");
        assert_eq!(imported.policies[0].priority, 10);
        assert_eq!(imported.policies[1].priority, -5);
    }

    #[test]
    fn test_bulk_import_json_partial_accept() {
        // Mix of valid and invalid policies: only valid ones accepted
        let policies = vec![
            make_policy("good1", "Good One", 0, PolicyType::Allow),
            make_policy("", "No ID", 0, PolicyType::Deny),
            make_policy("good2", "Good Two", 1, PolicyType::Allow),
        ];
        let json = serde_json::to_string(&policies).unwrap();
        let result = BulkOperations::import_json(&json);
        assert_eq!(result.imported_count, 2);
        assert_eq!(result.error_count, 1);
        assert_eq!(result.policies[0].id, "good1");
        assert_eq!(result.policies[1].id, "good2");
    }

    #[test]
    fn test_bulk_validate_empty_input() {
        let findings = BulkOperations::validate_import(&[]);
        assert!(findings.is_empty());
    }
}
