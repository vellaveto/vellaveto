// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Policy coverage analysis — identifies dead policies and coverage gaps.
//!
//! Phase 72: Analyzes evaluation records against the current policy set to
//! determine which policies are actively matching, which are dead (never matched),
//! and which tools have no matching policy.

use std::collections::{HashMap, HashSet};
use vellaveto_types::Policy;

/// Coverage analysis for a single policy.
#[derive(Debug, Clone)]
pub struct PolicyCoverage {
    /// Policy identifier.
    pub policy_id: String,
    /// Policy display name.
    pub policy_name: String,
    /// Number of evaluations that matched this policy.
    pub match_count: u64,
    /// ISO 8601 timestamp of the last match (if any).
    pub last_matched: Option<String>,
    /// True if this policy has never been matched.
    pub is_dead: bool,
    /// Fraction of total evaluations that matched this policy.
    /// Clamped to [0.0, 1.0]. Returns 0.0 when total_evaluations is zero.
    pub coverage_pct: f64,
}

/// A tool that was seen in evaluations but had no matching policy.
#[derive(Debug, Clone)]
pub struct UncoveredTool {
    /// Tool name.
    pub tool_name: String,
    /// Number of times this tool was seen without a matching policy.
    pub occurrence_count: u64,
    /// ISO 8601 timestamp of the last time this tool was seen.
    pub last_seen: Option<String>,
}

/// Full coverage analysis report.
#[derive(Debug, Clone)]
pub struct CoverageReport {
    /// Total number of evaluation records analyzed.
    pub total_evaluations: u64,
    /// Total number of policies in the set.
    pub total_policies: usize,
    /// Policies that never matched any evaluation record.
    pub dead_policies: Vec<PolicyCoverage>,
    /// Policies that matched at least one evaluation record.
    pub active_policies: Vec<PolicyCoverage>,
    /// Tools seen in evaluations with no matching policy.
    pub uncovered_tools: Vec<UncoveredTool>,
    /// Fraction of policies that are active (matched at least once).
    /// Clamped to [0.0, 1.0]. Returns 0.0 when total_policies is zero.
    pub coverage_score: f64,
    /// Fraction of distinct tools that had a matching policy.
    /// Clamped to [0.0, 1.0]. Returns 0.0 when no tools were seen.
    pub tool_coverage_score: f64,
}

/// A recorded evaluation for coverage tracking.
#[derive(Debug, Clone)]
pub struct EvaluationRecord {
    /// Tool name from the evaluation.
    pub tool: String,
    /// Policy ID that matched, or `None` if no policy matched.
    pub matched_policy_id: Option<String>,
    /// ISO 8601 timestamp of the evaluation.
    pub timestamp: String,
}

/// Policy coverage analyzer.
///
/// Stateless analyzer that takes a snapshot of policies and evaluation
/// records, producing a coverage report.
pub struct CoverageAnalyzer;

impl CoverageAnalyzer {
    /// Analyze policy coverage from evaluation records.
    ///
    /// Examines each evaluation record to count matches per policy and
    /// identify tools with no matching policy. Produces coverage scores
    /// that are always in [0.0, 1.0] (handles division by zero as 0.0).
    pub fn analyze(policies: &[Policy], records: &[EvaluationRecord]) -> CoverageReport {
        let total_evaluations = records.len() as u64;
        let total_policies = policies.len();

        // Build per-policy match tracking
        let mut policy_match_count: HashMap<String, u64> = HashMap::new();
        let mut policy_last_matched: HashMap<String, String> = HashMap::new();

        // Track all tools seen and which had matches
        let mut tool_occurrences: HashMap<String, u64> = HashMap::new();
        let mut tool_last_seen: HashMap<String, String> = HashMap::new();
        let mut covered_tools: HashSet<String> = HashSet::new();

        // Initialize all policies with zero counts
        for policy in policies {
            policy_match_count.insert(policy.id.clone(), 0);
        }

        // Process each evaluation record
        for record in records {
            // Track tool occurrence (saturating)
            let tool_count = tool_occurrences.entry(record.tool.clone()).or_insert(0);
            *tool_count = tool_count.saturating_add(1);
            tool_last_seen.insert(record.tool.clone(), record.timestamp.clone());

            if let Some(ref pid) = record.matched_policy_id {
                // Increment match count for the matched policy (saturating)
                let count = policy_match_count.entry(pid.clone()).or_insert(0);
                *count = count.saturating_add(1);
                policy_last_matched.insert(pid.clone(), record.timestamp.clone());

                // Mark this tool as covered
                covered_tools.insert(record.tool.clone());
            }
        }

        // Build policy coverage entries
        let mut dead_policies = Vec::new();
        let mut active_policies = Vec::new();

        for policy in policies {
            let match_count = policy_match_count.get(&policy.id).copied().unwrap_or(0);
            let last_matched = policy_last_matched.get(&policy.id).cloned();
            let is_dead = match_count == 0;
            let coverage_pct = safe_divide_f64(match_count as f64, total_evaluations as f64);

            let entry = PolicyCoverage {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                match_count,
                last_matched,
                is_dead,
                coverage_pct,
            };

            if is_dead {
                dead_policies.push(entry);
            } else {
                active_policies.push(entry);
            }
        }

        // Build uncovered tools list
        let mut uncovered_tools = Vec::new();
        for (tool_name, occurrence_count) in &tool_occurrences {
            if !covered_tools.contains(tool_name) {
                uncovered_tools.push(UncoveredTool {
                    tool_name: tool_name.clone(),
                    occurrence_count: *occurrence_count,
                    last_seen: tool_last_seen.get(tool_name).cloned(),
                });
            }
        }
        // Sort uncovered tools by occurrence count descending for deterministic output
        uncovered_tools.sort_by(|a, b| b.occurrence_count.cmp(&a.occurrence_count));

        // Compute coverage scores
        let active_count = active_policies.len() as f64;
        let coverage_score = safe_divide_f64(active_count, total_policies as f64);

        let total_distinct_tools = tool_occurrences.len() as f64;
        let covered_tool_count = covered_tools.len() as f64;
        let tool_coverage_score = safe_divide_f64(covered_tool_count, total_distinct_tools);

        CoverageReport {
            total_evaluations,
            total_policies,
            dead_policies,
            active_policies,
            uncovered_tools,
            coverage_score,
            tool_coverage_score,
        }
    }
}

/// Safe division that returns 0.0 on divide-by-zero, NaN, or Infinity.
/// Result is clamped to [0.0, 1.0].
fn safe_divide_f64(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        return 0.0;
    }
    let result = numerator / denominator;
    if result.is_nan() || result.is_infinite() {
        return 0.0;
    }
    result.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::{Policy, PolicyType};

    fn make_policy(id: &str, name: &str) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            policy_type: PolicyType::Allow,
            priority: 0,
            path_rules: None,
            network_rules: None,
        }
    }

    fn make_record(tool: &str, policy_id: Option<&str>, ts: &str) -> EvaluationRecord {
        EvaluationRecord {
            tool: tool.to_string(),
            matched_policy_id: policy_id.map(|s| s.to_string()),
            timestamp: ts.to_string(),
        }
    }

    #[test]
    fn test_coverage_empty_policies_and_records() {
        let report = CoverageAnalyzer::analyze(&[], &[]);
        assert_eq!(report.total_evaluations, 0);
        assert_eq!(report.total_policies, 0);
        assert!(report.dead_policies.is_empty());
        assert!(report.active_policies.is_empty());
        assert!(report.uncovered_tools.is_empty());
        assert!((report.coverage_score - 0.0).abs() < f64::EPSILON);
        assert!((report.tool_coverage_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_all_dead_policies() {
        let policies = vec![make_policy("p1", "Policy A"), make_policy("p2", "Policy B")];
        let records = vec![make_record("tool_x", None, "2026-01-01T00:00:00Z")];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.dead_policies.len(), 2);
        assert_eq!(report.active_policies.len(), 0);
        assert!((report.coverage_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_all_active_policies() {
        let policies = vec![make_policy("p1", "Policy A"), make_policy("p2", "Policy B")];
        let records = vec![
            make_record("tool_a", Some("p1"), "2026-01-01T00:00:00Z"),
            make_record("tool_b", Some("p2"), "2026-01-01T01:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.dead_policies.len(), 0);
        assert_eq!(report.active_policies.len(), 2);
        assert!((report.coverage_score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_mixed_dead_and_active() {
        let policies = vec![
            make_policy("p1", "Active Policy"),
            make_policy("p2", "Dead Policy"),
            make_policy("p3", "Also Active"),
        ];
        let records = vec![
            make_record("tool_a", Some("p1"), "2026-01-01T00:00:00Z"),
            make_record("tool_b", Some("p3"), "2026-01-01T01:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.dead_policies.len(), 1);
        assert_eq!(report.dead_policies[0].policy_id, "p2");
        assert_eq!(report.active_policies.len(), 2);
        // coverage_score = 2/3
        assert!((report.coverage_score - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn test_coverage_uncovered_tools() {
        let policies = vec![make_policy("p1", "Policy A")];
        let records = vec![
            make_record("covered_tool", Some("p1"), "2026-01-01T00:00:00Z"),
            make_record("uncovered_tool", None, "2026-01-01T01:00:00Z"),
            make_record("uncovered_tool", None, "2026-01-01T02:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.uncovered_tools.len(), 1);
        assert_eq!(report.uncovered_tools[0].tool_name, "uncovered_tool");
        assert_eq!(report.uncovered_tools[0].occurrence_count, 2);
    }

    #[test]
    fn test_coverage_tool_coverage_score() {
        let policies = vec![make_policy("p1", "Policy A")];
        let records = vec![
            make_record("tool_a", Some("p1"), "2026-01-01T00:00:00Z"),
            make_record("tool_b", None, "2026-01-01T01:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        // 1 covered tool out of 2 distinct tools = 0.5
        assert!((report.tool_coverage_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_match_count_per_policy() {
        let policies = vec![make_policy("p1", "Busy Policy")];
        let records = vec![
            make_record("t1", Some("p1"), "2026-01-01T00:00:00Z"),
            make_record("t2", Some("p1"), "2026-01-01T01:00:00Z"),
            make_record("t3", Some("p1"), "2026-01-01T02:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.active_policies.len(), 1);
        assert_eq!(report.active_policies[0].match_count, 3);
        assert!(!report.active_policies[0].is_dead);
    }

    #[test]
    fn test_coverage_last_matched_timestamp() {
        let policies = vec![make_policy("p1", "Policy")];
        let records = vec![
            make_record("t1", Some("p1"), "2026-01-01T00:00:00Z"),
            make_record("t2", Some("p1"), "2026-01-02T00:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        // Last matched is the timestamp of the last record (order-dependent)
        assert_eq!(
            report.active_policies[0].last_matched.as_deref(),
            Some("2026-01-02T00:00:00Z")
        );
    }

    #[test]
    fn test_coverage_dead_policy_has_no_last_matched() {
        let policies = vec![make_policy("dead", "Dead Policy")];
        let records = vec![make_record("tool", None, "2026-01-01T00:00:00Z")];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.dead_policies.len(), 1);
        assert!(report.dead_policies[0].last_matched.is_none());
        assert!(report.dead_policies[0].is_dead);
    }

    #[test]
    fn test_coverage_no_records_all_dead() {
        let policies = vec![make_policy("p1", "Policy A"), make_policy("p2", "Policy B")];
        let report = CoverageAnalyzer::analyze(&policies, &[]);
        assert_eq!(report.total_evaluations, 0);
        assert_eq!(report.dead_policies.len(), 2);
        assert_eq!(report.active_policies.len(), 0);
        assert!((report.coverage_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_pct_calculation() {
        let policies = vec![make_policy("p1", "Policy")];
        let records = vec![
            make_record("t1", Some("p1"), "2026-01-01T00:00:00Z"),
            make_record("t2", None, "2026-01-01T01:00:00Z"),
            make_record("t3", None, "2026-01-01T02:00:00Z"),
            make_record("t4", Some("p1"), "2026-01-01T03:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        // p1 matched 2 out of 4 evaluations = 0.5
        assert!((report.active_policies[0].coverage_pct - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_uncovered_tool_last_seen() {
        let policies: Vec<Policy> = vec![];
        let records = vec![
            make_record("orphan", None, "2026-01-01T00:00:00Z"),
            make_record("orphan", None, "2026-02-01T00:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.uncovered_tools.len(), 1);
        assert_eq!(
            report.uncovered_tools[0].last_seen.as_deref(),
            Some("2026-02-01T00:00:00Z")
        );
    }

    #[test]
    fn test_coverage_uncovered_sorted_by_occurrence() {
        let policies: Vec<Policy> = vec![];
        let records = vec![
            make_record("rare", None, "2026-01-01T00:00:00Z"),
            make_record("common", None, "2026-01-01T01:00:00Z"),
            make_record("common", None, "2026-01-01T02:00:00Z"),
            make_record("common", None, "2026-01-01T03:00:00Z"),
        ];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.uncovered_tools.len(), 2);
        assert_eq!(report.uncovered_tools[0].tool_name, "common");
        assert_eq!(report.uncovered_tools[0].occurrence_count, 3);
        assert_eq!(report.uncovered_tools[1].tool_name, "rare");
        assert_eq!(report.uncovered_tools[1].occurrence_count, 1);
    }

    #[test]
    fn test_coverage_safe_divide_zero_denominator() {
        assert!((safe_divide_f64(5.0, 0.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_safe_divide_clamps_to_one() {
        // Numerator > denominator should clamp to 1.0
        assert!((safe_divide_f64(10.0, 5.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_safe_divide_nan() {
        assert!((safe_divide_f64(f64::NAN, 1.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_policies_with_no_records_for_tool() {
        // Policy exists but no evaluation records at all
        let policies = vec![make_policy("p1", "Lonely Policy")];
        let records: Vec<EvaluationRecord> = vec![];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        assert_eq!(report.dead_policies.len(), 1);
        assert_eq!(report.dead_policies[0].coverage_pct, 0.0);
        assert!(report.uncovered_tools.is_empty());
        assert!((report.tool_coverage_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_coverage_unknown_policy_id_in_record() {
        // A record references a policy ID not in the policies list
        let policies = vec![make_policy("p1", "Known Policy")];
        let records = vec![make_record(
            "tool",
            Some("p_unknown"),
            "2026-01-01T00:00:00Z",
        )];
        let report = CoverageAnalyzer::analyze(&policies, &records);
        // p1 is dead (never matched), p_unknown is tracked in match_count map but not a known policy
        assert_eq!(report.dead_policies.len(), 1);
        assert_eq!(report.dead_policies[0].policy_id, "p1");
        // tool is covered (had a matched_policy_id), so not in uncovered
        assert!(report.uncovered_tools.is_empty());
    }
}
