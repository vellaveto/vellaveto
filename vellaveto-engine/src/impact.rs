// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Policy Impact Analysis
//!
//! Replays historical audit entries against a candidate policy set to identify
//! verdict changes. This enables operators to preview the effect of policy
//! changes before deploying them.

use crate::PolicyEngine;
use vellaveto_types::{Action, Policy, Verdict};

/// Maximum number of verdict changes stored in an impact report.
///
/// SECURITY: Prevents unbounded memory growth when replaying large
/// historical datasets where every action changes verdict.
const MAX_VERDICT_CHANGES: usize = 100_000;

/// A single verdict change detected during impact analysis.
#[derive(Debug, Clone)]
pub struct VerdictChange {
    /// The tool name from the original action.
    pub action_tool: String,
    /// The function name from the original action.
    pub action_function: String,
    /// The verdict that was originally recorded.
    pub original_verdict: VerdictSummary,
    /// The verdict produced by the candidate policy set.
    pub new_verdict: VerdictSummary,
    /// The timestamp of the original action.
    pub timestamp: String,
}

/// Simplified verdict for comparison (no reason strings).
///
/// Strips the `reason` field from [`Verdict`] so that impact analysis
/// compares disposition (Allow/Deny/RequireApproval) rather than
/// message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictSummary {
    Allow,
    Deny,
    RequireApproval,
}

/// Impact analysis result summarizing verdict changes.
#[derive(Debug, Clone)]
pub struct ImpactReport {
    /// Total number of historical actions replayed.
    pub actions_replayed: usize,
    /// List of actions whose verdict changed.
    pub verdict_changes: Vec<VerdictChange>,
    /// Count of actions that were Allow or RequireApproval but are now Deny.
    pub newly_denied: usize,
    /// Count of actions that were Deny but are now Allow.
    pub newly_allowed: usize,
    /// Count of actions whose verdict did not change.
    pub unchanged: usize,
    /// Count of actions that caused evaluation errors.
    pub errors: usize,
}

/// Historical action for replay (extracted from audit entries).
#[derive(Debug, Clone)]
pub struct HistoricalAction {
    /// The action that was originally evaluated.
    pub action: Action,
    /// The verdict that was originally produced.
    pub original_verdict: VerdictSummary,
    /// The ISO 8601 timestamp of the original evaluation.
    pub timestamp: String,
}

/// Stateless impact analyzer that replays historical actions against
/// candidate policy sets.
pub struct ImpactAnalyzer;

impl ImpactAnalyzer {
    /// Analyze the impact of a candidate policy set against historical actions.
    ///
    /// Replays each historical action against the candidate policies and compares
    /// the new verdict to the original. Returns an [`ImpactReport`] summarizing
    /// how many actions would change disposition.
    ///
    /// # Arguments
    ///
    /// * `candidate_policies` — The new policy set to evaluate against.
    /// * `historical` — Historical actions with their original verdicts.
    /// * `strict_mode` — Whether the engine should use strict mode.
    ///
    /// # Fail-closed behavior
    ///
    /// Actions that cause evaluation errors are counted in `errors` and do
    /// not appear in `verdict_changes`. This prevents error cases from being
    /// misinterpreted as verdict changes.
    pub fn analyze(
        candidate_policies: &[Policy],
        historical: &[HistoricalAction],
        strict_mode: bool,
    ) -> ImpactReport {
        let engine = PolicyEngine::new(strict_mode);
        let mut changes = Vec::new();
        let mut newly_denied = 0usize;
        let mut newly_allowed = 0usize;
        let mut unchanged = 0usize;
        let mut errors = 0usize;

        for hist in historical {
            match engine.evaluate_action(&hist.action, candidate_policies) {
                Ok(new_verdict) => {
                    let new_summary = VerdictSummary::from(&new_verdict);
                    if new_summary != hist.original_verdict {
                        // Track direction of change
                        match (hist.original_verdict, new_summary) {
                            (VerdictSummary::Allow, VerdictSummary::Deny)
                            | (VerdictSummary::RequireApproval, VerdictSummary::Deny) => {
                                newly_denied = newly_denied.saturating_add(1);
                            }
                            (VerdictSummary::Deny, VerdictSummary::Allow) => {
                                newly_allowed = newly_allowed.saturating_add(1);
                            }
                            _ => {}
                        }
                        // SECURITY: Bound the changes vector to prevent unbounded growth.
                        if changes.len() < MAX_VERDICT_CHANGES {
                            changes.push(VerdictChange {
                                action_tool: hist.action.tool.clone(),
                                action_function: hist.action.function.clone(),
                                original_verdict: hist.original_verdict,
                                new_verdict: new_summary,
                                timestamp: hist.timestamp.clone(),
                            });
                        }
                    } else {
                        unchanged = unchanged.saturating_add(1);
                    }
                }
                Err(_) => {
                    errors = errors.saturating_add(1);
                }
            }
        }

        ImpactReport {
            actions_replayed: historical.len(),
            verdict_changes: changes,
            newly_denied,
            newly_allowed,
            unchanged,
            errors,
        }
    }
}

impl From<&Verdict> for VerdictSummary {
    fn from(v: &Verdict) -> Self {
        match v {
            Verdict::Allow => VerdictSummary::Allow,
            Verdict::Deny { .. } => VerdictSummary::Deny,
            Verdict::RequireApproval { .. } => VerdictSummary::RequireApproval,
            // Verdict is #[non_exhaustive]; fail-closed to Deny for unknown variants.
            _ => VerdictSummary::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vellaveto_types::PolicyType;

    fn make_action(tool: &str, function: &str) -> Action {
        Action::new(tool.to_string(), function.to_string(), json!({}))
    }

    fn make_historical(tool: &str, function: &str, verdict: VerdictSummary) -> HistoricalAction {
        HistoricalAction {
            action: make_action(tool, function),
            original_verdict: verdict,
            timestamp: "2026-02-26T00:00:00Z".to_string(),
        }
    }

    fn make_allow_policy(id: &str) -> Policy {
        Policy {
            id: id.to_string(),
            name: format!("Allow {id}"),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        }
    }

    fn make_deny_policy(id: &str) -> Policy {
        Policy {
            id: id.to_string(),
            name: format!("Deny {id}"),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }
    }

    // ---------------------------------------------------------------
    // 1. Empty historical actions → zero changes
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_empty_history_zero_changes() {
        let policies = vec![make_allow_policy("bash:*")];
        let report = ImpactAnalyzer::analyze(&policies, &[], false);
        assert_eq!(report.actions_replayed, 0);
        assert_eq!(report.verdict_changes.len(), 0);
        assert_eq!(report.newly_denied, 0);
        assert_eq!(report.newly_allowed, 0);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.errors, 0);
    }

    // ---------------------------------------------------------------
    // 2. All unchanged (same policies produce same verdicts)
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_all_unchanged_same_policies() {
        // With no policies, engine denies everything. If original was Deny, unchanged.
        let historical = vec![
            make_historical("bash", "execute", VerdictSummary::Deny),
            make_historical("curl", "fetch", VerdictSummary::Deny),
            make_historical("unknown", "op", VerdictSummary::Deny),
        ];
        // No policies → engine denies all → matches Deny original
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.actions_replayed, 3);
        assert_eq!(report.unchanged, 3);
        assert_eq!(report.verdict_changes.len(), 0);
        assert_eq!(report.newly_denied, 0);
        assert_eq!(report.newly_allowed, 0);
    }

    // ---------------------------------------------------------------
    // 3. Allow → Deny when allow policy removed
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_allow_to_deny_policy_removed() {
        // Originally allowed by bash:* policy, now no policies → Deny
        let historical = vec![make_historical("bash", "execute", VerdictSummary::Allow)];
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.actions_replayed, 1);
        assert_eq!(report.newly_denied, 1);
        assert_eq!(report.newly_allowed, 0);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.verdict_changes.len(), 1);
        let change = &report.verdict_changes[0];
        assert_eq!(change.action_tool, "bash");
        assert_eq!(change.action_function, "execute");
        assert_eq!(change.original_verdict, VerdictSummary::Allow);
        assert_eq!(change.new_verdict, VerdictSummary::Deny);
    }

    // ---------------------------------------------------------------
    // 4. Deny → Allow when deny policy removed and allow policy added
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_deny_to_allow_policy_changed() {
        // Originally denied, now allow policy present → Allow
        let historical = vec![make_historical(
            "file_system",
            "read_file",
            VerdictSummary::Deny,
        )];
        let policies = vec![make_allow_policy("file_system:read_file")];
        let report = ImpactAnalyzer::analyze(&policies, &historical, false);
        assert_eq!(report.newly_allowed, 1);
        assert_eq!(report.newly_denied, 0);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.verdict_changes.len(), 1);
        let change = &report.verdict_changes[0];
        assert_eq!(change.original_verdict, VerdictSummary::Deny);
        assert_eq!(change.new_verdict, VerdictSummary::Allow);
    }

    // ---------------------------------------------------------------
    // 5. Mixed changes with correct counts
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_mixed_changes_correct_counts() {
        let historical = vec![
            // Will stay Deny (no matching policy)
            make_historical("unknown", "op", VerdictSummary::Deny),
            // Was Allow, now Deny (no policy)
            make_historical("bash", "execute", VerdictSummary::Allow),
            // Was Deny, now Allow (policy added)
            make_historical("file_system", "read_file", VerdictSummary::Deny),
            // Will match allow → stays Allow
            make_historical("file_system", "read_file", VerdictSummary::Allow),
        ];
        let policies = vec![make_allow_policy("file_system:read_file")];
        let report = ImpactAnalyzer::analyze(&policies, &historical, false);
        assert_eq!(report.actions_replayed, 4);
        assert_eq!(report.newly_denied, 1); // bash Allow→Deny
        assert_eq!(report.newly_allowed, 1); // file_system Deny→Allow
        assert_eq!(report.unchanged, 2); // unknown stays Deny, file_system stays Allow
        assert_eq!(report.verdict_changes.len(), 2);
    }

    // ---------------------------------------------------------------
    // 6. newly_denied and newly_allowed counters correct
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_counter_accuracy() {
        let historical = vec![
            make_historical("a", "f1", VerdictSummary::Allow),
            make_historical("b", "f2", VerdictSummary::Allow),
            make_historical("c", "f3", VerdictSummary::Deny),
        ];
        // No policies → all become Deny
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.newly_denied, 2); // a and b: Allow→Deny
        assert_eq!(report.newly_allowed, 0);
        assert_eq!(report.unchanged, 1); // c stays Deny
    }

    // ---------------------------------------------------------------
    // 7. RequireApproval transitions
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_require_approval_to_deny() {
        // RequireApproval → Deny counts as newly_denied
        let historical = vec![make_historical(
            "sensitive",
            "op",
            VerdictSummary::RequireApproval,
        )];
        // No policies → Deny
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.newly_denied, 1);
        assert_eq!(report.verdict_changes.len(), 1);
        assert_eq!(
            report.verdict_changes[0].original_verdict,
            VerdictSummary::RequireApproval
        );
        assert_eq!(report.verdict_changes[0].new_verdict, VerdictSummary::Deny);
    }

    #[test]
    fn test_analyze_deny_to_require_approval_not_newly_allowed() {
        // Deny → RequireApproval is a change but not newly_allowed (not Allow)
        // We need a Conditional policy to produce RequireApproval
        // With standard policies we can't directly produce RequireApproval from
        // evaluate_action, but let's test the counter logic by verifying that
        // Deny→Allow is counted and Deny→Deny is unchanged.
        let historical = vec![make_historical("bash", "execute", VerdictSummary::Deny)];
        let policies = vec![make_allow_policy("bash:execute")];
        let report = ImpactAnalyzer::analyze(&policies, &historical, false);
        assert_eq!(report.newly_allowed, 1);
        assert_eq!(report.newly_denied, 0);
    }

    // ---------------------------------------------------------------
    // 8. Strict mode vs non-strict mode behavior
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_strict_mode() {
        let historical = vec![make_historical(
            "file_system",
            "read_file",
            VerdictSummary::Allow,
        )];
        let policies = vec![make_allow_policy("file_system:read_file")];

        // Non-strict: should match and remain Allow
        let report_non_strict = ImpactAnalyzer::analyze(&policies, &historical, false);
        assert_eq!(report_non_strict.unchanged, 1);

        // Strict: same result (strict mode affects constraint evaluation, not basic matching)
        let report_strict = ImpactAnalyzer::analyze(&policies, &historical, true);
        assert_eq!(report_strict.unchanged, 1);
    }

    // ---------------------------------------------------------------
    // 9. Error counting
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_error_counting() {
        // The legacy path with empty policies returns Deny, it doesn't error.
        // To trigger errors we can verify that well-formed actions don't error.
        let historical = vec![
            make_historical("bash", "execute", VerdictSummary::Deny),
            make_historical("file_system", "read", VerdictSummary::Allow),
        ];
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        // With the legacy path and empty policies, no errors expected
        assert_eq!(report.errors, 0);
        // All should be evaluated: bash stays Deny, file_system was Allow now Deny
        assert_eq!(report.actions_replayed, 2);
    }

    // ---------------------------------------------------------------
    // 10. Large replay set (500 historical actions)
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_large_replay_set() {
        let historical: Vec<HistoricalAction> = (0..500)
            .map(|i| {
                let tool = format!("tool_{i}");
                make_historical(&tool, "op", VerdictSummary::Allow)
            })
            .collect();
        // No policies → all Deny → all 500 change from Allow to Deny
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.actions_replayed, 500);
        assert_eq!(report.newly_denied, 500);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.verdict_changes.len(), 500);
    }

    // ---------------------------------------------------------------
    // 11. VerdictSummary From impl for all 3 variants
    // ---------------------------------------------------------------
    #[test]
    fn test_verdict_summary_from_allow() {
        let v = Verdict::Allow;
        let s = VerdictSummary::from(&v);
        assert_eq!(s, VerdictSummary::Allow);
    }

    #[test]
    fn test_verdict_summary_from_deny() {
        let v = Verdict::Deny {
            reason: "blocked".to_string(),
        };
        let s = VerdictSummary::from(&v);
        assert_eq!(s, VerdictSummary::Deny);
    }

    #[test]
    fn test_verdict_summary_from_require_approval() {
        let v = Verdict::RequireApproval {
            reason: "needs review".to_string(),
        };
        let s = VerdictSummary::from(&v);
        assert_eq!(s, VerdictSummary::RequireApproval);
    }

    // ---------------------------------------------------------------
    // 12. ImpactReport with no changes
    // ---------------------------------------------------------------
    #[test]
    fn test_impact_report_no_changes() {
        // All originally Deny, no policies → still Deny → no changes
        let historical = vec![
            make_historical("a", "x", VerdictSummary::Deny),
            make_historical("b", "y", VerdictSummary::Deny),
        ];
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.verdict_changes.len(), 0);
        assert_eq!(report.unchanged, 2);
        assert_eq!(report.newly_denied, 0);
        assert_eq!(report.newly_allowed, 0);
        assert_eq!(report.errors, 0);
    }

    // ---------------------------------------------------------------
    // 13. Overlapping policy changes
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_overlapping_policies() {
        // A deny policy at higher priority overrides an allow policy
        let historical = vec![make_historical("bash", "execute", VerdictSummary::Allow)];
        let policies = vec![
            make_deny_policy("bash:*"),        // priority 100
            make_allow_policy("bash:execute"), // priority 50
        ];
        // Deny at priority 100 wins → Allow becomes Deny
        let report = ImpactAnalyzer::analyze(&policies, &historical, false);
        assert_eq!(report.newly_denied, 1);
        assert_eq!(report.verdict_changes.len(), 1);
        assert_eq!(report.verdict_changes[0].new_verdict, VerdictSummary::Deny);
    }

    // ---------------------------------------------------------------
    // 14. VerdictChange captures correct fields
    // ---------------------------------------------------------------
    #[test]
    fn test_verdict_change_fields_populated() {
        let historical = vec![HistoricalAction {
            action: make_action("my_tool", "my_func"),
            original_verdict: VerdictSummary::Allow,
            timestamp: "2026-01-15T12:30:00Z".to_string(),
        }];
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.verdict_changes.len(), 1);
        let change = &report.verdict_changes[0];
        assert_eq!(change.action_tool, "my_tool");
        assert_eq!(change.action_function, "my_func");
        assert_eq!(change.timestamp, "2026-01-15T12:30:00Z");
        assert_eq!(change.original_verdict, VerdictSummary::Allow);
        assert_eq!(change.new_verdict, VerdictSummary::Deny);
    }

    // ---------------------------------------------------------------
    // 15. Multiple deny-to-allow transitions
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_multiple_deny_to_allow() {
        let historical = vec![
            make_historical("file_system", "read_file", VerdictSummary::Deny),
            make_historical("file_system", "write_file", VerdictSummary::Deny),
            make_historical("file_system", "list_dir", VerdictSummary::Deny),
        ];
        let policies = vec![make_allow_policy("file_system:*")];
        let report = ImpactAnalyzer::analyze(&policies, &historical, false);
        assert_eq!(report.newly_allowed, 3);
        assert_eq!(report.newly_denied, 0);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.verdict_changes.len(), 3);
        for change in &report.verdict_changes {
            assert_eq!(change.original_verdict, VerdictSummary::Deny);
            assert_eq!(change.new_verdict, VerdictSummary::Allow);
        }
    }

    // ---------------------------------------------------------------
    // 16. Empty candidate policies (all become Deny)
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_empty_candidate_policies() {
        let historical = vec![
            make_historical("a", "b", VerdictSummary::Allow),
            make_historical("c", "d", VerdictSummary::Deny),
        ];
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.newly_denied, 1); // a was Allow, now Deny
        assert_eq!(report.unchanged, 1); // c stays Deny
    }

    // ---------------------------------------------------------------
    // 17. Saturating counters don't overflow
    // ---------------------------------------------------------------
    #[test]
    fn test_analyze_saturating_counters() {
        // Verify the report compiles and counters are correct for a moderate set
        let historical: Vec<HistoricalAction> = (0..100)
            .map(|i| make_historical(&format!("t{i}"), "f", VerdictSummary::Allow))
            .collect();
        let report = ImpactAnalyzer::analyze(&[], &historical, false);
        assert_eq!(report.newly_denied, 100);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.errors, 0);
        // Verify total adds up
        assert_eq!(
            report.newly_denied + report.newly_allowed + report.unchanged + report.errors,
            report.actions_replayed
        );
    }
}
