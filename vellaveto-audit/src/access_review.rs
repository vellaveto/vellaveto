//! SOC 2 Type II access review report generator (Phase 38).
//!
//! Scans audit entries over a review period and cross-references with
//! least-agency data to produce CC6-focused access review reports with
//! reviewer attestation fields.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use vellaveto_types::compliance::{
    AccessReviewEntry, AccessReviewReport, AttestationStatus, Cc6Evidence, ReviewerAttestation,
};
use vellaveto_types::LeastAgencyReport;

use crate::types::AuditEntry;

/// Maximum number of audit entries to process in a single report.
/// Prevents unbounded memory usage on very large audit logs.
pub const MAX_ENTRIES_PER_REPORT: usize = 1_000_000;

/// Maximum number of distinct agents in a single report.
/// Prevents unbounded per-agent aggregation maps.
pub const MAX_AGENTS_PER_REPORT: usize = 10_000;

/// Per-agent accumulator used during report generation.
struct AgentAccumulator {
    session_ids: BTreeSet<String>,
    first_access: String,
    last_access: String,
    total_evaluations: u64,
    allow_count: u64,
    deny_count: u64,
    require_approval_count: u64,
    tools_accessed: BTreeSet<String>,
    functions_called: BTreeSet<String>,
}

/// Generate a SOC 2 Type II access review report from audit entries.
///
/// # Arguments
/// * `entries` — All audit entries (pre-loaded). Filtered to the review period internally.
/// * `org_name` — Organization name for the report header.
/// * `period_start` — Review period start (RFC 3339 UTC).
/// * `period_end` — Review period end (RFC 3339 UTC).
/// * `least_agency` — Map of `(agent_id, session_id)` → `LeastAgencyReport`.
pub fn generate_access_review(
    entries: &[AuditEntry],
    org_name: &str,
    period_start: &str,
    period_end: &str,
    least_agency: &std::collections::HashMap<(String, String), LeastAgencyReport>,
) -> AccessReviewReport {
    let mut agents: BTreeMap<String, AgentAccumulator> = BTreeMap::new();
    let mut total_evaluations: u64 = 0;
    let mut processed = 0usize;

    for entry in entries {
        // Bound processing
        if processed >= MAX_ENTRIES_PER_REPORT {
            tracing::warn!(
                max = MAX_ENTRIES_PER_REPORT,
                "Access review report truncated at max entries"
            );
            break;
        }

        // Skip internal vellaveto entries (heartbeats, circuit breaker, etc.)
        if entry.action.tool == "vellaveto" {
            continue;
        }

        // Filter by period — RFC 3339 strings sort lexicographically for UTC timestamps
        if entry.timestamp.as_str() < period_start || entry.timestamp.as_str() > period_end {
            continue;
        }

        processed += 1;

        // Extract agent_id from metadata, falling back to tool name
        let agent_id = entry
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&entry.action.tool)
            .to_string();

        // Bound distinct agents
        if !agents.contains_key(&agent_id) && agents.len() >= MAX_AGENTS_PER_REPORT {
            tracing::warn!(
                max = MAX_AGENTS_PER_REPORT,
                "Access review report truncated at max agents"
            );
            continue;
        }

        let session_id = entry
            .metadata
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let acc = agents.entry(agent_id).or_insert_with(|| AgentAccumulator {
            session_ids: BTreeSet::new(),
            first_access: entry.timestamp.clone(),
            last_access: entry.timestamp.clone(),
            total_evaluations: 0,
            allow_count: 0,
            deny_count: 0,
            require_approval_count: 0,
            tools_accessed: BTreeSet::new(),
            functions_called: BTreeSet::new(),
        });

        acc.session_ids.insert(session_id);
        acc.total_evaluations += 1;
        total_evaluations += 1;

        // Update timestamps
        if entry.timestamp < acc.first_access {
            acc.first_access.clone_from(&entry.timestamp);
        }
        if entry.timestamp > acc.last_access {
            acc.last_access.clone_from(&entry.timestamp);
        }

        // Count verdict types
        match &entry.verdict {
            vellaveto_types::Verdict::Allow => acc.allow_count += 1,
            vellaveto_types::Verdict::Deny { .. } => acc.deny_count += 1,
            vellaveto_types::Verdict::RequireApproval { .. } => acc.require_approval_count += 1,
            _ => acc.deny_count += 1, // Fail-closed: unknown verdicts count as deny
        }

        acc.tools_accessed.insert(entry.action.tool.clone());
        if !entry.action.function.is_empty() {
            acc.functions_called.insert(entry.action.function.clone());
        }
    }

    // Build per-agent entries with least-agency cross-reference
    let mut optimal_count = 0usize;
    let mut review_grants_count = 0usize;
    let mut narrow_scope_count = 0usize;
    let mut critical_count = 0usize;

    let review_entries: Vec<AccessReviewEntry> = agents
        .into_iter()
        .map(|(agent_id, acc)| {
            // Find any least-agency report for this agent (across all sessions)
            let la_report = acc
                .session_ids
                .iter()
                .find_map(|sid| least_agency.get(&(agent_id.clone(), sid.clone())));

            let (permissions_granted, permissions_used, usage_ratio, unused_permissions, recommendation) =
                if let Some(la) = la_report {
                    let rec = format!("{:?}", la.recommendation);
                    match la.recommendation {
                        vellaveto_types::AgencyRecommendation::Optimal => optimal_count += 1,
                        vellaveto_types::AgencyRecommendation::ReviewGrants => {
                            review_grants_count += 1
                        }
                        vellaveto_types::AgencyRecommendation::NarrowScope => {
                            narrow_scope_count += 1
                        }
                        vellaveto_types::AgencyRecommendation::Critical => critical_count += 1,
                    }
                    (
                        la.granted_permissions,
                        la.used_permissions,
                        la.usage_ratio,
                        la.unused_permissions.clone(),
                        rec,
                    )
                } else {
                    (0, 0, 0.0, Vec::new(), "NoData".to_string())
                };

            AccessReviewEntry {
                agent_id,
                session_ids: acc.session_ids.into_iter().collect(),
                first_access: acc.first_access,
                last_access: acc.last_access,
                total_evaluations: acc.total_evaluations,
                allow_count: acc.allow_count,
                deny_count: acc.deny_count,
                require_approval_count: acc.require_approval_count,
                tools_accessed: acc.tools_accessed.into_iter().collect(),
                functions_called: acc.functions_called.into_iter().collect(),
                permissions_granted,
                permissions_used,
                usage_ratio,
                unused_permissions,
                agency_recommendation: recommendation,
            }
        })
        .collect();

    let total_agents = review_entries.len();

    let cc6_evidence = Cc6Evidence {
        cc6_1_evidence: format!(
            "All {} agent(s) subject to policy-based access control. \
             {} total evaluations recorded during the review period.",
            total_agents, total_evaluations
        ),
        cc6_2_evidence: format!(
            "Agent identities validated prior to access grants. \
             {} agent(s) tracked with session-level granularity.",
            total_agents
        ),
        cc6_3_evidence: format!(
            "Unused permissions tracked via least-agency monitoring. \
             {} optimal, {} review-needed, {} narrow-scope, {} critical agent(s).",
            optimal_count, review_grants_count, narrow_scope_count, critical_count
        ),
        optimal_count,
        review_grants_count,
        narrow_scope_count,
        critical_count,
    };

    AccessReviewReport {
        generated_at: Utc::now().to_rfc3339(),
        organization_name: org_name.to_string(),
        period_start: period_start.to_string(),
        period_end: period_end.to_string(),
        total_agents,
        total_evaluations,
        entries: review_entries,
        cc6_evidence,
        attestation: ReviewerAttestation {
            reviewer_name: String::new(),
            reviewer_title: String::new(),
            reviewed_at: None,
            notes: String::new(),
            status: AttestationStatus::Pending,
        },
    }
}

/// Escape a string for safe HTML embedding.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render an access review report as self-contained HTML.
pub fn render_html(report: &AccessReviewReport) -> String {
    let mut html = String::with_capacity(8192);

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str("<title>SOC 2 Type II Access Review Report</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2em; color: #333; }\n");
    html.push_str("h1, h2, h3 { color: #1a1a2e; }\n");
    html.push_str("table { border-collapse: collapse; width: 100%; margin: 1em 0; }\n");
    html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
    html.push_str("th { background-color: #f4f4f8; }\n");
    html.push_str("tr:nth-child(even) { background-color: #fafafa; }\n");
    html.push_str(".summary { background: #f0f4ff; padding: 1em; border-radius: 6px; margin: 1em 0; }\n");
    html.push_str(".attestation { border: 2px solid #ccc; padding: 1em; margin: 2em 0; border-radius: 6px; }\n");
    html.push_str(".optimal { color: #2d8a4e; } .review { color: #b8860b; } .narrow { color: #d4760a; } .critical { color: #c0392b; }\n");
    html.push_str("</style>\n</head>\n<body>\n");

    // Header
    html.push_str("<h1>SOC 2 Type II Access Review Report</h1>\n");
    html.push_str(&format!(
        "<p><strong>Organization:</strong> {}</p>\n",
        html_escape(&report.organization_name)
    ));
    html.push_str(&format!(
        "<p><strong>Review Period:</strong> {} to {}</p>\n",
        html_escape(&report.period_start),
        html_escape(&report.period_end)
    ));
    html.push_str(&format!(
        "<p><strong>Generated:</strong> {}</p>\n",
        html_escape(&report.generated_at)
    ));

    // Summary
    html.push_str("<div class=\"summary\">\n");
    html.push_str("<h2>Summary</h2>\n");
    html.push_str("<table>\n<tr><th>Metric</th><th>Value</th></tr>\n");
    html.push_str(&format!(
        "<tr><td>Total Agents</td><td>{}</td></tr>\n",
        report.total_agents
    ));
    html.push_str(&format!(
        "<tr><td>Total Evaluations</td><td>{}</td></tr>\n",
        report.total_evaluations
    ));
    html.push_str(&format!(
        "<tr><td>Optimal Agents (&gt;80%)</td><td>{}</td></tr>\n",
        report.cc6_evidence.optimal_count
    ));
    html.push_str(&format!(
        "<tr><td>Review Needed (50-80%)</td><td>{}</td></tr>\n",
        report.cc6_evidence.review_grants_count
    ));
    html.push_str(&format!(
        "<tr><td>Narrow Scope (20-50%)</td><td>{}</td></tr>\n",
        report.cc6_evidence.narrow_scope_count
    ));
    html.push_str(&format!(
        "<tr><td>Critical (&lt;20%)</td><td>{}</td></tr>\n",
        report.cc6_evidence.critical_count
    ));
    html.push_str("</table>\n</div>\n");

    // CC6 Evidence
    html.push_str("<h2>CC6 Evidence</h2>\n");
    html.push_str("<table>\n<tr><th>Criterion</th><th>Evidence</th></tr>\n");
    html.push_str(&format!(
        "<tr><td>CC6.1</td><td>{}</td></tr>\n",
        html_escape(&report.cc6_evidence.cc6_1_evidence)
    ));
    html.push_str(&format!(
        "<tr><td>CC6.2</td><td>{}</td></tr>\n",
        html_escape(&report.cc6_evidence.cc6_2_evidence)
    ));
    html.push_str(&format!(
        "<tr><td>CC6.3</td><td>{}</td></tr>\n",
        html_escape(&report.cc6_evidence.cc6_3_evidence)
    ));
    html.push_str("</table>\n");

    // Per-agent table
    html.push_str("<h2>Agent Access Details</h2>\n");
    html.push_str("<table>\n<tr>");
    html.push_str("<th>Agent ID</th><th>Sessions</th><th>First Access</th><th>Last Access</th>");
    html.push_str("<th>Evaluations</th><th>Allow</th><th>Deny</th><th>Approval</th>");
    html.push_str("<th>Tools</th><th>Usage Ratio</th><th>Recommendation</th>");
    html.push_str("</tr>\n");

    for entry in &report.entries {
        let rec_class = match entry.agency_recommendation.as_str() {
            "Optimal" => "optimal",
            "ReviewGrants" => "review",
            "NarrowScope" => "narrow",
            "Critical" => "critical",
            _ => "",
        };
        html.push_str("<tr>");
        html.push_str(&format!("<td>{}</td>", html_escape(&entry.agent_id)));
        html.push_str(&format!("<td>{}</td>", entry.session_ids.len()));
        html.push_str(&format!("<td>{}</td>", html_escape(&entry.first_access)));
        html.push_str(&format!("<td>{}</td>", html_escape(&entry.last_access)));
        html.push_str(&format!("<td>{}</td>", entry.total_evaluations));
        html.push_str(&format!("<td>{}</td>", entry.allow_count));
        html.push_str(&format!("<td>{}</td>", entry.deny_count));
        html.push_str(&format!("<td>{}</td>", entry.require_approval_count));
        html.push_str(&format!("<td>{}</td>", entry.tools_accessed.len()));
        html.push_str(&format!("<td>{:.1}%</td>", entry.usage_ratio * 100.0));
        html.push_str(&format!(
            "<td class=\"{}\">{}</td>",
            rec_class,
            html_escape(&entry.agency_recommendation)
        ));
        html.push_str("</tr>\n");
    }
    html.push_str("</table>\n");

    // Attestation section
    html.push_str("<div class=\"attestation\">\n");
    html.push_str("<h2>Reviewer Attestation</h2>\n");
    html.push_str("<p><strong>Status:</strong> ");
    html.push_str(&html_escape(&report.attestation.status.to_string()));
    html.push_str("</p>\n");
    html.push_str("<table>\n");
    html.push_str("<tr><td><strong>Reviewer Name:</strong></td><td>___________________________</td></tr>\n");
    html.push_str("<tr><td><strong>Reviewer Title:</strong></td><td>___________________________</td></tr>\n");
    html.push_str("<tr><td><strong>Date:</strong></td><td>___________________________</td></tr>\n");
    html.push_str("<tr><td><strong>Notes:</strong></td><td>___________________________</td></tr>\n");
    html.push_str("</table>\n");
    html.push_str("</div>\n");

    html.push_str("</body>\n</html>\n");
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AuditEntry;
    use std::collections::HashMap;
    use vellaveto_types::{Action, AgencyRecommendation, LeastAgencyReport, Verdict};

    fn make_entry(
        tool: &str,
        function: &str,
        verdict: Verdict,
        timestamp: &str,
        agent_id: Option<&str>,
        session_id: Option<&str>,
    ) -> AuditEntry {
        let mut metadata = serde_json::json!({});
        if let Some(aid) = agent_id {
            metadata["agent_id"] = serde_json::json!(aid);
        }
        if let Some(sid) = session_id {
            metadata["session_id"] = serde_json::json!(sid);
        }
        AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            action: Action::new(tool, function, serde_json::json!({})),
            verdict,
            timestamp: timestamp.to_string(),
            metadata,
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
        }
    }

    #[test]
    fn test_empty_entries() {
        let report = generate_access_review(
            &[],
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert_eq!(report.total_agents, 0);
        assert_eq!(report.total_evaluations, 0);
        assert!(report.entries.is_empty());
        assert_eq!(report.organization_name, "Acme");
        assert_eq!(report.attestation.status, AttestationStatus::Pending);
    }

    #[test]
    fn test_single_agent() {
        let entries = vec![
            make_entry(
                "read_file",
                "execute",
                Verdict::Allow,
                "2026-01-15T10:00:00Z",
                Some("agent-1"),
                Some("sess-1"),
            ),
            make_entry(
                "write_file",
                "execute",
                Verdict::Deny {
                    reason: "blocked".into(),
                },
                "2026-01-16T10:00:00Z",
                Some("agent-1"),
                Some("sess-1"),
            ),
        ];
        let report = generate_access_review(
            &entries,
            "Test Corp",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert_eq!(report.total_agents, 1);
        assert_eq!(report.total_evaluations, 2);
        assert_eq!(report.entries[0].agent_id, "agent-1");
        assert_eq!(report.entries[0].allow_count, 1);
        assert_eq!(report.entries[0].deny_count, 1);
        assert_eq!(report.entries[0].tools_accessed.len(), 2);
    }

    #[test]
    fn test_multiple_agents() {
        let entries = vec![
            make_entry(
                "tool-a",
                "fn1",
                Verdict::Allow,
                "2026-01-10T10:00:00Z",
                Some("agent-1"),
                Some("sess-1"),
            ),
            make_entry(
                "tool-b",
                "fn2",
                Verdict::Allow,
                "2026-01-11T10:00:00Z",
                Some("agent-2"),
                Some("sess-2"),
            ),
            make_entry(
                "tool-c",
                "fn3",
                Verdict::RequireApproval {
                    reason: "needs review".into(),
                },
                "2026-01-12T10:00:00Z",
                Some("agent-2"),
                Some("sess-3"),
            ),
        ];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert_eq!(report.total_agents, 2);
        assert_eq!(report.total_evaluations, 3);
        // BTreeMap ordering: agent-1 < agent-2
        assert_eq!(report.entries[0].agent_id, "agent-1");
        assert_eq!(report.entries[1].agent_id, "agent-2");
        assert_eq!(report.entries[1].require_approval_count, 1);
        assert_eq!(report.entries[1].session_ids.len(), 2);
    }

    #[test]
    fn test_period_filtering() {
        let entries = vec![
            // Before period
            make_entry(
                "tool-a",
                "fn1",
                Verdict::Allow,
                "2025-12-31T23:59:59Z",
                Some("agent-1"),
                None,
            ),
            // In period
            make_entry(
                "tool-b",
                "fn2",
                Verdict::Allow,
                "2026-01-15T10:00:00Z",
                Some("agent-2"),
                None,
            ),
            // After period
            make_entry(
                "tool-c",
                "fn3",
                Verdict::Allow,
                "2026-02-02T00:00:00Z",
                Some("agent-3"),
                None,
            ),
        ];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert_eq!(report.total_agents, 1);
        assert_eq!(report.entries[0].agent_id, "agent-2");
    }

    #[test]
    fn test_internal_events_excluded() {
        let entries = vec![
            make_entry(
                "vellaveto",
                "heartbeat",
                Verdict::Allow,
                "2026-01-15T10:00:00Z",
                None,
                None,
            ),
            make_entry(
                "vellaveto",
                "circuit_breaker",
                Verdict::Allow,
                "2026-01-15T10:01:00Z",
                None,
                None,
            ),
            make_entry(
                "real_tool",
                "execute",
                Verdict::Allow,
                "2026-01-15T10:02:00Z",
                Some("agent-1"),
                None,
            ),
        ];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert_eq!(report.total_agents, 1);
        assert_eq!(report.total_evaluations, 1);
    }

    #[test]
    fn test_least_agency_data_present() {
        let entries = vec![make_entry(
            "tool-a",
            "fn1",
            Verdict::Allow,
            "2026-01-15T10:00:00Z",
            Some("agent-1"),
            Some("sess-1"),
        )];
        let mut la = HashMap::new();
        la.insert(
            ("agent-1".to_string(), "sess-1".to_string()),
            LeastAgencyReport {
                agent_id: "agent-1".to_string(),
                session_id: "sess-1".to_string(),
                granted_permissions: 10,
                used_permissions: 8,
                unused_permissions: vec!["p9".to_string(), "p10".to_string()],
                usage_ratio: 0.8,
                recommendation: AgencyRecommendation::Optimal,
            },
        );
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &la,
        );
        assert_eq!(report.entries[0].permissions_granted, 10);
        assert_eq!(report.entries[0].permissions_used, 8);
        assert_eq!(report.entries[0].usage_ratio, 0.8);
        assert_eq!(report.entries[0].agency_recommendation, "Optimal");
        assert_eq!(report.cc6_evidence.optimal_count, 1);
    }

    #[test]
    fn test_least_agency_data_absent() {
        let entries = vec![make_entry(
            "tool-a",
            "fn1",
            Verdict::Allow,
            "2026-01-15T10:00:00Z",
            Some("agent-1"),
            Some("sess-1"),
        )];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert_eq!(report.entries[0].permissions_granted, 0);
        assert_eq!(report.entries[0].agency_recommendation, "NoData");
    }

    #[test]
    fn test_cc6_counts() {
        let entries = vec![
            make_entry(
                "t1",
                "f",
                Verdict::Allow,
                "2026-01-15T10:00:00Z",
                Some("optimal-agent"),
                Some("s1"),
            ),
            make_entry(
                "t2",
                "f",
                Verdict::Allow,
                "2026-01-15T10:01:00Z",
                Some("review-agent"),
                Some("s2"),
            ),
            make_entry(
                "t3",
                "f",
                Verdict::Allow,
                "2026-01-15T10:02:00Z",
                Some("narrow-agent"),
                Some("s3"),
            ),
            make_entry(
                "t4",
                "f",
                Verdict::Allow,
                "2026-01-15T10:03:00Z",
                Some("critical-agent"),
                Some("s4"),
            ),
        ];
        let mut la = HashMap::new();
        la.insert(
            ("optimal-agent".to_string(), "s1".to_string()),
            LeastAgencyReport {
                agent_id: "optimal-agent".to_string(),
                session_id: "s1".to_string(),
                granted_permissions: 10,
                used_permissions: 9,
                unused_permissions: vec![],
                usage_ratio: 0.9,
                recommendation: AgencyRecommendation::Optimal,
            },
        );
        la.insert(
            ("review-agent".to_string(), "s2".to_string()),
            LeastAgencyReport {
                agent_id: "review-agent".to_string(),
                session_id: "s2".to_string(),
                granted_permissions: 10,
                used_permissions: 6,
                unused_permissions: vec![],
                usage_ratio: 0.6,
                recommendation: AgencyRecommendation::ReviewGrants,
            },
        );
        la.insert(
            ("narrow-agent".to_string(), "s3".to_string()),
            LeastAgencyReport {
                agent_id: "narrow-agent".to_string(),
                session_id: "s3".to_string(),
                granted_permissions: 10,
                used_permissions: 3,
                unused_permissions: vec![],
                usage_ratio: 0.3,
                recommendation: AgencyRecommendation::NarrowScope,
            },
        );
        la.insert(
            ("critical-agent".to_string(), "s4".to_string()),
            LeastAgencyReport {
                agent_id: "critical-agent".to_string(),
                session_id: "s4".to_string(),
                granted_permissions: 10,
                used_permissions: 1,
                unused_permissions: vec![],
                usage_ratio: 0.1,
                recommendation: AgencyRecommendation::Critical,
            },
        );
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &la,
        );
        assert_eq!(report.cc6_evidence.optimal_count, 1);
        assert_eq!(report.cc6_evidence.review_grants_count, 1);
        assert_eq!(report.cc6_evidence.narrow_scope_count, 1);
        assert_eq!(report.cc6_evidence.critical_count, 1);
    }

    #[test]
    fn test_deterministic_ordering() {
        let entries = vec![
            make_entry(
                "tool",
                "f",
                Verdict::Allow,
                "2026-01-15T10:00:00Z",
                Some("zebra"),
                None,
            ),
            make_entry(
                "tool",
                "f",
                Verdict::Allow,
                "2026-01-15T10:01:00Z",
                Some("alpha"),
                None,
            ),
            make_entry(
                "tool",
                "f",
                Verdict::Allow,
                "2026-01-15T10:02:00Z",
                Some("mike"),
                None,
            ),
        ];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        let ids: Vec<&str> = report.entries.iter().map(|e| e.agent_id.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "mike", "zebra"]);
    }

    #[test]
    fn test_agent_id_fallback_to_tool() {
        let entries = vec![make_entry(
            "my_tool",
            "run",
            Verdict::Allow,
            "2026-01-15T10:00:00Z",
            None, // no agent_id in metadata
            None,
        )];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert_eq!(report.entries[0].agent_id, "my_tool");
    }

    #[test]
    fn test_bounded_agents() {
        // Create MAX_AGENTS_PER_REPORT + 1 distinct agents
        let entries: Vec<AuditEntry> = (0..=MAX_AGENTS_PER_REPORT)
            .map(|i| {
                make_entry(
                    "tool",
                    "f",
                    Verdict::Allow,
                    "2026-01-15T10:00:00Z",
                    Some(&format!("agent-{:05}", i)),
                    None,
                )
            })
            .collect();
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert!(report.entries.len() <= MAX_AGENTS_PER_REPORT);
    }

    #[test]
    fn test_html_escaping() {
        let entries = vec![make_entry(
            "safe_tool",
            "fn1",
            Verdict::Allow,
            "2026-01-15T10:00:00Z",
            Some("<b>evil</b>"),
            None,
        )];
        let report = generate_access_review(
            &entries,
            "Org<>&\"'",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        let html = render_html(&report);
        // Agent ID with HTML should be escaped
        assert!(!html.contains("<b>evil</b>"));
        assert!(html.contains("&lt;b&gt;evil&lt;/b&gt;"));
        // Org name with special chars should be escaped
        assert!(html.contains("Org&lt;&gt;&amp;&quot;&#x27;"));
    }

    #[test]
    fn test_html_structure() {
        let report = generate_access_review(
            &[],
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        let html = render_html(&report);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("SOC 2 Type II Access Review Report"));
        assert!(html.contains("Reviewer Attestation"));
        assert!(html.contains("CC6 Evidence"));
        assert!(html.ends_with("</html>\n"));
    }

    #[test]
    fn test_verdict_counting() {
        let entries = vec![
            make_entry(
                "tool",
                "f",
                Verdict::Allow,
                "2026-01-15T10:00:00Z",
                Some("a1"),
                None,
            ),
            make_entry(
                "tool",
                "f",
                Verdict::Allow,
                "2026-01-15T10:01:00Z",
                Some("a1"),
                None,
            ),
            make_entry(
                "tool",
                "f",
                Verdict::Deny {
                    reason: "x".into(),
                },
                "2026-01-15T10:02:00Z",
                Some("a1"),
                None,
            ),
            make_entry(
                "tool",
                "f",
                Verdict::RequireApproval {
                    reason: "y".into(),
                },
                "2026-01-15T10:03:00Z",
                Some("a1"),
                None,
            ),
        ];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert_eq!(report.entries[0].allow_count, 2);
        assert_eq!(report.entries[0].deny_count, 1);
        assert_eq!(report.entries[0].require_approval_count, 1);
        assert_eq!(report.entries[0].total_evaluations, 4);
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let entries = vec![make_entry(
            "tool",
            "f",
            Verdict::Allow,
            "2026-01-15T10:00:00Z",
            Some("agent-1"),
            Some("sess-1"),
        )];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: AccessReviewReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_agents, report.total_agents);
        assert_eq!(deserialized.entries.len(), report.entries.len());
    }

    #[test]
    fn test_empty_function_not_tracked() {
        let entries = vec![make_entry(
            "tool",
            "",
            Verdict::Allow,
            "2026-01-15T10:00:00Z",
            Some("a1"),
            None,
        )];
        let report = generate_access_review(
            &entries,
            "Acme",
            "2026-01-01T00:00:00Z",
            "2026-02-01T00:00:00Z",
            &HashMap::new(),
        );
        assert!(report.entries[0].functions_called.is_empty());
    }

    #[test]
    fn test_html_escape_function() {
        assert_eq!(html_escape("safe text"), "safe text");
        assert_eq!(html_escape("<>&\"'"), "&lt;&gt;&amp;&quot;&#x27;");
        assert_eq!(html_escape(""), "");
    }
}
