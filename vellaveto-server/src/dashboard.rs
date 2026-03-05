// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Minimal admin dashboard served as HTML (P3.2).
//!
//! Provides a server-rendered web UI for viewing audit logs, pending approvals,
//! policy summaries, and operational metrics. No JavaScript framework required —
//! all rendering is server-side. Protected by the existing auth chain.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::fmt::Write;

use crate::AppState;

/// Maximum number of audit entries displayed on the dashboard.
/// Prevents excessive rendering time and response size when the audit log is large.
const MAX_DASHBOARD_AUDIT_ENTRIES: usize = 1_000;

/// Maximum number of entries that can be loaded before returning an error.
const MAX_LOADED_ENTRIES: usize = 500_000;

// ═══════════════════════════════════════════════════
// HTML ESCAPING (XSS prevention)
// ═══════════════════════════════════════════════════

/// HTML-escape a string to prevent XSS. Handles the six critical characters
/// per OWASP recommendation (including `/` to prevent closing tags).
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            '/' => out.push_str("&#x2F;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Truncate a string to `max` characters and append "..." if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Find a safe char boundary
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

// ═══════════════════════════════════════════════════
// CSS (inline, no external dependencies)
// ═══════════════════════════════════════════════════

const DASHBOARD_CSS: &str = r#"
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
       background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px; }
h1 { color: #58a6ff; margin-bottom: 20px; font-size: 1.5rem; }
h2 { color: #8b949e; margin: 24px 0 12px; font-size: 1.1rem; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }
.card .label { color: #8b949e; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
.card .value { font-size: 1.5rem; font-weight: 600; color: #c9d1d9; margin-top: 4px; }
.card .value.green { color: #3fb950; }
.card .value.red { color: #f85149; }
.card .value.yellow { color: #d29922; }
table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
th { text-align: left; padding: 8px 12px; background: #161b22; color: #8b949e;
     font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;
     border-bottom: 2px solid #30363d; }
td { padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 0.85rem; }
tr:hover { background: #161b22; }
.verdict-allow { color: #3fb950; font-weight: 600; }
.verdict-deny { color: #f85149; font-weight: 600; }
.verdict-approval { color: #d29922; font-weight: 600; }
.btn { display: inline-block; padding: 4px 12px; border-radius: 4px;
       font-size: 0.8rem; font-weight: 600; cursor: pointer; border: 1px solid transparent;
       text-decoration: none; }
.btn-approve { background: #238636; color: #fff; border-color: #2ea043; }
.btn-approve:hover { background: #2ea043; }
.btn-deny { background: #da3633; color: #fff; border-color: #f85149; }
.btn-deny:hover { background: #f85149; }
.btn-reload { background: #1f6feb; color: #fff; border-color: #388bfd; margin-left: 8px;
              padding: 2px 10px; font-size: 0.75rem; }
.meta { color: #484f58; font-size: 0.75rem; margin-top: 16px; }
form { display: inline; }
.nowrap { white-space: nowrap; }
.muted { color: #484f58; }
.policy-type { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
.policy-allow { background: #0d2818; color: #3fb950; }
.policy-deny { background: #2d1117; color: #f85149; }
.policy-approval { background: #2d2000; color: #d29922; }
"#;

// ═══════════════════════════════════════════════════
// HANDLERS
// ═══════════════════════════════════════════════════

/// Main dashboard page.
pub async fn dashboard_page(State(state): State<AppState>) -> Html<String> {
    let mut html = String::with_capacity(8192);

    // ── Header ────────────────────────────────────
    let _ = write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vellaveto Dashboard</title>
<style>{DASHBOARD_CSS}</style>
</head>
<body>
<h1>Vellaveto Dashboard</h1>
"#
    );

    // ── Metrics overview ──────────────────────────
    let metrics = &state.metrics;
    let uptime_secs = metrics.start_time.elapsed().as_secs();
    let uptime_str = format_duration(uptime_secs);
    let snap = state.policy_state.load();
    let policy_count = snap.policies.len();
    let eval_total = metrics
        .evaluations_total
        .load(std::sync::atomic::Ordering::SeqCst);
    let eval_allow = metrics
        .evaluations_allow
        .load(std::sync::atomic::Ordering::SeqCst);
    let eval_deny = metrics
        .evaluations_deny
        .load(std::sync::atomic::Ordering::SeqCst);
    let eval_approval = metrics
        .evaluations_require_approval
        .load(std::sync::atomic::Ordering::SeqCst);
    let pending_count = state.pending_approval_count().await.unwrap_or(0);

    let _ = write!(
        html,
        r#"<h2>Overview</h2>
<div class="grid">
  <div class="card"><div class="label">Uptime</div><div class="value">{uptime_str}</div></div>
  <div class="card"><div class="label">Policies</div><div class="value">{policy_count}</div></div>
  <div class="card"><div class="label">Evaluations</div><div class="value">{eval_total}</div></div>
  <div class="card"><div class="label">Allowed</div><div class="value green">{eval_allow}</div></div>
  <div class="card"><div class="label">Denied</div><div class="value red">{eval_deny}</div></div>
  <div class="card"><div class="label">Require Approval</div><div class="value yellow">{eval_approval}</div></div>
  <div class="card"><div class="label">Pending Approvals</div><div class="value yellow">{pending_count}</div></div>
</div>
"#
    );

    // ── Verdict distribution sparkline ─────────────
    render_verdict_sparkline(&mut html, eval_allow, eval_deny, eval_approval);

    // ── Policy type pie chart ────────────────────────
    render_policy_pie_chart(&mut html, &snap.policies);

    // ── Pending approvals ─────────────────────────
    let pending = state.list_pending_approvals().await.unwrap_or_default();
    let _ = write!(html, r#"<h2>Pending Approvals ({pending_count})</h2>"#);

    if pending.is_empty() {
        let _ = write!(html, r#"<p class="muted">No pending approvals.</p>"#);
    } else {
        let _ = write!(
            html,
            r#"<table>
<tr><th>ID</th><th>Tool</th><th>Function</th><th>Reason</th><th>Created</th><th>Expires</th><th>Actions</th></tr>
"#
        );
        // Show at most 50 pending approvals
        for approval in pending.iter().take(50) {
            let id = html_escape(&approval.id);
            let id_short = html_escape(&truncate(&approval.id, 12));
            let tool = html_escape(&approval.action.tool);
            let func = html_escape(&approval.action.function);
            let reason = html_escape(&truncate(&approval.reason, 60));
            let created = html_escape(&approval.created_at.format("%H:%M:%S").to_string());
            let expires = html_escape(&approval.expires_at.format("%H:%M:%S").to_string());

            let _ = write!(
                html,
                r#"<tr>
  <td class="nowrap" title="{id}">{id_short}</td>
  <td>{tool}</td>
  <td>{func}</td>
  <td>{reason}</td>
  <td class="nowrap">{created}</td>
  <td class="nowrap">{expires}</td>
  <td class="nowrap">
    <form method="post" action="/dashboard/approvals/{id}/approve">
      <button type="submit" class="btn btn-approve">Approve</button>
    </form>
    <form method="post" action="/dashboard/approvals/{id}/deny">
      <button type="submit" class="btn btn-deny">Deny</button>
    </form>
  </td>
</tr>
"#
            );
        }
        let _ = write!(html, "</table>");
    }

    // ── Recent audit log ──────────────────────────
    let _ = write!(html, r#"<h2>Recent Audit Log</h2>"#);
    match state.audit.load_entries().await {
        Ok(entries) if entries.len() > MAX_LOADED_ENTRIES => {
            let _ = write!(
                html,
                r#"<p class="muted">Audit log exceeds capacity limit ({}). Rotate or archive the audit log.</p>"#,
                entries.len()
            );
        }
        Ok(entries) => {
            let capped = entries.len() > MAX_DASHBOARD_AUDIT_ENTRIES;
            let display_entries = if capped {
                &entries[entries.len() - MAX_DASHBOARD_AUDIT_ENTRIES..]
            } else {
                &entries[..]
            };
            if display_entries.is_empty() {
                let _ = write!(html, r#"<p class="muted">No audit entries.</p>"#);
            } else {
                if capped {
                    let _ = write!(
                        html,
                        r#"<p class="muted">Showing last {} of {} audit entries.</p>"#,
                        MAX_DASHBOARD_AUDIT_ENTRIES,
                        entries.len()
                    );
                }
                let _ = write!(
                    html,
                    r#"<table>
<tr><th>Time</th><th>Tool</th><th>Function</th><th>Verdict</th><th>Details</th></tr>
"#
                );
                // Show last 30 entries, most recent first
                for entry in display_entries.iter().rev().take(30) {
                    let time = html_escape(&truncate(&entry.timestamp, 19));
                    let tool = html_escape(&entry.action.tool);
                    let func = html_escape(&entry.action.function);
                    let (verdict_class, verdict_text) = match &entry.verdict {
                        vellaveto_types::Verdict::Allow => ("verdict-allow", "Allow".to_string()),
                        vellaveto_types::Verdict::Deny { reason } => {
                            ("verdict-deny", format!("Deny: {}", truncate(reason, 50)))
                        }
                        vellaveto_types::Verdict::RequireApproval { reason, .. } => (
                            "verdict-approval",
                            format!("Approval: {}", truncate(reason, 50)),
                        ),
                        // Handle future variants
                        _ => ("verdict-deny", "Unknown".to_string()),
                    };
                    let verdict_escaped = html_escape(&verdict_text);

                    // Extract target info from metadata if available
                    let detail = entry
                        .action
                        .target_domains
                        .first()
                        .map(|d| html_escape(&truncate(d, 30)))
                        .unwrap_or_default();

                    let _ = write!(
                        html,
                        r#"<tr>
  <td class="nowrap">{time}</td>
  <td>{tool}</td>
  <td>{func}</td>
  <td class="{verdict_class}">{verdict_escaped}</td>
  <td class="muted">{detail}</td>
</tr>
"#
                    );
                }
                let _ = write!(html, "</table>");
            }
        }
        Err(e) => {
            // SECURITY (R239-SRV-7): Do not render raw error into HTML — log server-side.
            tracing::warn!("Dashboard: failed to load audit entries: {}", e);
            let _ = write!(
                html,
                r#"<p class="muted">Failed to load audit entries. Check server logs for details.</p>"#
            );
        }
    }

    // ── Policy summary ────────────────────────────
    let _ = write!(html, r#"<h2>Policy Summary</h2>"#);
    let policies = &snap.policies;
    if policies.is_empty() {
        let _ = write!(html, r#"<p class="muted">No policies loaded.</p>"#);
    } else {
        let mut allow_count = 0usize;
        let mut deny_count = 0usize;
        let mut conditional_count = 0usize;
        for p in policies.iter() {
            match &p.policy_type {
                vellaveto_types::PolicyType::Allow => allow_count += 1,
                vellaveto_types::PolicyType::Deny => deny_count += 1,
                vellaveto_types::PolicyType::Conditional { .. } => conditional_count += 1,
                // Handle future variants
                _ => deny_count += 1,
            }
        }

        let _ = write!(
            html,
            r#"<div class="grid">
  <div class="card"><div class="label">Allow Policies</div><div class="value green">{allow_count}</div></div>
  <div class="card"><div class="label">Deny Policies</div><div class="value red">{deny_count}</div></div>
  <div class="card"><div class="label">Conditional</div><div class="value yellow">{conditional_count}</div></div>
</div>
<table>
<tr><th>Priority</th><th>Name</th><th>Type</th><th>ID</th></tr>
"#
        );

        // Sort by priority (highest first) for display
        let mut sorted: Vec<&vellaveto_types::Policy> = policies.iter().collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        for p in sorted.iter().take(50) {
            let name = html_escape(&truncate(&p.name, 40));
            let id = html_escape(&truncate(&p.id, 20));
            let (type_class, type_label) = match &p.policy_type {
                vellaveto_types::PolicyType::Allow => ("policy-allow", "Allow"),
                vellaveto_types::PolicyType::Deny => ("policy-deny", "Deny"),
                vellaveto_types::PolicyType::Conditional { .. } => {
                    ("policy-approval", "Conditional")
                }
                // Handle future variants
                _ => ("policy-deny", "Unknown"),
            };

            let _ = write!(
                html,
                r#"<tr>
  <td>{}</td>
  <td>{name}</td>
  <td><span class="policy-type {type_class}">{type_label}</span></td>
  <td class="muted">{id}</td>
</tr>
"#,
                p.priority
            );
        }
        if policies.len() > 50 {
            let _ = write!(
                html,
                r#"<tr><td colspan="4" class="muted">... and {} more policies</td></tr>"#,
                policies.len() - 50
            );
        }
        let _ = write!(html, "</table>");
    }

    // ── Execution graph section (Phase 36) ─────────
    render_exec_graph_section(&mut html, &state).await;

    // ── Governance section (Phase 26) ──────────────
    render_governance_section(&mut html, &state);

    // ── Federation section (Phase 39) ──────────────
    render_federation_section(&mut html, &state);

    // ── Compliance status ────────────────────────────
    render_compliance_section(&mut html, &snap);

    // ── Footer ────────────────────────────────────
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let _ = write!(
        html,
        r#"<p class="meta">Generated at {now} | <a href="/dashboard" class="btn btn-reload">Refresh</a></p>
</body>
</html>"#
    );

    Html(html)
}

/// Return CSS class for a coverage percentage.
fn coverage_class(percent: f32) -> &'static str {
    if percent >= 90.0 {
        "green"
    } else if percent >= 70.0 {
        "yellow"
    } else {
        "red"
    }
}

/// Render compliance status section into the dashboard HTML.
fn render_compliance_section(html: &mut String, snap: &crate::PolicySnapshot) {
    let config = &snap.compliance_config;

    // EU AI Act compliance %
    let eu_registry = vellaveto_audit::eu_ai_act::EuAiActRegistry::new();
    let eu_report = eu_registry.generate_assessment(
        config.eu_ai_act.risk_class,
        &config.eu_ai_act.deployer_name,
        &config.eu_ai_act.system_id,
    );

    // SOC 2 readiness %
    let soc2_registry = vellaveto_audit::soc2::Soc2Registry::new();
    let soc2_report = soc2_registry.generate_evidence_report(
        &config.soc2.organization_name,
        &config.soc2.period_start,
        &config.soc2.period_end,
        &config.soc2.tracked_categories,
    );

    // Gap analysis
    let gap_report = vellaveto_audit::gap_analysis::generate_gap_analysis();

    let eu_pct = eu_report.compliance_percentage;
    let soc2_pct = soc2_report.overall_readiness;
    let gap_pct = gap_report.overall_coverage_percent;
    let critical_gaps = gap_report.critical_gaps.len();

    let _ = write!(
        html,
        r#"<h2>Compliance Status</h2>
<div class="grid">
  <div class="card"><div class="label">EU AI Act</div><div class="value {eu_cls}">{eu_pct:.0}%</div></div>
  <div class="card"><div class="label">SOC 2 Readiness</div><div class="value {soc2_cls}">{soc2_pct:.0}%</div></div>
  <div class="card"><div class="label">Framework Coverage</div><div class="value {gap_cls}">{gap_pct:.0}%</div></div>
  <div class="card"><div class="label">Critical Gaps</div><div class="value {gaps_cls}">{critical_gaps}</div></div>
</div>
<table>
<tr><th>Framework</th><th>Coverage</th><th>Items</th><th>Status</th></tr>
"#,
        eu_cls = coverage_class(eu_pct),
        soc2_cls = coverage_class(soc2_pct),
        gap_cls = coverage_class(gap_pct),
        gaps_cls = if critical_gaps == 0 { "green" } else { "red" },
    );

    for fw in &gap_report.frameworks {
        let name = html_escape(&fw.name);
        let cls = coverage_class(fw.coverage_percent);
        let status = if fw.coverage_percent >= 90.0 {
            "Compliant"
        } else if fw.coverage_percent >= 70.0 {
            "Partial"
        } else {
            "Gaps Found"
        };
        let _ = write!(
            html,
            r#"<tr>
  <td>{name}</td>
  <td class="{cls}">{pct:.0}%</td>
  <td>{covered}/{total}</td>
  <td class="{cls}">{status}</td>
</tr>
"#,
            pct = fw.coverage_percent,
            covered = fw.covered_items,
            total = fw.total_items,
        );
    }
    let _ = write!(html, "</table>");
}

/// Render an SVG bar chart showing the allow/deny/approval verdict distribution.
fn render_verdict_sparkline(html: &mut String, allow: u64, deny: u64, approval: u64) {
    let total = allow + deny + approval;
    if total == 0 {
        return;
    }

    let bar_width: u32 = 300;
    let bar_height: u32 = 24;
    let allow_w = (allow as f64 / total as f64 * bar_width as f64) as u32;
    let deny_w = (deny as f64 / total as f64 * bar_width as f64) as u32;
    // Approval gets the remainder to avoid off-by-one gaps
    let approval_w = bar_width.saturating_sub(allow_w).saturating_sub(deny_w);

    let _ = write!(
        html,
        r##"<h2>Verdict Distribution</h2>
<svg width="{bar_width}" height="{bar_height}" role="img" aria-label="Verdict distribution bar chart" style="margin-bottom:16px">"##
    );

    if allow_w > 0 {
        let _ = write!(
            html,
            r##"<rect x="0" y="0" width="{allow_w}" height="{bar_height}" fill="#3fb950" rx="2"/>"##
        );
    }
    if deny_w > 0 {
        let _ = write!(
            html,
            r##"<rect x="{allow_w}" y="0" width="{deny_w}" height="{bar_height}" fill="#f85149" rx="2"/>"##
        );
    }
    if approval_w > 0 {
        let offset = allow_w + deny_w;
        let _ = write!(
            html,
            r##"<rect x="{offset}" y="0" width="{approval_w}" height="{bar_height}" fill="#d29922" rx="2"/>"##
        );
    }

    let _ = write!(html, "</svg>");

    // Legend
    let allow_pct = (allow as f64 / total as f64 * 100.0) as u32;
    let deny_pct = (deny as f64 / total as f64 * 100.0) as u32;
    let approval_pct = 100u32.saturating_sub(allow_pct).saturating_sub(deny_pct);
    let _ = write!(
        html,
        r##"<p style="font-size:0.8rem;color:#8b949e;margin-bottom:16px">
<span style="color:#3fb950">Allow {allow_pct}%</span> &middot;
<span style="color:#f85149">Deny {deny_pct}%</span> &middot;
<span style="color:#d29922">Approval {approval_pct}%</span>
({total} total)</p>"##
    );
}

/// Render an SVG pie chart showing policy type distribution (Allow/Deny/Conditional).
fn render_policy_pie_chart(html: &mut String, policies: &[vellaveto_types::Policy]) {
    if policies.is_empty() {
        return;
    }

    let mut allow_count = 0u32;
    let mut deny_count = 0u32;
    let mut conditional_count = 0u32;
    for p in policies {
        match &p.policy_type {
            vellaveto_types::PolicyType::Allow => allow_count += 1,
            vellaveto_types::PolicyType::Deny => deny_count += 1,
            vellaveto_types::PolicyType::Conditional { .. } => conditional_count += 1,
            _ => deny_count += 1,
        }
    }

    let total = allow_count + deny_count + conditional_count;
    if total == 0 {
        return;
    }

    let r = 40.0f64; // radius
    let cx = 50.0f64;
    let cy = 50.0f64;

    let _ = write!(
        html,
        r##"<h2>Policy Types</h2>
<svg width="220" height="110" role="img" aria-label="Policy type pie chart" style="margin-bottom:16px">"##
    );

    let slices: Vec<(f64, &str)> = vec![
        (allow_count as f64 / total as f64, "#3fb950"),
        (deny_count as f64 / total as f64, "#f85149"),
        (conditional_count as f64 / total as f64, "#d29922"),
    ];

    let mut angle = -std::f64::consts::FRAC_PI_2; // start at top
    for (frac, color) in &slices {
        if *frac <= 0.0 {
            continue;
        }
        let sweep = frac * 2.0 * std::f64::consts::PI;
        let x1 = cx + r * angle.cos();
        let y1 = cy + r * angle.sin();
        let end_angle = angle + sweep;
        let x2 = cx + r * end_angle.cos();
        let y2 = cy + r * end_angle.sin();
        let large_arc = if sweep > std::f64::consts::PI { 1 } else { 0 };

        if *frac >= 1.0 {
            // Full circle
            let _ = write!(
                html,
                r##"<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}"/>"##
            );
        } else {
            let _ = write!(
                html,
                r##"<path d="M {cx} {cy} L {x1:.1} {y1:.1} A {r} {r} 0 {large_arc} 1 {x2:.1} {y2:.1} Z" fill="{color}"/>"##
            );
        }
        angle = end_angle;
    }

    // Legend on the right
    let _ = write!(
        html,
        r##"<text x="105" y="30" fill="#3fb950" font-size="12">Allow: {allow_count}</text>
<text x="105" y="50" fill="#f85149" font-size="12">Deny: {deny_count}</text>
<text x="105" y="70" fill="#d29922" font-size="12">Cond: {conditional_count}</text>
</svg>"##
    );
}

/// SECURITY (R240-SRV-1): Validate CSRF for dashboard POST requests.
/// Requires either an Origin/Referer header or the X-Requested-With header.
/// Cookie-authenticated endpoints cannot rely on API key for CSRF protection.
fn validate_dashboard_csrf(headers: &axum::http::HeaderMap) -> bool {
    // X-Requested-With is a custom header that browsers won't send cross-origin
    // without CORS preflight (which would be blocked).
    if headers.contains_key("x-requested-with") {
        return true;
    }
    // Accept if Origin or Referer is present (validated by the CSRF middleware).
    if headers.contains_key("origin") || headers.contains_key("referer") {
        return true;
    }
    false
}

/// Handle approval form submission from dashboard.
pub async fn dashboard_approve(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // SECURITY (R240-SRV-1): CSRF check for cookie-authenticated dashboard forms.
    if !validate_dashboard_csrf(&headers) {
        tracing::warn!("Dashboard CSRF check failed: no Origin/Referer/X-Requested-With");
        return (StatusCode::FORBIDDEN, "CSRF validation failed").into_response();
    }

    // Validate approval ID length (defense against oversized paths)
    if id.len() > 128 {
        return (StatusCode::BAD_REQUEST, "Invalid approval ID").into_response();
    }
    // SECURITY (FIND-R49-009, FIND-R73-SRV-001): Reject control characters AND
    // Unicode format characters in approval ID, matching API approval handler pattern.
    if id.chars().any(crate::routes::is_unsafe_char) {
        return (StatusCode::BAD_REQUEST, "Invalid approval ID").into_response();
    }

    // SECURITY (FIND-R73-SRV-012): Derive resolver identity from auth headers
    // instead of hardcoding "dashboard-admin", matching the API approval pattern.
    let resolver = crate::routes::approval::derive_resolver_identity(&headers, "dashboard-admin");

    match state.approve_approval(&id, &resolver).await {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => {
            // SECURITY (FIND-R49-006): Log error details server-side, return generic message
            tracing::warn!("Dashboard action failed for id={}: {:?}", id, e);
            (
                StatusCode::BAD_REQUEST,
                "Approval action failed".to_string(),
            )
                .into_response()
        }
    }
}

/// Handle denial form submission from dashboard.
pub async fn dashboard_deny(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    // SECURITY (R240-SRV-1): CSRF check for cookie-authenticated dashboard forms.
    if !validate_dashboard_csrf(&headers) {
        tracing::warn!("Dashboard CSRF check failed: no Origin/Referer/X-Requested-With");
        return (StatusCode::FORBIDDEN, "CSRF validation failed").into_response();
    }

    if id.len() > 128 {
        return (StatusCode::BAD_REQUEST, "Invalid approval ID").into_response();
    }
    // SECURITY (FIND-R49-009, FIND-R73-SRV-001): Reject control characters AND
    // Unicode format characters in approval ID, matching API approval handler pattern.
    if id.chars().any(crate::routes::is_unsafe_char) {
        return (StatusCode::BAD_REQUEST, "Invalid approval ID").into_response();
    }

    // SECURITY (FIND-R73-SRV-012): Derive resolver identity from auth headers
    // instead of hardcoding "dashboard-admin", matching the API approval pattern.
    let resolver = crate::routes::approval::derive_resolver_identity(&headers, "dashboard-admin");

    match state.deny_approval(&id, &resolver).await {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => {
            // SECURITY (FIND-R49-006): Log error details server-side, return generic message
            tracing::warn!("Dashboard action failed for id={}: {:?}", id, e);
            (
                StatusCode::BAD_REQUEST,
                "Approval action failed".to_string(),
            )
                .into_response()
        }
    }
}

/// Format seconds into a human-readable duration string.
fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m {s}s")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Render recent execution graphs with SVG export links (Phase 36).
async fn render_exec_graph_section(html: &mut String, state: &AppState) {
    let store = match state.exec_graph_store.as_ref() {
        Some(s) => s,
        None => return,
    };

    let sessions = store.list_sessions().await;
    if sessions.is_empty() {
        return;
    }

    let _ = write!(
        html,
        r#"<h2>Recent Execution Graphs ({} sessions)</h2>
<table>
<tr><th>Session</th><th>Nodes</th><th>Started</th><th>Export</th></tr>
"#,
        sessions.len()
    );

    // Show last 10 sessions
    for session_id in sessions.iter().rev().take(10) {
        if let Some(graph) = store.get(session_id).await {
            let id = html_escape(&truncate(session_id, 24));
            let full_id = html_escape(session_id);
            let nodes = graph.nodes.len();
            let started = graph
                .metadata
                .started_at
                .map(|t| {
                    let secs = t / 1000;
                    let nanos = (t % 1000) * 1_000_000;
                    // SECURITY (R240-P3-SRV-1): Safe cast via try_from to avoid wrap on adversarial timestamps.
                    let secs_i64 = i64::try_from(secs).unwrap_or(i64::MAX);
                    let nanos_u32 = u32::try_from(nanos).unwrap_or(0);
                    chrono::DateTime::from_timestamp(secs_i64, nanos_u32)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_else(|| "—".to_string())
                })
                .unwrap_or_else(|| "—".to_string());
            let started_esc = html_escape(&started);

            let _ = write!(
                html,
                r#"<tr>
  <td title="{full_id}">{id}</td>
  <td>{nodes}</td>
  <td class="nowrap">{started_esc}</td>
  <td class="nowrap">
    <a href="/api/graphs/{full_id}/svg" class="btn btn-reload" target="_blank">SVG</a>
    <a href="/api/graphs/{full_id}/dot" class="btn btn-reload" target="_blank">DOT</a>
  </td>
</tr>
"#
            );
        }
    }

    if sessions.len() > 10 {
        let _ = write!(
            html,
            r#"<tr><td colspan="4" class="muted">... and {} more sessions</td></tr>"#,
            sessions.len() - 10
        );
    }
    let _ = write!(html, "</table>");
}

/// Render governance visibility section (Phase 26).
fn render_governance_section(html: &mut String, state: &AppState) {
    if let Some(ref discovery) = state.shadow_ai_discovery {
        let unreg = discovery.unregistered_agent_count();
        let unapp = discovery.unapproved_tool_count();
        let unksvr = discovery.unknown_server_count();

        let unreg_cls = if unreg == 0 { "green" } else { "red" };
        let unapp_cls = if unapp == 0 { "green" } else { "yellow" };
        let unksvr_cls = if unksvr == 0 { "green" } else { "red" };

        let _ = write!(
            html,
            r#"<h2>Governance — Shadow AI Discovery</h2>
<div class="grid">
  <div class="card"><div class="label">Unregistered Agents</div><div class="value {unreg_cls}">{unreg}</div></div>
  <div class="card"><div class="label">Unapproved Tools</div><div class="value {unapp_cls}">{unapp}</div></div>
  <div class="card"><div class="label">Unknown Servers</div><div class="value {unksvr_cls}">{unksvr}</div></div>
</div>
"#
        );

        // Show unregistered agents table if any
        if unreg > 0 {
            let report = discovery.generate_report();
            let _ = write!(
                html,
                r#"<table>
<tr><th>Agent ID</th><th>First Seen</th><th>Requests</th><th>Tools Used</th><th>Risk</th></tr>
"#
            );
            for agent in report.unregistered_agents.iter().take(20) {
                let id = html_escape(&truncate(&agent.agent_id, 40));
                let first = html_escape(&truncate(&agent.first_seen, 19));
                let tools_count = agent.tools_used.len();
                // SECURITY (FIND-R62-SRV-001): NaN/Infinity risk_score must
                // render as "red" — NaN comparisons all return false, which
                // would fall through to "green" and mislead operators.
                let risk_cls = if !agent.risk_score.is_finite() || agent.risk_score >= 0.7 {
                    "red"
                } else if agent.risk_score >= 0.3 {
                    "yellow"
                } else {
                    "green"
                };
                let _ = write!(
                    html,
                    r#"<tr>
  <td>{id}</td>
  <td class="nowrap">{first}</td>
  <td>{}</td>
  <td>{tools_count}</td>
  <td class="{risk_cls}">{:.2}</td>
</tr>
"#,
                    agent.request_count, agent.risk_score
                );
            }
            let _ = write!(html, "</table>");
        }
    }
}

/// Render federation status section (Phase 39).
fn render_federation_section(html: &mut String, state: &AppState) {
    match state.federation_resolver.as_ref() {
        Some(resolver) => {
            let status = resolver.status();
            let anchor_count = status.trust_anchor_count;
            let enabled_cls = "green";

            let _ = write!(
                html,
                r#"<h2>Federation — Agent Identity</h2>
<div class="grid">
  <div class="card"><div class="label">Federation</div><div class="value {enabled_cls}">Enabled</div></div>
  <div class="card"><div class="label">Trust Anchors</div><div class="value">{anchor_count}</div></div>
</div>
"#
            );

            if !status.anchors.is_empty() {
                let _ = write!(
                    html,
                    r#"<table>
<tr><th>Org ID</th><th>Display Name</th><th>Trust Level</th><th>JWKS</th><th>Mappings</th><th>OK</th><th>Fail</th></tr>
"#
                );
                for anchor in &status.anchors {
                    let org = html_escape(&truncate(&anchor.org_id, 30));
                    let name = html_escape(&truncate(&anchor.display_name, 30));
                    let level = html_escape(&anchor.trust_level);
                    let level_cls = match anchor.trust_level.as_str() {
                        "full" => "green",
                        "limited" => "yellow",
                        "read_only" => "muted",
                        _ => "red",
                    };
                    let jwks = if anchor.has_jwks_uri { "Yes" } else { "No" };
                    let mappings = anchor.identity_mapping_count;
                    let ok = anchor.successful_validations;
                    let fail = anchor.failed_validations;
                    let fail_cls = if fail > 0 { "red" } else { "green" };

                    let _ = write!(
                        html,
                        r#"<tr>
  <td>{org}</td>
  <td>{name}</td>
  <td class="{level_cls}">{level}</td>
  <td>{jwks}</td>
  <td>{mappings}</td>
  <td class="green">{ok}</td>
  <td class="{fail_cls}">{fail}</td>
</tr>
"#
                    );
                }
                let _ = write!(html, "</table>");
            }
        }
        None => {
            let _ = write!(
                html,
                r#"<h2>Federation — Agent Identity</h2>
<div class="grid">
  <div class="card"><div class="label">Federation</div><div class="value muted">Disabled</div></div>
</div>
"#
            );
        }
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_escape_basic() {
        assert_eq!(html_escape("hello"), "hello");
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape(r#"say "hi""#), "say &quot;hi&quot;");
        assert_eq!(html_escape("it's"), "it&#x27;s");
    }

    #[test]
    fn test_html_escape_combined() {
        assert_eq!(
            html_escape(r#"<img src="x" onerror='alert(1)'>&"#),
            "&lt;img src=&quot;x&quot; onerror=&#x27;alert(1)&#x27;&gt;&amp;"
        );
    }

    #[test]
    fn test_html_escape_empty() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn test_html_escape_unicode() {
        assert_eq!(html_escape("caf\u{00e9}"), "caf\u{00e9}");
        assert_eq!(html_escape("\u{1F600}"), "\u{1F600}");
    }

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_exact() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long() {
        assert_eq!(truncate("hello world", 5), "hello...");
    }

    #[test]
    fn test_truncate_unicode_boundary() {
        // "caf\u{00e9}" is 5 bytes (c=1, a=1, f=1, \u{00e9}=2)
        // Truncating at 4 should find valid boundary
        let result = truncate("caf\u{00e9}", 4);
        assert!(result.ends_with("..."));
        assert_eq!(result, "caf...");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(42), "42s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(125), "2m 5s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3661), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_days() {
        assert_eq!(format_duration(90061), "1d 1h 1m");
    }

    #[test]
    fn test_compliance_color_classes() {
        assert_eq!(coverage_class(95.0), "green");
        assert_eq!(coverage_class(90.0), "green");
        assert_eq!(coverage_class(89.9), "yellow");
        assert_eq!(coverage_class(70.0), "yellow");
        assert_eq!(coverage_class(69.9), "red");
        assert_eq!(coverage_class(0.0), "red");
    }

    #[test]
    fn test_render_compliance_section_contains_heading() {
        let snap = crate::PolicySnapshot {
            engine: vellaveto_engine::PolicyEngine::new(false),
            policies: Vec::new(),
            compliance_config: vellaveto_config::compliance::ComplianceConfig::default(),
        };
        let mut html = String::new();
        render_compliance_section(&mut html, &snap);
        assert!(html.contains("Compliance Status"));
    }

    #[test]
    fn test_render_compliance_section_contains_frameworks() {
        let snap = crate::PolicySnapshot {
            engine: vellaveto_engine::PolicyEngine::new(false),
            policies: Vec::new(),
            compliance_config: vellaveto_config::compliance::ComplianceConfig::default(),
        };
        let mut html = String::new();
        render_compliance_section(&mut html, &snap);
        // The gap analysis report includes these 8 frameworks
        assert!(html.contains("MITRE ATLAS"));
        assert!(html.contains("NIST AI RMF"));
        assert!(html.contains("ISO 27090"));
        assert!(html.contains("ISO 42001"));
        assert!(html.contains("EU AI Act"));
        assert!(html.contains("CoSAI"));
        assert!(html.contains("Adversa TOP 25"));
        assert!(html.contains("OWASP ASI"));
    }

    #[test]
    fn test_verdict_sparkline_zero_totals() {
        let mut html = String::new();
        render_verdict_sparkline(&mut html, 0, 0, 0);
        // Should produce no output when all counts are zero
        assert!(html.is_empty());
    }

    #[test]
    fn test_verdict_sparkline_with_data() {
        let mut html = String::new();
        render_verdict_sparkline(&mut html, 70, 20, 10);
        assert!(html.contains("<svg"));
        assert!(html.contains("Verdict Distribution"));
        assert!(html.contains("#3fb950")); // green for allow
        assert!(html.contains("#f85149")); // red for deny
        assert!(html.contains("100 total"));
    }

    #[test]
    fn test_policy_pie_chart_empty() {
        let mut html = String::new();
        render_policy_pie_chart(&mut html, &[]);
        assert!(html.is_empty());
    }

    #[test]
    fn test_policy_pie_chart_with_policies() {
        let policies = vec![
            vellaveto_types::Policy {
                id: "p1".into(),
                name: "Allow".into(),
                policy_type: vellaveto_types::PolicyType::Allow,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            vellaveto_types::Policy {
                id: "p2".into(),
                name: "Deny".into(),
                policy_type: vellaveto_types::PolicyType::Deny,
                priority: 200,
                path_rules: None,
                network_rules: None,
            },
        ];
        let mut html = String::new();
        render_policy_pie_chart(&mut html, &policies);
        assert!(html.contains("<svg"));
        assert!(html.contains("Policy Types"));
        assert!(html.contains("Allow: 1"));
        assert!(html.contains("Deny: 1"));
    }
}
