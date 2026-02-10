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

// ═══════════════════════════════════════════════════
// HTML ESCAPING (XSS prevention)
// ═══════════════════════════════════════════════════

/// HTML-escape a string to prevent XSS. Handles the five critical characters.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
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
<title>Sentinel Dashboard</title>
<style>{DASHBOARD_CSS}</style>
</head>
<body>
<h1>Sentinel Dashboard</h1>
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
        .load(std::sync::atomic::Ordering::Relaxed);
    let eval_allow = metrics
        .evaluations_allow
        .load(std::sync::atomic::Ordering::Relaxed);
    let eval_deny = metrics
        .evaluations_deny
        .load(std::sync::atomic::Ordering::Relaxed);
    let eval_approval = metrics
        .evaluations_require_approval
        .load(std::sync::atomic::Ordering::Relaxed);
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
        Ok(entries) => {
            if entries.is_empty() {
                let _ = write!(html, r#"<p class="muted">No audit entries.</p>"#);
            } else {
                let _ = write!(
                    html,
                    r#"<table>
<tr><th>Time</th><th>Tool</th><th>Function</th><th>Verdict</th><th>Details</th></tr>
"#
                );
                // Show last 30 entries, most recent first
                for entry in entries.iter().rev().take(30) {
                    let time = html_escape(&truncate(&entry.timestamp, 19));
                    let tool = html_escape(&entry.action.tool);
                    let func = html_escape(&entry.action.function);
                    let (verdict_class, verdict_text) = match &entry.verdict {
                        sentinel_types::Verdict::Allow => ("verdict-allow", "Allow".to_string()),
                        sentinel_types::Verdict::Deny { reason } => {
                            ("verdict-deny", format!("Deny: {}", truncate(reason, 50)))
                        }
                        sentinel_types::Verdict::RequireApproval { reason, .. } => (
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
            let _ = write!(
                html,
                r#"<p class="muted">Failed to load audit entries: {}</p>"#,
                html_escape(&e.to_string())
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
                sentinel_types::PolicyType::Allow => allow_count += 1,
                sentinel_types::PolicyType::Deny => deny_count += 1,
                sentinel_types::PolicyType::Conditional { .. } => conditional_count += 1,
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
        let mut sorted: Vec<&sentinel_types::Policy> = policies.iter().collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        for p in sorted.iter().take(50) {
            let name = html_escape(&truncate(&p.name, 40));
            let id = html_escape(&truncate(&p.id, 20));
            let (type_class, type_label) = match &p.policy_type {
                sentinel_types::PolicyType::Allow => ("policy-allow", "Allow"),
                sentinel_types::PolicyType::Deny => ("policy-deny", "Deny"),
                sentinel_types::PolicyType::Conditional { .. } => {
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

/// Handle approval form submission from dashboard.
pub async fn dashboard_approve(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    // Validate approval ID length (defense against oversized paths)
    if id.len() > 128 {
        return (StatusCode::BAD_REQUEST, "Invalid approval ID").into_response();
    }

    match state.approve_approval(&id, "dashboard-admin").await {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => {
            let msg = format!("Failed to approve: {:?}", e);
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
    }
}

/// Handle denial form submission from dashboard.
pub async fn dashboard_deny(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if id.len() > 128 {
        return (StatusCode::BAD_REQUEST, "Invalid approval ID").into_response();
    }

    match state.deny_approval(&id, "dashboard-admin").await {
        Ok(_) => Redirect::to("/dashboard").into_response(),
        Err(e) => {
            let msg = format!("Failed to deny: {:?}", e);
            (StatusCode::BAD_REQUEST, msg).into_response()
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
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, s)
    } else if mins > 0 {
        format!("{}m {}s", mins, s)
    } else {
        format!("{}s", s)
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
}
