//! Interactive setup wizard for first-time Vellaveto configuration.
//!
//! Provides a multi-step web-based wizard at `/setup` that guides users through
//! configuring security, policies, detection, audit, and compliance settings.
//! Generates and applies a TOML config file on completion.
//!
//! Server-side rendered HTML with no JavaScript (POST/redirect/GET pattern).

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use std::fmt::Write;
use std::sync::atomic::Ordering;

use crate::routes::is_unsafe_char;
use crate::AppState;

// ═══════════════════════════════════════════════════════════════════
// Constants (bounded, fail-closed)
// ═══════════════════════════════════════════════════════════════════

/// Maximum concurrent wizard sessions to prevent memory exhaustion.
const MAX_WIZARD_SESSIONS: usize = 100;

/// Session TTL in seconds (1 hour).
const WIZARD_SESSION_TTL_SECS: u64 = 3600;

/// Maximum API key length.
const MAX_API_KEY_LEN: usize = 256;

/// Maximum length for a single CORS origin.
const MAX_ORIGIN_LEN: usize = 256;

/// Maximum number of CORS origins.
const MAX_ORIGINS: usize = 20;

/// Maximum length for audit export target URL.
const MAX_EXPORT_TARGET_LEN: usize = 512;

/// Maximum number of form fields accepted in a single POST body.
/// Prevents hash-collision DoS and excessive memory allocation.
const MAX_FORM_FIELDS: usize = 100;

// ═══════════════════════════════════════════════════════════════════
// Data Structures
// ═══════════════════════════════════════════════════════════════════

/// Policy preset selection.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyPreset {
    Strict,
    Balanced,
    Permissive,
}

impl PolicyPreset {
    fn as_str(&self) -> &'static str {
        match self {
            PolicyPreset::Strict => "strict",
            PolicyPreset::Balanced => "balanced",
            PolicyPreset::Permissive => "permissive",
        }
    }

    fn parse_preset(s: &str) -> Option<Self> {
        match s {
            "strict" => Some(PolicyPreset::Strict),
            "balanced" => Some(PolicyPreset::Balanced),
            "permissive" => Some(PolicyPreset::Permissive),
            _ => None,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            PolicyPreset::Strict => "Strict",
            PolicyPreset::Balanced => "Balanced",
            PolicyPreset::Permissive => "Permissive",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            PolicyPreset::Strict => "Deny-by-default. Block credentials and exfiltration. Destructive commands require approval. Recommended for regulated environments.",
            PolicyPreset::Balanced => "Deny-by-default. Block credentials. Allow file reads, require approval for writes. Good for most teams.",
            PolicyPreset::Permissive => "Allow-by-default. Only block credentials and exfiltration attempts. For trusted development environments.",
        }
    }
}

/// Wizard session state persisted across steps.
///
/// FIND-R56-SRV-020: Custom `Debug` impl redacts `api_key` and `csrf_token`
/// to prevent accidental credential leakage in logs or error messages.
pub struct WizardSession {
    pub created_at: std::time::Instant,
    pub csrf_token: String,
    // Step 2: Security
    pub api_key: String,
    pub cors_origins: Vec<String>,
    pub allow_anonymous: bool,
    // Step 3: Policies
    pub policy_preset: PolicyPreset,
    // Step 4: Detection
    pub injection_enabled: bool,
    pub injection_blocking: bool,
    pub dlp_enabled: bool,
    pub dlp_blocking: bool,
    pub behavioral_enabled: bool,
    // Step 5: Audit
    pub redaction_level: String,
    pub audit_export_format: String,
    pub audit_export_target: String,
    pub checkpoint_interval_secs: u64,
    // Step 6: Compliance
    pub eu_ai_act: bool,
    pub nis2: bool,
    pub dora: bool,
    pub soc2: bool,
    pub iso42001: bool,
}

impl std::fmt::Debug for WizardSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WizardSession")
            .field("created_at", &self.created_at)
            .field("csrf_token", &"[REDACTED]")
            .field("api_key", &"[REDACTED]")
            .field("allow_anonymous", &self.allow_anonymous)
            .field("policy_preset", &self.policy_preset)
            .field("injection_enabled", &self.injection_enabled)
            .field("dlp_enabled", &self.dlp_enabled)
            .finish()
    }
}

impl WizardSession {
    fn new() -> Self {
        let csrf_token = uuid::Uuid::new_v4().to_string();
        // Generate a random API key suggestion
        let api_key = format!("vk_{}", &uuid::Uuid::new_v4().to_string().replace('-', ""));
        Self {
            created_at: std::time::Instant::now(),
            csrf_token,
            api_key,
            cors_origins: vec!["http://localhost".to_string()],
            allow_anonymous: false,
            policy_preset: PolicyPreset::Balanced,
            injection_enabled: true,
            injection_blocking: false,
            dlp_enabled: true,
            dlp_blocking: false,
            behavioral_enabled: false,
            redaction_level: "KeysAndPatterns".to_string(),
            audit_export_format: "none".to_string(),
            audit_export_target: String::new(),
            checkpoint_interval_secs: 300,
            eu_ai_act: false,
            nis2: false,
            dora: false,
            soc2: false,
            iso42001: false,
        }
    }

    fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() > WIZARD_SESSION_TTL_SECS
    }
}

// ═══════════════════════════════════════════════════════════════════
// CSS
// ═══════════════════════════════════════════════════════════════════

const WIZARD_CSS: &str = r#"
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
       background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px;
       max-width: 800px; margin: 0 auto; }
h1 { color: #58a6ff; margin-bottom: 8px; font-size: 1.5rem; }
h2 { color: #c9d1d9; margin: 24px 0 12px; font-size: 1.2rem; }
h3 { color: #8b949e; margin: 16px 0 8px; font-size: 1rem; }
p { color: #8b949e; margin-bottom: 16px; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }

/* Step indicator */
.steps { display: flex; align-items: center; margin: 24px 0 32px; padding: 0; list-style: none; }
.steps li { display: flex; align-items: center; }
.steps .circle {
    width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center;
    justify-content: center; font-size: 0.85rem; font-weight: 600;
    background: #161b22; border: 2px solid #30363d; color: #8b949e; flex-shrink: 0;
}
.steps .circle.active { background: #1f6feb; border-color: #58a6ff; color: #fff; }
.steps .circle.done { background: #238636; border-color: #3fb950; color: #fff; }
.steps .line { width: 32px; height: 2px; background: #30363d; margin: 0 4px; }
.steps .line.done { background: #3fb950; }
.steps .step-label { font-size: 0.7rem; color: #8b949e; margin-left: 4px; margin-right: 8px; }

/* Cards */
.card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin-bottom: 16px; }
.card.highlight { border-color: #58a6ff; }

/* Form inputs */
label { display: block; color: #c9d1d9; font-size: 0.9rem; font-weight: 500; margin-bottom: 4px; }
input[type="text"], input[type="password"], select, textarea {
    width: 100%; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d;
    border-radius: 4px; color: #c9d1d9; font-size: 0.9rem; font-family: inherit;
    margin-bottom: 12px;
}
input[type="text"]:focus, input[type="password"]:focus, select:focus, textarea:focus {
    outline: none; border-color: #58a6ff; box-shadow: 0 0 0 2px rgba(88,166,255,0.2);
}
select { appearance: auto; cursor: pointer; }
.input-hint { font-size: 0.8rem; color: #484f58; margin-top: -8px; margin-bottom: 12px; }

/* Radio card groups */
.radio-group { display: grid; grid-template-columns: 1fr; gap: 12px; margin-bottom: 16px; }
.radio-card {
    background: #161b22; border: 2px solid #30363d; border-radius: 6px; padding: 16px;
    cursor: pointer; transition: border-color 0.15s;
}
.radio-card:hover { border-color: #484f58; }
.radio-card input[type="radio"] { display: none; }
.radio-card input[type="radio"]:checked + .radio-content { }
.radio-card.selected, .radio-card:has(input:checked) { border-color: #58a6ff; background: #0d1117; }
.radio-title { font-weight: 600; color: #c9d1d9; margin-bottom: 4px; }
.radio-desc { font-size: 0.85rem; color: #8b949e; }

/* Toggle rows */
.toggle-row {
    display: flex; align-items: flex-start; justify-content: space-between;
    padding: 12px 0; border-bottom: 1px solid #21262d;
}
.toggle-row:last-child { border-bottom: none; }
.toggle-info { flex: 1; margin-right: 16px; }
.toggle-label { font-weight: 500; color: #c9d1d9; }
.toggle-desc { font-size: 0.85rem; color: #8b949e; margin-top: 2px; }
.toggle-controls { display: flex; gap: 12px; align-items: center; flex-shrink: 0; padding-top: 2px; }
.toggle-controls label { display: flex; align-items: center; gap: 4px; font-size: 0.85rem;
    color: #8b949e; margin-bottom: 0; font-weight: normal; cursor: pointer; white-space: nowrap; }
.toggle-controls input[type="checkbox"] { accent-color: #58a6ff; width: 16px; height: 16px; cursor: pointer; }

/* Checkbox grid */
.checkbox-grid { display: grid; grid-template-columns: 1fr; gap: 12px; }
.checkbox-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px;
}
.checkbox-card label { display: flex; align-items: flex-start; gap: 8px; cursor: pointer; margin-bottom: 0; }
.checkbox-card input[type="checkbox"] { accent-color: #58a6ff; width: 18px; height: 18px;
    margin-top: 2px; cursor: pointer; flex-shrink: 0; }
.checkbox-title { font-weight: 600; color: #c9d1d9; }
.checkbox-desc { font-size: 0.85rem; color: #8b949e; margin-top: 2px; }

/* Buttons */
.btn-row { display: flex; justify-content: flex-end; gap: 12px; margin-top: 24px; }
.btn {
    display: inline-block; padding: 8px 20px; border-radius: 6px; font-size: 0.9rem;
    font-weight: 600; cursor: pointer; border: 1px solid transparent; text-decoration: none;
}
.btn-primary { background: #238636; color: #fff; border-color: #2ea043; }
.btn-primary:hover { background: #2ea043; }
.btn-secondary { background: #21262d; color: #c9d1d9; border-color: #30363d; }
.btn-secondary:hover { background: #30363d; }
.btn-apply { background: #1f6feb; color: #fff; border-color: #388bfd; }
.btn-apply:hover { background: #388bfd; }

/* Review summary */
.summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
@media (max-width: 600px) { .summary-grid { grid-template-columns: 1fr; } }
.summary-item { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }
.summary-label { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
.summary-value { color: #c9d1d9; margin-top: 4px; }
.summary-value.green { color: #3fb950; }
.summary-value.yellow { color: #d29922; }
.summary-value.red { color: #f85149; }

/* Code block (TOML preview) */
pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px;
      overflow-x: auto; font-size: 0.85rem; line-height: 1.5; color: #c9d1d9;
      margin-bottom: 16px; white-space: pre-wrap; word-wrap: break-word; }

/* Error/success banners */
.banner { padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; font-size: 0.9rem; }
.banner-error { background: #2d1117; border: 1px solid #f85149; color: #f85149; }
.banner-success { background: #0d2818; border: 1px solid #3fb950; color: #3fb950; }

/* Footer */
.footer { color: #484f58; font-size: 0.75rem; margin-top: 32px; padding-top: 16px;
          border-top: 1px solid #21262d; text-align: center; }
"#;

// ═══════════════════════════════════════════════════════════════════
// HTML Helpers
// ═══════════════════════════════════════════════════════════════════

/// Delegates to `dashboard::html_escape` which includes `/` escaping per OWASP.
fn html_escape(s: &str) -> String {
    crate::dashboard::html_escape(s)
}

fn checked(val: bool) -> &'static str {
    if val {
        "checked"
    } else {
        ""
    }
}

fn selected(val: bool) -> &'static str {
    if val {
        "selected"
    } else {
        ""
    }
}

fn render_head(title: &str) -> String {
    let escaped_title = html_escape(title);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escaped_title} — Vellaveto Setup</title>
<style>{WIZARD_CSS}</style>
</head>
<body>
"#
    )
}

fn render_steps(current: usize) -> String {
    let labels = [
        "Welcome",
        "Security",
        "Policies",
        "Detection",
        "Audit",
        "Compliance",
        "Review",
    ];
    let mut html = String::from("<ol class=\"steps\">");
    for (i, label) in labels.iter().enumerate() {
        let step = i + 1;
        let class = if step < current {
            "circle done"
        } else if step == current {
            "circle active"
        } else {
            "circle"
        };
        let line_class = if step < current { "line done" } else { "line" };
        let _ = write!(html, "<li><span class=\"{class}\">{step}</span><span class=\"step-label\">{label}</span></li>");
        if i < labels.len() - 1 {
            let _ = write!(html, "<li><span class=\"{line_class}\"></span></li>");
        }
    }
    html.push_str("</ol>");
    html
}

fn render_footer() -> &'static str {
    r#"<div class="footer">Vellaveto Setup Wizard</div></body></html>"#
}

fn render_csrf(token: &str) -> String {
    format!(
        r#"<input type="hidden" name="csrf_token" value="{}">"#,
        html_escape(token)
    )
}

// ═══════════════════════════════════════════════════════════════════
// Session Management
// ═══════════════════════════════════════════════════════════════════

fn get_session_id(req: &Request) -> Option<String> {
    let cookie_header = req.headers().get(header::COOKIE)?;
    let cookie_str = cookie_header.to_str().ok()?;
    for part in cookie_str.split(';') {
        let trimmed = part.trim();
        if let Some(val) = trimmed.strip_prefix("wizard_session=") {
            let val = val.trim();
            if !val.is_empty() && val.len() <= 64 {
                // SECURITY (FIND-R112-007): Reject session IDs containing control
                // or Unicode format characters to prevent log injection and bypass.
                if val.chars().any(is_unsafe_char) {
                    return None;
                }
                return Some(val.to_string());
            }
        }
    }
    None
}

fn session_cookie(session_id: &str) -> String {
    format!(
        "wizard_session={}; Path=/setup; Secure; HttpOnly; SameSite=Strict",
        session_id
    )
}

fn cleanup_expired_sessions(state: &AppState) {
    // Iterates all wizard sessions (bounded by MAX_WIZARD_SESSIONS) and removes
    // entries whose TTL has elapsed. Two-pass to avoid holding an iterator across removal.
    let mut to_remove = Vec::new();
    for entry in state.wizard_sessions.iter() {
        if entry.value().is_expired() {
            to_remove.push(entry.key().clone());
        }
    }
    for key in to_remove {
        state.wizard_sessions.remove(&key);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Guard Middleware
// ═══════════════════════════════════════════════════════════════════

/// Middleware that blocks access to the wizard after setup is completed.
pub async fn setup_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if state.setup_completed.load(Ordering::Acquire) {
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>Setup already completed</h1><p>The setup wizard has been locked. To reconfigure, delete the <code>.setup-complete</code> marker file and restart the server.</p>".to_string()),
        ).into_response();
    }

    // Cleanup expired sessions on each request (bounded)
    cleanup_expired_sessions(&state);

    next.run(req).await
}

// ═══════════════════════════════════════════════════════════════════
// Form Parsing
// ═══════════════════════════════════════════════════════════════════

fn parse_form(body: &[u8]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let body_str = String::from_utf8_lossy(body);
    for pair in body_str.split('&') {
        if map.len() >= MAX_FORM_FIELDS {
            tracing::warn!(
                "parse_form: exceeded {} field limit, ignoring remaining fields",
                MAX_FORM_FIELDS
            );
            break;
        }
        if let Some((key, value)) = pair.split_once('=') {
            let key = percent_decode(key);
            let value = percent_decode(value);
            map.insert(key, value);
        }
    }
    map
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

// ═══════════════════════════════════════════════════════════════════
// Step Handlers
// ═══════════════════════════════════════════════════════════════════

/// Step 1 — Welcome page (GET /setup)
pub async fn step_welcome(State(state): State<AppState>, req: Request) -> Response {
    // SECURITY (FIND-R112-010): Reuse an existing valid session if the cookie
    // is present and the session has not expired. This prevents unbounded
    // session creation on repeated GET /setup requests.
    if let Some(existing_id) = get_session_id(&req) {
        let session_valid = state
            .wizard_sessions
            .get(&existing_id)
            .map(|s| !s.is_expired())
            .unwrap_or(false);
        if session_valid {
            let mut html = render_head("Welcome");
            html.push_str(&render_steps(1));

            let _ = write!(
                html,
                r#"
<h1>Welcome to Vellaveto Setup</h1>
<div class="card">
<p>Vellaveto is a runtime security engine for AI agent tool calls. This wizard will walk you through configuring:</p>
<ul style="color: #8b949e; margin: 12px 0 12px 24px;">
<li><strong style="color: #c9d1d9;">Security</strong> &mdash; API key, CORS, authentication</li>
<li><strong style="color: #c9d1d9;">Policies</strong> &mdash; Allow/deny rules for tool access</li>
<li><strong style="color: #c9d1d9;">Detection</strong> &mdash; Injection, DLP, behavioral anomaly</li>
<li><strong style="color: #c9d1d9;">Audit</strong> &mdash; Logging, redaction, export</li>
<li><strong style="color: #c9d1d9;">Compliance</strong> &mdash; EU AI Act, NIS2, DORA, SOC 2, ISO 42001</li>
</ul>
<p>At the end, a TOML configuration file will be generated and applied. You can always reconfigure by editing the file directly.</p>
</div>
<div class="btn-row">
<a href="/setup/security" class="btn btn-primary">Start Setup &rarr;</a>
</div>
"#
            );
            html.push_str(render_footer());

            return Html(html).into_response();
        }
    }

    // No valid session — create a new one
    if state.wizard_sessions.len() >= MAX_WIZARD_SESSIONS {
        cleanup_expired_sessions(&state);
        if state.wizard_sessions.len() >= MAX_WIZARD_SESSIONS {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Html("<h1>Too many active sessions</h1><p>Please try again later.</p>".to_string()),
            )
                .into_response();
        }
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let session = WizardSession::new();

    state.wizard_sessions.insert(session_id.clone(), session);

    let mut html = render_head("Welcome");
    html.push_str(&render_steps(1));

    let _ = write!(
        html,
        r#"
<h1>Welcome to Vellaveto Setup</h1>
<div class="card">
<p>Vellaveto is a runtime security engine for AI agent tool calls. This wizard will walk you through configuring:</p>
<ul style="color: #8b949e; margin: 12px 0 12px 24px;">
<li><strong style="color: #c9d1d9;">Security</strong> &mdash; API key, CORS, authentication</li>
<li><strong style="color: #c9d1d9;">Policies</strong> &mdash; Allow/deny rules for tool access</li>
<li><strong style="color: #c9d1d9;">Detection</strong> &mdash; Injection, DLP, behavioral anomaly</li>
<li><strong style="color: #c9d1d9;">Audit</strong> &mdash; Logging, redaction, export</li>
<li><strong style="color: #c9d1d9;">Compliance</strong> &mdash; EU AI Act, NIS2, DORA, SOC 2, ISO 42001</li>
</ul>
<p>At the end, a TOML configuration file will be generated and applied. You can always reconfigure by editing the file directly.</p>
</div>
<div class="btn-row">
<a href="/setup/security" class="btn btn-primary">Start Setup &rarr;</a>
</div>
"#
    );
    html.push_str(render_footer());

    (
        StatusCode::OK,
        [(header::SET_COOKIE, session_cookie(&session_id))],
        Html(html),
    )
        .into_response()
}

/// Step 2 — Security (GET /setup/security)
pub async fn step_security(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };
    let session = match state.wizard_sessions.get(&session_id) {
        Some(s) => s,
        None => return Redirect::to("/setup").into_response(),
    };

    let mut html = render_head("Security");
    html.push_str(&render_steps(2));

    let api_key_val = html_escape(&session.api_key);
    let origins_val = html_escape(&session.cors_origins.join(", "));
    let anon_checked = checked(session.allow_anonymous);
    let csrf = render_csrf(&session.csrf_token);

    let _ = write!(
        html,
        r#"
<h1>Security Settings</h1>
<form method="POST" action="/setup/security">
{csrf}
<div class="card">
<h3>API Key</h3>
<p>This key protects all mutating API endpoints. Store it securely.</p>
<label for="api_key">API Key</label>
<input type="text" id="api_key" name="api_key" value="{api_key_val}" maxlength="{MAX_API_KEY_LEN}" autocomplete="off">
<div class="input-hint">Auto-generated suggestion. You can customize it.</div>
</div>

<div class="card">
<h3>CORS Origins</h3>
<p>Comma-separated list of allowed origins for cross-origin requests.</p>
<label for="cors_origins">Allowed Origins</label>
<input type="text" id="cors_origins" name="cors_origins" value="{origins_val}" maxlength="5120">
<div class="input-hint">Use * to allow any origin (not recommended for production).</div>
</div>

<div class="card">
<h3>Anonymous Access</h3>
<div class="toggle-row">
<div class="toggle-info">
<div class="toggle-label">Allow anonymous access</div>
<div class="toggle-desc">When enabled, the server starts without requiring an API key. Not recommended for production.</div>
</div>
<div class="toggle-controls">
<label><input type="checkbox" name="allow_anonymous" {anon_checked}> Enable</label>
</div>
</div>
</div>

<div class="btn-row">
<a href="/setup" class="btn btn-secondary">&larr; Back</a>
<button type="submit" class="btn btn-primary">Next &rarr;</button>
</div>
</form>
"#
    );
    html.push_str(render_footer());
    Html(html).into_response()
}

/// Step 2 — Security (POST /setup/security)
pub async fn step_security_post(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };

    let body = match axum::body::to_bytes(req.into_body(), 16_384).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid request body").into_response(),
    };
    let form = parse_form(&body);

    // CSRF validation
    {
        let session = match state.wizard_sessions.get(&session_id) {
            Some(s) => s,
            None => return Redirect::to("/setup").into_response(),
        };
        let expected_csrf = session.csrf_token.clone();
        let provided_csrf = form.get("csrf_token").cloned().unwrap_or_default();
        if !csrf_token_matches(&provided_csrf, &expected_csrf) {
            return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
        }
    }

    // Validate and save
    let api_key = form.get("api_key").cloned().unwrap_or_default();
    if api_key.len() > MAX_API_KEY_LEN {
        return error_redirect("/setup/security", "API key is too long");
    }
    // SECURITY (FIND-R112-006): Use canonical is_unsafe_char which checks both
    // ASCII control characters AND Unicode format characters (zero-width, bidi, BOM).
    if api_key.chars().any(is_unsafe_char) {
        return error_redirect(
            "/setup/security",
            "API key contains control or format characters",
        );
    }

    let origins_str = form.get("cors_origins").cloned().unwrap_or_default();
    let origins: Vec<String> = origins_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if origins.len() > MAX_ORIGINS {
        return error_redirect("/setup/security", "Too many CORS origins");
    }
    for origin in &origins {
        if origin.len() > MAX_ORIGIN_LEN {
            return error_redirect("/setup/security", "CORS origin is too long");
        }
        // SECURITY (FIND-R112-006): Use canonical is_unsafe_char which checks both
        // ASCII control characters AND Unicode format characters (zero-width, bidi, BOM).
        if origin.chars().any(is_unsafe_char) {
            return error_redirect(
                "/setup/security",
                "CORS origin contains control or format characters",
            );
        }
    }

    let allow_anonymous = form.contains_key("allow_anonymous");

    // Update session
    if let Some(mut session) = state.wizard_sessions.get_mut(&session_id) {
        session.api_key = api_key;
        session.cors_origins = origins;
        session.allow_anonymous = allow_anonymous;
        // SECURITY (FIND-R210-003): Rotate CSRF token after each successful step
        // submission so a leaked token is only valid for one step.
        session.csrf_token = uuid::Uuid::new_v4().to_string();
    }

    Redirect::to("/setup/policies").into_response()
}

/// Step 3 — Policies (GET /setup/policies)
pub async fn step_policies(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };
    let session = match state.wizard_sessions.get(&session_id) {
        Some(s) => s,
        None => return Redirect::to("/setup").into_response(),
    };

    let mut html = render_head("Policies");
    html.push_str(&render_steps(3));

    let csrf = render_csrf(&session.csrf_token);
    let presets = [
        PolicyPreset::Strict,
        PolicyPreset::Balanced,
        PolicyPreset::Permissive,
    ];

    let _ = write!(
        html,
        r#"
<h1>Policy Preset</h1>
<p>Choose a starting policy preset. You can customize individual policies later by editing the config file.</p>
<form method="POST" action="/setup/policies">
{csrf}
<div class="radio-group">
"#
    );

    for preset in &presets {
        let is_selected = *preset == session.policy_preset;
        let card_class = if is_selected {
            "radio-card selected"
        } else {
            "radio-card"
        };
        let checked_attr = checked(is_selected);
        let label = preset.label();
        let desc = preset.description();
        let value = preset.as_str();
        let _ = write!(
            html,
            r#"
<label class="{card_class}">
<input type="radio" name="policy_preset" value="{value}" {checked_attr}>
<div class="radio-content">
<div class="radio-title">{label}</div>
<div class="radio-desc">{desc}</div>
</div>
</label>
"#
        );
    }

    let _ = write!(
        html,
        r#"
</div>
<div class="btn-row">
<a href="/setup/security" class="btn btn-secondary">&larr; Back</a>
<button type="submit" class="btn btn-primary">Next &rarr;</button>
</div>
</form>
"#
    );
    html.push_str(render_footer());
    Html(html).into_response()
}

/// Step 3 — Policies (POST /setup/policies)
pub async fn step_policies_post(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };

    let body = match axum::body::to_bytes(req.into_body(), 16_384).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid request body").into_response(),
    };
    let form = parse_form(&body);

    {
        let session = match state.wizard_sessions.get(&session_id) {
            Some(s) => s,
            None => return Redirect::to("/setup").into_response(),
        };
        let provided_csrf = form.get("csrf_token").cloned().unwrap_or_default();
        if !csrf_token_matches(&provided_csrf, &session.csrf_token) {
            return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
        }
    }

    let preset_str = form.get("policy_preset").cloned().unwrap_or_default();
    let preset = PolicyPreset::parse_preset(&preset_str).unwrap_or(PolicyPreset::Balanced);

    if let Some(mut session) = state.wizard_sessions.get_mut(&session_id) {
        session.policy_preset = preset;
        // SECURITY (FIND-R210-003): Rotate CSRF token after each step.
        session.csrf_token = uuid::Uuid::new_v4().to_string();
    }

    Redirect::to("/setup/detection").into_response()
}

/// Step 4 — Detection (GET /setup/detection)
pub async fn step_detection(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };
    let session = match state.wizard_sessions.get(&session_id) {
        Some(s) => s,
        None => return Redirect::to("/setup").into_response(),
    };

    let mut html = render_head("Detection");
    html.push_str(&render_steps(4));

    let csrf = render_csrf(&session.csrf_token);
    let inj_enabled = checked(session.injection_enabled);
    let inj_blocking = checked(session.injection_blocking);
    let dlp_enabled = checked(session.dlp_enabled);
    let dlp_blocking = checked(session.dlp_blocking);
    let beh_enabled = checked(session.behavioral_enabled);

    let _ = write!(
        html,
        r#"
<h1>Detection Settings</h1>
<p>Configure which security detection systems to enable. Alert-only mode logs detections without blocking requests.</p>
<form method="POST" action="/setup/detection">
{csrf}
<div class="card">
<div class="toggle-row">
<div class="toggle-info">
<div class="toggle-label">Prompt Injection Detection</div>
<div class="toggle-desc">Scans tool call parameters for prompt injection patterns using Aho-Corasick matching with NFKC normalization.</div>
</div>
<div class="toggle-controls">
<label><input type="checkbox" name="injection_enabled" {inj_enabled}> Enable</label>
<label><input type="checkbox" name="injection_blocking" {inj_blocking}> Block</label>
</div>
</div>

<div class="toggle-row">
<div class="toggle-info">
<div class="toggle-label">DLP / Secret Scanning</div>
<div class="toggle-desc">Detects API keys, passwords, tokens, and other secrets in tool call parameters using multi-layer decode (Base64, URL, Unicode).</div>
</div>
<div class="toggle-controls">
<label><input type="checkbox" name="dlp_enabled" {dlp_enabled}> Enable</label>
<label><input type="checkbox" name="dlp_blocking" {dlp_blocking}> Block</label>
</div>
</div>

<div class="toggle-row">
<div class="toggle-info">
<div class="toggle-label">Behavioral Anomaly Detection</div>
<div class="toggle-desc">Tracks tool usage patterns over time and flags statistical outliers using exponential moving average. Higher false-positive rate; best used in alert-only mode.</div>
</div>
<div class="toggle-controls">
<label><input type="checkbox" name="behavioral_enabled" {beh_enabled}> Enable</label>
</div>
</div>
</div>

<div class="btn-row">
<a href="/setup/policies" class="btn btn-secondary">&larr; Back</a>
<button type="submit" class="btn btn-primary">Next &rarr;</button>
</div>
</form>
"#
    );
    html.push_str(render_footer());
    Html(html).into_response()
}

/// Step 4 — Detection (POST /setup/detection)
pub async fn step_detection_post(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };

    let body = match axum::body::to_bytes(req.into_body(), 16_384).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid request body").into_response(),
    };
    let form = parse_form(&body);

    {
        let session = match state.wizard_sessions.get(&session_id) {
            Some(s) => s,
            None => return Redirect::to("/setup").into_response(),
        };
        let provided_csrf = form.get("csrf_token").cloned().unwrap_or_default();
        if !csrf_token_matches(&provided_csrf, &session.csrf_token) {
            return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
        }
    }

    if let Some(mut session) = state.wizard_sessions.get_mut(&session_id) {
        session.injection_enabled = form.contains_key("injection_enabled");
        session.injection_blocking = form.contains_key("injection_blocking");
        session.dlp_enabled = form.contains_key("dlp_enabled");
        session.dlp_blocking = form.contains_key("dlp_blocking");
        session.behavioral_enabled = form.contains_key("behavioral_enabled");
        // SECURITY (FIND-R210-003): Rotate CSRF token after each step.
        session.csrf_token = uuid::Uuid::new_v4().to_string();
    }

    Redirect::to("/setup/audit").into_response()
}

/// Step 5 — Audit (GET /setup/audit)
pub async fn step_audit(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };
    let session = match state.wizard_sessions.get(&session_id) {
        Some(s) => s,
        None => return Redirect::to("/setup").into_response(),
    };

    let mut html = render_head("Audit");
    html.push_str(&render_steps(5));

    let csrf = render_csrf(&session.csrf_token);
    let redaction = &session.redaction_level;
    let export_fmt = &session.audit_export_format;
    let export_target = html_escape(&session.audit_export_target);
    let cp_interval = session.checkpoint_interval_secs;

    let _ = write!(
        html,
        r#"
<h1>Audit Settings</h1>
<p>Configure how audit data is recorded, redacted, and exported.</p>
<form method="POST" action="/setup/audit">
{csrf}
<div class="card">
<h3>Redaction Level</h3>
<p>Controls how sensitive data is redacted in audit logs.</p>
<label for="redaction_level">Redaction Level</label>
<select id="redaction_level" name="redaction_level">
<option value="Off" {sel_off}>None &mdash; raw values logged</option>
<option value="KeysOnly" {sel_keys}>Keys Only &mdash; redact sensitive key names</option>
<option value="KeysAndPatterns" {sel_kp}>Keys and Patterns (recommended) &mdash; redact keys + PII patterns</option>
<option value="Full" {sel_full}>Full &mdash; redact all parameter values</option>
</select>
</div>

<div class="card">
<h3>Audit Export</h3>
<p>Optionally forward audit events to an external system.</p>
<label for="audit_export_format">Export Format</label>
<select id="audit_export_format" name="audit_export_format">
<option value="none" {sel_none}>None</option>
<option value="cef" {sel_cef}>CEF (Common Event Format)</option>
<option value="jsonl" {sel_jsonl}>JSON Lines</option>
<option value="webhook" {sel_webhook}>Webhook (HTTP POST)</option>
</select>

<label for="audit_export_target">Export Target</label>
<input type="text" id="audit_export_target" name="audit_export_target" value="{export_target}"
       placeholder="e.g., /var/log/vellaveto/export.jsonl or https://siem.example.com/events" maxlength="{MAX_EXPORT_TARGET_LEN}">
<div class="input-hint">File path for CEF/JSONL, URL for webhook. Leave empty if format is None.</div>
</div>

<div class="card">
<h3>Checkpoint Interval</h3>
<p>How often to create signed audit checkpoints for tamper detection.</p>
<label for="checkpoint_interval_secs">Interval</label>
<select id="checkpoint_interval_secs" name="checkpoint_interval_secs">
<option value="60" {sel_60}>60 seconds</option>
<option value="300" {sel_300}>5 minutes (recommended)</option>
<option value="600" {sel_600}>10 minutes</option>
<option value="3600" {sel_3600}>1 hour</option>
</select>
</div>

<div class="btn-row">
<a href="/setup/detection" class="btn btn-secondary">&larr; Back</a>
<button type="submit" class="btn btn-primary">Next &rarr;</button>
</div>
</form>
"#,
        sel_off = selected(redaction == "Off"),
        sel_keys = selected(redaction == "KeysOnly"),
        sel_kp = selected(redaction == "KeysAndPatterns"),
        sel_full = selected(redaction == "Full"),
        sel_none = selected(export_fmt == "none"),
        sel_cef = selected(export_fmt == "cef"),
        sel_jsonl = selected(export_fmt == "jsonl"),
        sel_webhook = selected(export_fmt == "webhook"),
        sel_60 = selected(cp_interval == 60),
        sel_300 = selected(cp_interval == 300),
        sel_600 = selected(cp_interval == 600),
        sel_3600 = selected(cp_interval == 3600),
    );
    html.push_str(render_footer());
    Html(html).into_response()
}

/// Step 5 — Audit (POST /setup/audit)
pub async fn step_audit_post(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };

    let body = match axum::body::to_bytes(req.into_body(), 16_384).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid request body").into_response(),
    };
    let form = parse_form(&body);

    {
        let session = match state.wizard_sessions.get(&session_id) {
            Some(s) => s,
            None => return Redirect::to("/setup").into_response(),
        };
        let provided_csrf = form.get("csrf_token").cloned().unwrap_or_default();
        if !csrf_token_matches(&provided_csrf, &session.csrf_token) {
            return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
        }
    }

    let redaction_level = form
        .get("redaction_level")
        .cloned()
        .unwrap_or_else(|| "KeysAndPatterns".to_string());
    let valid_levels = ["Off", "KeysOnly", "KeysAndPatterns", "Full"];
    let redaction_level = if valid_levels.contains(&redaction_level.as_str()) {
        redaction_level
    } else {
        "KeysAndPatterns".to_string()
    };

    let export_format = form
        .get("audit_export_format")
        .cloned()
        .unwrap_or_else(|| "none".to_string());
    let valid_formats = ["none", "cef", "jsonl", "webhook"];
    let export_format = if valid_formats.contains(&export_format.as_str()) {
        export_format
    } else {
        "none".to_string()
    };

    let export_target = form.get("audit_export_target").cloned().unwrap_or_default();
    if export_target.len() > MAX_EXPORT_TARGET_LEN {
        return error_redirect("/setup/audit", "Export target is too long");
    }
    // SECURITY (FIND-R101-002, FIND-R112-011): Use canonical is_unsafe_char
    // which checks both ASCII control characters AND Unicode format characters
    // (zero-width, bidi overrides, BOM) for consistency with other wizard steps.
    if export_target.chars().any(is_unsafe_char) {
        return error_redirect(
            "/setup/audit",
            "Export target contains control or format characters",
        );
    }

    let checkpoint_interval: u64 = form
        .get("checkpoint_interval_secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let checkpoint_interval = match checkpoint_interval {
        60 | 300 | 600 | 3600 => checkpoint_interval,
        _ => 300,
    };

    if let Some(mut session) = state.wizard_sessions.get_mut(&session_id) {
        session.redaction_level = redaction_level;
        session.audit_export_format = export_format;
        session.audit_export_target = export_target;
        session.checkpoint_interval_secs = checkpoint_interval;
        // SECURITY (FIND-R210-003): Rotate CSRF token after each step.
        session.csrf_token = uuid::Uuid::new_v4().to_string();
    }

    Redirect::to("/setup/compliance").into_response()
}

/// Step 6 — Compliance (GET /setup/compliance)
pub async fn step_compliance(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };
    let session = match state.wizard_sessions.get(&session_id) {
        Some(s) => s,
        None => return Redirect::to("/setup").into_response(),
    };

    let mut html = render_head("Compliance");
    html.push_str(&render_steps(6));

    let csrf = render_csrf(&session.csrf_token);

    let _ = write!(
        html,
        r#"
<h1>Compliance Frameworks</h1>
<p>Enable compliance features for your regulatory requirements. Each framework adds specific audit events, reports, and evidence collection.</p>
<form method="POST" action="/setup/compliance">
{csrf}
<div class="checkbox-grid">

<div class="checkbox-card">
<label>
<input type="checkbox" name="eu_ai_act" {eu}>
<div>
<div class="checkbox-title">EU AI Act</div>
<div class="checkbox-desc">Art 50 transparency marking, Art 10 data governance, Art 12 record-keeping, Art 14 human oversight logging.</div>
</div>
</label>
</div>

<div class="checkbox-card">
<label>
<input type="checkbox" name="nis2" {nis2}>
<div>
<div class="checkbox-title">NIS2</div>
<div class="checkbox-desc">Incident reporting events, supply chain security checks, access control logging, continuous monitoring.</div>
</div>
</label>
</div>

<div class="checkbox-card">
<label>
<input type="checkbox" name="dora" {dora}>
<div>
<div class="checkbox-title">DORA</div>
<div class="checkbox-desc">ICT risk management, incident management events, third-party risk tracking for AI service providers.</div>
</div>
</label>
</div>

<div class="checkbox-card">
<label>
<input type="checkbox" name="soc2" {soc2}>
<div>
<div class="checkbox-title">SOC 2</div>
<div class="checkbox-desc">Access review reports, CC6 evidence collection, Trust Services Criteria coverage tracking.</div>
</div>
</label>
</div>

<div class="checkbox-card">
<label>
<input type="checkbox" name="iso42001" {iso}>
<div>
<div class="checkbox-title">ISO 42001</div>
<div class="checkbox-desc">AI management system controls, risk assessment framework, performance monitoring.</div>
</div>
</label>
</div>

</div>

<div class="btn-row">
<a href="/setup/audit" class="btn btn-secondary">&larr; Back</a>
<button type="submit" class="btn btn-primary">Next &rarr;</button>
</div>
</form>
"#,
        eu = checked(session.eu_ai_act),
        nis2 = checked(session.nis2),
        dora = checked(session.dora),
        soc2 = checked(session.soc2),
        iso = checked(session.iso42001),
    );
    html.push_str(render_footer());
    Html(html).into_response()
}

/// Step 6 — Compliance (POST /setup/compliance)
pub async fn step_compliance_post(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };

    let body = match axum::body::to_bytes(req.into_body(), 16_384).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid request body").into_response(),
    };
    let form = parse_form(&body);

    {
        let session = match state.wizard_sessions.get(&session_id) {
            Some(s) => s,
            None => return Redirect::to("/setup").into_response(),
        };
        let provided_csrf = form.get("csrf_token").cloned().unwrap_or_default();
        if !csrf_token_matches(&provided_csrf, &session.csrf_token) {
            return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
        }
    }

    if let Some(mut session) = state.wizard_sessions.get_mut(&session_id) {
        session.eu_ai_act = form.contains_key("eu_ai_act");
        session.nis2 = form.contains_key("nis2");
        session.dora = form.contains_key("dora");
        session.soc2 = form.contains_key("soc2");
        session.iso42001 = form.contains_key("iso42001");
        // SECURITY (FIND-R210-003): Rotate CSRF token after each step.
        session.csrf_token = uuid::Uuid::new_v4().to_string();
    }

    Redirect::to("/setup/review").into_response()
}

/// Step 7 — Review (GET /setup/review)
pub async fn step_review(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };
    let session = match state.wizard_sessions.get(&session_id) {
        Some(s) => s,
        None => return Redirect::to("/setup").into_response(),
    };

    let mut html = render_head("Review");
    html.push_str(&render_steps(7));

    let csrf = render_csrf(&session.csrf_token);

    // Summary cards
    let api_key_display = if session.api_key.is_empty() {
        "(not set)".to_string()
    } else {
        let key = &session.api_key;
        if key.len() > 8 {
            format!("{}...{}", &key[..4], &key[key.len() - 4..])
        } else {
            "****".to_string()
        }
    };

    let origins_display = if session.cors_origins.is_empty() {
        "localhost only".to_string()
    } else {
        html_escape(&session.cors_origins.join(", "))
    };

    let anon_display = if session.allow_anonymous { "Yes" } else { "No" };
    let preset_display = session.policy_preset.label();

    let inj_display = detection_display(session.injection_enabled, session.injection_blocking);
    let dlp_display = detection_display(session.dlp_enabled, session.dlp_blocking);
    let beh_display = if session.behavioral_enabled {
        "Enabled"
    } else {
        "Disabled"
    };

    let redaction_display = match session.redaction_level.as_str() {
        "Off" => "None",
        "KeysOnly" => "Keys Only",
        "KeysAndPatterns" => "Keys and Patterns",
        "Full" => "Full",
        _ => "Keys and Patterns",
    };

    let export_display = match session.audit_export_format.as_str() {
        "none" => "None".to_string(),
        "cef" => format!("CEF → {}", html_escape(&session.audit_export_target)),
        "jsonl" => format!("JSONL → {}", html_escape(&session.audit_export_target)),
        "webhook" => format!("Webhook → {}", html_escape(&session.audit_export_target)),
        _ => "None".to_string(),
    };

    let mut frameworks = Vec::new();
    if session.eu_ai_act {
        frameworks.push("EU AI Act");
    }
    if session.nis2 {
        frameworks.push("NIS2");
    }
    if session.dora {
        frameworks.push("DORA");
    }
    if session.soc2 {
        frameworks.push("SOC 2");
    }
    if session.iso42001 {
        frameworks.push("ISO 42001");
    }
    let compliance_display = if frameworks.is_empty() {
        "None".to_string()
    } else {
        frameworks.join(", ")
    };

    let toml_preview = html_escape(&generate_config_toml(&session));

    let _ = write!(
        html,
        r#"
<h1>Review Configuration</h1>
<p>Review your settings before applying. Click &ldquo;Apply Configuration&rdquo; to write the config file and activate it.</p>

<div class="summary-grid">
<div class="summary-item">
<div class="summary-label">API Key</div>
<div class="summary-value">{api_key_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">CORS Origins</div>
<div class="summary-value">{origins_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">Anonymous Access</div>
<div class="summary-value">{anon_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">Policy Preset</div>
<div class="summary-value">{preset_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">Injection Detection</div>
<div class="summary-value">{inj_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">DLP Scanning</div>
<div class="summary-value">{dlp_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">Behavioral Detection</div>
<div class="summary-value">{beh_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">Audit Redaction</div>
<div class="summary-value">{redaction_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">Audit Export</div>
<div class="summary-value">{export_display}</div>
</div>
<div class="summary-item">
<div class="summary-label">Checkpoint Interval</div>
<div class="summary-value">{cp_secs}s</div>
</div>
<div class="summary-item">
<div class="summary-label">Compliance</div>
<div class="summary-value">{compliance_display}</div>
</div>
</div>

<h2>Generated Configuration (TOML)</h2>
<pre>{toml_preview}</pre>

<form method="POST" action="/setup/apply">
{csrf}
<div class="btn-row">
<a href="/setup/compliance" class="btn btn-secondary">&larr; Back</a>
<button type="submit" class="btn btn-apply">Apply Configuration</button>
</div>
</form>
"#,
        cp_secs = session.checkpoint_interval_secs,
    );
    html.push_str(render_footer());
    Html(html).into_response()
}

fn detection_display(enabled: bool, blocking: bool) -> &'static str {
    match (enabled, blocking) {
        (true, true) => "Enabled (blocking)",
        (true, false) => "Enabled (alert-only)",
        (false, _) => "Disabled",
    }
}

/// Step 7 — Apply (POST /setup/apply)
pub async fn step_apply(State(state): State<AppState>, req: Request) -> Response {
    let session_id = match get_session_id(&req) {
        Some(id) => id,
        None => return Redirect::to("/setup").into_response(),
    };

    let body = match axum::body::to_bytes(req.into_body(), 16_384).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid request body").into_response(),
    };
    let form = parse_form(&body);

    let toml_content;
    {
        let session = match state.wizard_sessions.get(&session_id) {
            Some(s) => s,
            None => return Redirect::to("/setup").into_response(),
        };
        let provided_csrf = form.get("csrf_token").cloned().unwrap_or_default();
        if !csrf_token_matches(&provided_csrf, &session.csrf_token) {
            return (StatusCode::FORBIDDEN, "Invalid CSRF token").into_response();
        }
        toml_content = generate_config_toml(&session);
    }

    // Validate the generated TOML parses correctly AND passes semantic validation.
    // SECURITY (FIND-R104-004): Previously only checked from_toml() (parse), not
    // validate() (semantic checks). Without validate(), configs with unbounded
    // collections, invalid float ranges, or SSRF webhooks could be written to disk.
    let parsed_config = match vellaveto_config::PolicyConfig::from_toml(&toml_content) {
        Ok(c) => c,
        Err(e) => {
            let mut html = render_head("Error");
            html.push_str(&render_steps(7));
            let _ = write!(
                html,
                r#"
<h1>Configuration Error</h1>
<div class="banner banner-error">Failed to parse generated configuration: {}</div>
<p>Please go back and adjust your settings.</p>
<div class="btn-row">
<a href="/setup/review" class="btn btn-secondary">&larr; Back to Review</a>
</div>
"#,
                html_escape(&e.to_string())
            );
            html.push_str(render_footer());
            return Html(html).into_response();
        }
    };
    if let Err(e) = parsed_config.validate() {
        let mut html = render_head("Error");
        html.push_str(&render_steps(7));
        let _ = write!(
            html,
            r#"
<h1>Configuration Validation Error</h1>
<div class="banner banner-error">Generated configuration failed validation: {}</div>
<p>Please go back and adjust your settings.</p>
<div class="btn-row">
<a href="/setup/review" class="btn btn-secondary">&larr; Back to Review</a>
</div>
"#,
            html_escape(&e.to_string())
        );
        html.push_str(render_footer());
        return Html(html).into_response();
    }

    // SECURITY (FIND-R101-001): Atomically claim setup completion before writing
    // config. Prevents TOCTOU race where two concurrent step_apply requests both
    // pass the middleware guard and write the config file.
    if state
        .setup_completed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return (
            StatusCode::CONFLICT,
            "Setup already completed by another request",
        )
            .into_response();
    }

    // Write the config file
    let config_path = state.config_path.as_str();
    if let Err(e) = std::fs::write(config_path, &toml_content) {
        // SECURITY (FIND-R101-001): Rollback the atomic flag on write failure
        // so the wizard can be retried.
        state.setup_completed.store(false, Ordering::Release);
        let mut html = render_head("Error");
        html.push_str(&render_steps(7));
        let _ = write!(
            html,
            r#"
<h1>Write Error</h1>
<div class="banner banner-error">Failed to write configuration file: {}</div>
<p>Check that the server has write permissions to the config directory.</p>
<div class="btn-row">
<a href="/setup/review" class="btn btn-secondary">&larr; Back to Review</a>
</div>
"#,
            html_escape(&e.to_string())
        );
        html.push_str(render_footer());
        return Html(html).into_response();
    }

    // Reload policies from the new config
    match crate::reload_policies_from_file(&state, "setup_wizard").await {
        Ok(count) => {
            tracing::info!(
                "Setup wizard: applied configuration with {} policies",
                count
            );
        }
        Err(e) => {
            tracing::warn!(
                "Setup wizard: policy reload failed after config write: {}",
                e
            );
            // Config was written successfully, but reload failed.
            // The config will take effect on next server restart.
        }
    }

    // Write the .setup-complete marker file
    let marker_path = setup_complete_marker_path(config_path);
    if let Err(e) = std::fs::write(&marker_path, "setup completed\n") {
        tracing::warn!(
            "Failed to write setup-complete marker at {:?}: {}",
            marker_path,
            e
        );
    }

    // SECURITY (FIND-R101-001): setup_completed was already set atomically above
    // via compare_exchange. No need to store again.

    // Clean up the session
    state.wizard_sessions.remove(&session_id);

    // Get the API key from the session for the env var instruction
    let api_key_instruction;
    {
        // Session was already removed, but we can read from the TOML
        api_key_instruction = if toml_content.contains("# API key configured via wizard") {
            r#"<p>Set the API key as an environment variable before starting the server:</p>
<pre>export VELLAVETO_API_KEY=&lt;your-api-key&gt;</pre>"#
                .to_string()
        } else {
            String::new()
        };
    }

    // Success page
    let mut html = render_head("Complete");
    let _ = write!(
        html,
        r#"
<div style="text-align: center; padding: 40px 0;">
<h1 style="font-size: 2rem; margin-bottom: 16px;">Setup Complete</h1>
<div class="banner banner-success">Configuration has been written and applied successfully.</div>
</div>

<div class="card">
<h3>What Happens Next</h3>
<ul style="color: #8b949e; margin: 12px 0 12px 24px;">
<li>The configuration file has been written to <code>{config_path}</code></li>
<li>Policies have been reloaded from the new configuration</li>
<li>The setup wizard is now locked (returns 403 on revisit)</li>
</ul>
{api_key_instruction}
<p>To reconfigure, either edit the TOML file directly or delete <code>.setup-complete</code> and restart the server.</p>
</div>

<div class="btn-row">
<a href="/dashboard" class="btn btn-primary">Go to Dashboard &rarr;</a>
</div>
"#,
        config_path = html_escape(config_path),
    );
    html.push_str(render_footer());
    Html(html).into_response()
}

// ═══════════════════════════════════════════════════════════════════
// TOML Generation
// ═══════════════════════════════════════════════════════════════════

/// Generate a human-readable TOML configuration from wizard session state.
fn generate_config_toml(session: &WizardSession) -> String {
    let mut toml = String::with_capacity(4096);

    // Header comment
    toml.push_str("# Vellaveto Configuration\n");
    toml.push_str("# Generated by the setup wizard\n\n");

    // API key note (the key itself is set via env var, not in the config)
    if !session.api_key.is_empty() {
        toml.push_str(
            "# API key configured via wizard — set VELLAVETO_API_KEY environment variable\n\n",
        );
    }

    // CORS origins
    if !session.cors_origins.is_empty() {
        toml.push_str(
            "# Allowed CORS origins (also settable via VELLAVETO_CORS_ORIGINS env var)\n",
        );
        toml.push_str("allowed_origins = [");
        for (i, origin) in session.cors_origins.iter().enumerate() {
            if i > 0 {
                toml.push_str(", ");
            }
            let _ = write!(toml, "\"{}\"", escape_toml_string(origin));
        }
        toml.push_str("]\n\n");
    }

    // Policies
    toml.push_str("# ─── Policies ───────────────────────────────────────────────\n\n");
    generate_policy_preset_toml(&mut toml, &session.policy_preset);

    // Injection detection
    toml.push_str("# ─── Detection ──────────────────────────────────────────────\n\n");
    toml.push_str("[injection]\n");
    let _ = writeln!(toml, "enabled = {}", session.injection_enabled);
    if session.injection_enabled {
        let _ = writeln!(toml, "blocking = {}", session.injection_blocking);
    }
    toml.push('\n');

    // DLP
    toml.push_str("[dlp]\n");
    let _ = writeln!(toml, "enabled = {}", session.dlp_enabled);
    if session.dlp_enabled {
        let _ = writeln!(toml, "blocking = {}", session.dlp_blocking);
    }
    toml.push('\n');

    // Behavioral
    if session.behavioral_enabled {
        toml.push_str("[behavioral]\n");
        toml.push_str("enabled = true\n\n");
    }

    // Audit
    toml.push_str("# ─── Audit ──────────────────────────────────────────────────\n\n");
    toml.push_str("[audit]\n");
    let _ = writeln!(
        toml,
        "redaction_level = \"{}\"",
        escape_toml_string(&session.redaction_level)
    );
    toml.push('\n');

    // Audit export
    if session.audit_export_format != "none" {
        toml.push_str("[audit_export]\n");
        let _ = writeln!(
            toml,
            "format = \"{}\"",
            escape_toml_string(&session.audit_export_format)
        );
        if !session.audit_export_target.is_empty() {
            let _ = writeln!(
                toml,
                "target = \"{}\"",
                escape_toml_string(&session.audit_export_target)
            );
        }
        toml.push('\n');
    }

    // Compliance
    let has_compliance =
        session.eu_ai_act || session.nis2 || session.dora || session.soc2 || session.iso42001;
    if has_compliance {
        toml.push_str("# ─── Compliance ─────────────────────────────────────────────\n\n");
        toml.push_str("[compliance]\n");

        if session.eu_ai_act {
            toml.push_str("\n[compliance.eu_ai_act]\n");
            toml.push_str("enabled = true\n");
            toml.push_str("transparency_marking = true\n");
        }
        if session.soc2 {
            toml.push_str("\n[compliance.soc2]\n");
            toml.push_str("enabled = true\n");
        }
        if session.iso42001 {
            toml.push_str("\n[compliance.iso42001]\n");
            toml.push_str("enabled = true\n");
        }
        // NIS2 and DORA are noted as compliance targets in comments
        if session.nis2 {
            toml.push_str(
                "\n# NIS2 compliance enabled — incident reporting and supply chain checks active\n",
            );
        }
        if session.dora {
            toml.push_str(
                "\n# DORA compliance enabled — ICT risk management and incident tracking active\n",
            );
        }
        toml.push('\n');
    }

    toml
}

fn generate_policy_preset_toml(toml: &mut String, preset: &PolicyPreset) {
    match preset {
        PolicyPreset::Strict => {
            toml.push_str("# Policy preset: Strict (deny-by-default, maximum security)\n\n");

            // Default deny policy
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"default-deny\"\n");
            toml.push_str("name = \"Default deny all\"\n");
            toml.push_str("policy_type = \"Deny\"\n");
            toml.push_str("priority = 0\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");

            // Block credential access
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"block-credentials\"\n");
            toml.push_str("name = \"Block credential access\"\n");
            toml.push_str("policy_type = \"Deny\"\n");
            toml.push_str("priority = 100\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");
            toml.push_str("[policies.path_rules]\n");
            toml.push_str("blocked_patterns = [\"**/.env\", \"**/*.key\", \"**/*.pem\", \"**/credentials*\", \"**/.ssh/**\", \"**/.aws/**\"]\n\n");

            // Block exfiltration
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"block-exfiltration\"\n");
            toml.push_str("name = \"Block data exfiltration\"\n");
            toml.push_str("policy_type = \"Deny\"\n");
            toml.push_str("priority = 100\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");
            toml.push_str("[policies.network_rules]\n");
            toml.push_str(
                "blocked_domains = [\"*.pastebin.com\", \"*.transfer.sh\", \"*.ngrok.io\"]\n\n",
            );

            // Require approval for destructive commands
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"approve-destructive\"\n");
            toml.push_str("name = \"Require approval for destructive operations\"\n");
            toml.push_str("policy_type = \"RequireApproval\"\n");
            toml.push_str("priority = 50\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");
            toml.push_str("[policies.path_rules]\n");
            toml.push_str("write_patterns = [\"**/*\"]\n\n");
        }
        PolicyPreset::Balanced => {
            toml.push_str("# Policy preset: Balanced (deny-by-default, read allowed, writes require approval)\n\n");

            // Default deny
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"default-deny\"\n");
            toml.push_str("name = \"Default deny all\"\n");
            toml.push_str("policy_type = \"Deny\"\n");
            toml.push_str("priority = 0\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");

            // Block credentials
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"block-credentials\"\n");
            toml.push_str("name = \"Block credential access\"\n");
            toml.push_str("policy_type = \"Deny\"\n");
            toml.push_str("priority = 100\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");
            toml.push_str("[policies.path_rules]\n");
            toml.push_str("blocked_patterns = [\"**/.env\", \"**/*.key\", \"**/*.pem\", \"**/credentials*\", \"**/.ssh/**\", \"**/.aws/**\"]\n\n");

            // Allow reads
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"allow-reads\"\n");
            toml.push_str("name = \"Allow file reads\"\n");
            toml.push_str("policy_type = \"Allow\"\n");
            toml.push_str("priority = 50\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"read*\"\n\n");

            // Require approval for writes
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"approve-writes\"\n");
            toml.push_str("name = \"Require approval for file writes\"\n");
            toml.push_str("policy_type = \"RequireApproval\"\n");
            toml.push_str("priority = 50\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"write*\"\n\n");
        }
        PolicyPreset::Permissive => {
            toml.push_str("# Policy preset: Permissive (allow-by-default, block credentials and exfiltration)\n\n");

            // Default allow
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"default-allow\"\n");
            toml.push_str("name = \"Default allow all\"\n");
            toml.push_str("policy_type = \"Allow\"\n");
            toml.push_str("priority = 0\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");

            // Block credentials
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"block-credentials\"\n");
            toml.push_str("name = \"Block credential access\"\n");
            toml.push_str("policy_type = \"Deny\"\n");
            toml.push_str("priority = 100\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");
            toml.push_str("[policies.path_rules]\n");
            toml.push_str("blocked_patterns = [\"**/.env\", \"**/*.key\", \"**/*.pem\", \"**/credentials*\", \"**/.ssh/**\", \"**/.aws/**\"]\n\n");

            // Block exfiltration
            toml.push_str("[[policies]]\n");
            toml.push_str("id = \"block-exfiltration\"\n");
            toml.push_str("name = \"Block data exfiltration\"\n");
            toml.push_str("policy_type = \"Deny\"\n");
            toml.push_str("priority = 100\n");
            toml.push_str("tool = \"*\"\n");
            toml.push_str("function = \"*\"\n\n");
            toml.push_str("[policies.network_rules]\n");
            toml.push_str(
                "blocked_domains = [\"*.pastebin.com\", \"*.transfer.sh\", \"*.ngrok.io\"]\n\n",
            );
        }
    }
}

fn escape_toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Escape all other control characters as Unicode escapes
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            // SECURITY (FIND-R210-004): Escape Unicode format characters (zero-width,
            // bidi overrides, BOM) that are invisible but could be interpreted
            // differently by TOML parsers, causing config injection.
            c if vellaveto_types::is_unicode_format_char(c) => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Constant-time CSRF token comparison to prevent timing attacks (FIND-P2-CSRF-TIMING).
/// Hashes both values with SHA-256 to normalize length (prevents length oracle)
/// and uses `subtle::ConstantTimeEq` for the comparison.
fn csrf_token_matches(provided: &str, expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let provided_hash = Sha256::digest(provided.as_bytes());
    let expected_hash = Sha256::digest(expected.as_bytes());
    bool::from(provided_hash.ct_eq(&expected_hash))
}

fn error_redirect(path: &str, _msg: &str) -> Response {
    // For simplicity in a no-JS environment, just redirect back.
    // The user will see their previous values preserved.
    // `_msg` is currently unused but kept in the signature for future
    // flash-message support (e.g., cookie-based error banners).
    Redirect::to(path).into_response()
}

/// Compute the path for the `.setup-complete` marker file.
pub fn setup_complete_marker_path(config_path: &str) -> std::path::PathBuf {
    let config_dir = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    config_dir.join(".setup-complete")
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wizard_session_new_has_sane_defaults() {
        let session = WizardSession::new();
        assert!(!session.api_key.is_empty());
        assert!(session.api_key.starts_with("vk_"));
        assert_eq!(session.cors_origins, vec!["http://localhost"]);
        assert!(!session.allow_anonymous);
        assert_eq!(session.policy_preset, PolicyPreset::Balanced);
        assert!(session.injection_enabled);
        assert!(!session.injection_blocking);
        assert!(session.dlp_enabled);
        assert!(!session.dlp_blocking);
        assert!(!session.behavioral_enabled);
        assert_eq!(session.redaction_level, "KeysAndPatterns");
        assert_eq!(session.audit_export_format, "none");
        assert!(session.audit_export_target.is_empty());
        assert_eq!(session.checkpoint_interval_secs, 300);
        assert!(!session.eu_ai_act);
        assert!(!session.nis2);
        assert!(!session.dora);
        assert!(!session.soc2);
        assert!(!session.iso42001);
    }

    #[test]
    fn test_wizard_session_expiry() {
        let mut session = WizardSession::new();
        assert!(!session.is_expired());
        // Simulate old session
        session.created_at =
            std::time::Instant::now() - std::time::Duration::from_secs(WIZARD_SESSION_TTL_SECS + 1);
        assert!(session.is_expired());
    }

    #[test]
    fn test_policy_preset_roundtrip() {
        for preset in &[
            PolicyPreset::Strict,
            PolicyPreset::Balanced,
            PolicyPreset::Permissive,
        ] {
            let s = preset.as_str();
            let parsed = PolicyPreset::parse_preset(s).expect("should parse");
            assert_eq!(&parsed, preset);
        }
        assert!(PolicyPreset::parse_preset("invalid").is_none());
    }

    #[test]
    fn test_html_escape_special_chars() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("it's"), "it&#x27;s");
        assert_eq!(html_escape("normal"), "normal");
    }

    #[test]
    fn test_escape_toml_string() {
        assert_eq!(escape_toml_string("hello"), "hello");
        assert_eq!(escape_toml_string(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(escape_toml_string(r"path\to"), r"path\\to");
    }

    #[test]
    fn test_generate_config_toml_balanced_default() {
        let session = WizardSession::new();
        let toml = generate_config_toml(&session);
        assert!(toml.contains("# Vellaveto Configuration"));
        assert!(toml.contains("policy_type = \"Deny\""));
        assert!(toml.contains("id = \"default-deny\""));
        assert!(toml.contains("[injection]"));
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("[dlp]"));
        assert!(toml.contains("[audit]"));
        assert!(toml.contains("redaction_level = \"KeysAndPatterns\""));
        // No compliance section by default
        assert!(!toml.contains("[compliance]"));
    }

    #[test]
    fn test_generate_config_toml_strict_preset() {
        let mut session = WizardSession::new();
        session.policy_preset = PolicyPreset::Strict;
        let toml = generate_config_toml(&session);
        assert!(toml.contains("id = \"default-deny\""));
        assert!(toml.contains("id = \"block-credentials\""));
        assert!(toml.contains("id = \"block-exfiltration\""));
        assert!(toml.contains("id = \"approve-destructive\""));
    }

    #[test]
    fn test_generate_config_toml_permissive_preset() {
        let mut session = WizardSession::new();
        session.policy_preset = PolicyPreset::Permissive;
        let toml = generate_config_toml(&session);
        assert!(toml.contains("id = \"default-allow\""));
        assert!(toml.contains("policy_type = \"Allow\""));
    }

    #[test]
    fn test_generate_config_toml_with_compliance() {
        let mut session = WizardSession::new();
        session.eu_ai_act = true;
        session.soc2 = true;
        let toml = generate_config_toml(&session);
        assert!(toml.contains("[compliance]"));
        assert!(toml.contains("[compliance.eu_ai_act]"));
        assert!(toml.contains("[compliance.soc2]"));
    }

    #[test]
    fn test_generate_config_toml_with_export() {
        let mut session = WizardSession::new();
        session.audit_export_format = "webhook".to_string();
        session.audit_export_target = "https://siem.example.com/events".to_string();
        let toml = generate_config_toml(&session);
        assert!(toml.contains("[audit_export]"));
        assert!(toml.contains("format = \"webhook\""));
        assert!(toml.contains("target = \"https://siem.example.com/events\""));
    }

    #[test]
    fn test_generate_config_toml_behavioral_enabled() {
        let mut session = WizardSession::new();
        session.behavioral_enabled = true;
        let toml = generate_config_toml(&session);
        assert!(toml.contains("[behavioral]"));
        assert!(toml.contains("enabled = true"));
    }

    #[test]
    fn test_generate_config_toml_no_behavioral_when_disabled() {
        let session = WizardSession::new();
        let toml = generate_config_toml(&session);
        assert!(!toml.contains("[behavioral]"));
    }

    #[test]
    fn test_setup_complete_marker_path() {
        let path = setup_complete_marker_path("/etc/vellaveto/config.toml");
        assert_eq!(
            path,
            std::path::PathBuf::from("/etc/vellaveto/.setup-complete")
        );
    }

    #[test]
    fn test_setup_complete_marker_path_relative() {
        let path = setup_complete_marker_path("config.toml");
        assert_eq!(path, std::path::PathBuf::from(".setup-complete"));
    }

    #[test]
    fn test_parse_form_basic() {
        let body = b"key1=value1&key2=value2";
        let form = parse_form(body);
        assert_eq!(form.get("key1").unwrap(), "value1");
        assert_eq!(form.get("key2").unwrap(), "value2");
    }

    #[test]
    fn test_parse_form_url_encoded() {
        let body = b"key=hello%20world&csrf_token=abc-123";
        let form = parse_form(body);
        assert_eq!(form.get("key").unwrap(), "hello world");
        assert_eq!(form.get("csrf_token").unwrap(), "abc-123");
    }

    #[test]
    fn test_parse_form_empty() {
        let body = b"";
        let form = parse_form(body);
        assert!(form.is_empty());
    }

    #[test]
    fn test_render_steps_highlights_current() {
        let html = render_steps(3);
        // Step 1 and 2 should be "done", step 3 should be "active"
        assert!(html.contains("circle done"));
        assert!(html.contains("circle active"));
    }

    #[test]
    fn test_detection_display() {
        assert_eq!(detection_display(true, true), "Enabled (blocking)");
        assert_eq!(detection_display(true, false), "Enabled (alert-only)");
        assert_eq!(detection_display(false, false), "Disabled");
        assert_eq!(detection_display(false, true), "Disabled");
    }

    #[test]
    fn test_checked_helper() {
        assert_eq!(checked(true), "checked");
        assert_eq!(checked(false), "");
    }

    #[test]
    fn test_selected_helper() {
        assert_eq!(selected(true), "selected");
        assert_eq!(selected(false), "");
    }

    #[test]
    fn test_session_cookie_format() {
        let cookie = session_cookie("test-uuid-123");
        assert!(cookie.contains("wizard_session=test-uuid-123"));
        assert!(cookie.contains("Path=/setup"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn test_csrf_token_is_uuid() {
        let session = WizardSession::new();
        assert!(uuid::Uuid::parse_str(&session.csrf_token).is_ok());
    }

    #[test]
    fn test_max_wizard_sessions_constant() {
        assert_eq!(MAX_WIZARD_SESSIONS, 100);
    }

    #[test]
    fn test_wizard_session_ttl_constant() {
        assert_eq!(WIZARD_SESSION_TTL_SECS, 3600);
    }

    #[test]
    fn test_generate_config_toml_with_cors_origins() {
        let mut session = WizardSession::new();
        session.cors_origins = vec![
            "https://app.example.com".to_string(),
            "https://admin.example.com".to_string(),
        ];
        let toml = generate_config_toml(&session);
        assert!(toml.contains(
            "allowed_origins = [\"https://app.example.com\", \"https://admin.example.com\"]"
        ));
    }

    #[test]
    fn test_generate_config_toml_injection_disabled() {
        let mut session = WizardSession::new();
        session.injection_enabled = false;
        let toml = generate_config_toml(&session);
        assert!(toml.contains("[injection]\nenabled = false\n"));
    }

    #[test]
    fn test_generate_config_toml_injection_blocking() {
        let mut session = WizardSession::new();
        session.injection_enabled = true;
        session.injection_blocking = true;
        let toml = generate_config_toml(&session);
        assert!(toml.contains("blocking = true"));
    }

    // --- TOML escape adversarial tests (FIND-P2-TOML-INJECTION) ---

    #[test]
    fn test_escape_toml_string_newlines() {
        // Newlines must be escaped to prevent TOML key injection
        assert_eq!(escape_toml_string("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_toml_string("line1\rline2"), "line1\\rline2");
        assert_eq!(escape_toml_string("line1\r\nline2"), "line1\\r\\nline2");
    }

    #[test]
    fn test_escape_toml_string_tab() {
        assert_eq!(escape_toml_string("col1\tcol2"), "col1\\tcol2");
    }

    #[test]
    fn test_escape_toml_string_control_chars() {
        // NUL, BEL, and other control characters must be escaped
        assert_eq!(escape_toml_string("\0"), "\\u0000");
        assert_eq!(escape_toml_string("\x07"), "\\u0007");
        assert_eq!(escape_toml_string("\x1B"), "\\u001B");
    }

    #[test]
    fn test_escape_toml_string_injection_adversarial() {
        // Adversarial: attacker tries to inject a new TOML key via newline
        let malicious = "innocent\"\nmalicious_key = \"pwned";
        let escaped = escape_toml_string(malicious);
        // The escaped string must not contain a raw newline
        assert!(
            !escaped.contains('\n'),
            "escaped TOML string must not contain raw newline"
        );
    }

    #[test]
    fn test_escape_toml_string_cr_injection_adversarial() {
        // Adversarial: attacker tries to inject via carriage return
        let malicious = "value\r\n[new_section]\r\nkey = \"injected\"";
        let escaped = escape_toml_string(malicious);
        assert!(
            !escaped.contains('\r'),
            "escaped TOML string must not contain raw CR"
        );
        assert!(
            !escaped.contains('\n'),
            "escaped TOML string must not contain raw LF"
        );
    }

    // --- CSRF constant-time comparison test (FIND-P2-CSRF-TIMING) ---

    #[test]
    fn test_csrf_token_matches_constant_time() {
        // Matching tokens
        assert!(csrf_token_matches("abc-123-def", "abc-123-def"));
        // Non-matching tokens
        assert!(!csrf_token_matches("abc-123-def", "abc-123-xyz"));
        // Empty vs non-empty
        assert!(!csrf_token_matches("", "abc-123-def"));
        assert!(!csrf_token_matches("abc-123-def", ""));
        // Both empty
        assert!(csrf_token_matches("", ""));
        // Different length tokens -- must still be constant-time (no length oracle)
        assert!(!csrf_token_matches("short", "a-much-longer-token-value"));
    }
}
