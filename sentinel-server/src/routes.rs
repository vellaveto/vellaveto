use axum::{
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, EvaluationContext, Policy, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use governor::clock::Clock;

use subtle::ConstantTimeEq;

use crate::AppState;

pub fn build_router(state: AppState) -> Router {
    // Build CORS layer from configured origins.
    // Default (empty vec) = localhost only. "*" = any origin.
    let cors = build_cors_layer(&state.cors_origins);

    // Authenticated routes (behind API key + rate limit middleware)
    let authenticated = Router::new()
        .route("/health", get(health))
        .route("/api/evaluate", post(evaluate))
        .route("/api/policies", get(list_policies))
        .route("/api/policies", post(add_policy))
        .route("/api/policies/reload", post(reload_policies))
        .route("/api/policies/{id}", delete(remove_policy))
        .route("/api/audit/entries", get(audit_entries))
        .route("/api/audit/export", get(audit_export))
        .route("/api/audit/report", get(audit_report))
        .route("/api/audit/verify", get(audit_verify))
        .route("/api/audit/checkpoints", get(list_checkpoints))
        .route("/api/audit/checkpoints/verify", get(verify_checkpoints))
        .route("/api/audit/checkpoint", post(create_checkpoint))
        .route("/api/approvals/pending", get(list_pending_approvals))
        .route("/api/approvals/{id}", get(get_approval))
        .route("/api/approvals/{id}/approve", post(approve_approval))
        .route("/api/approvals/{id}/deny", post(deny_approval))
        .route("/api/metrics", get(metrics_json))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    // Merge the /metrics Prometheus endpoint OUTSIDE auth middleware so
    // Prometheus scrapers do not need an API key. This endpoint only
    // exposes operational counters, not security-sensitive data.
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .merge(authenticated)
        .layer(middleware::from_fn(request_id))
        .layer(middleware::from_fn(security_headers))
        .layer(DefaultBodyLimit::max(1_048_576)) // 1 MB max request body
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

fn build_cors_layer(origins: &[String]) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(std::time::Duration::from_secs(3600)); // Cache preflight for 1 hour

    if origins.iter().any(|o| o == "*") {
        base.allow_origin(Any)
    } else if origins.is_empty() {
        // Strict default: localhost only
        base.allow_origin([
            HeaderValue::from_static("http://localhost"),
            HeaderValue::from_static("http://127.0.0.1"),
            HeaderValue::from_static("http://[::1]"),
        ])
    } else {
        let allowed: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse::<HeaderValue>().ok())
            .collect();
        base.allow_origin(allowed)
    }
}

/// Middleware that adds standard security headers to all responses.
///
/// Headers added:
/// - `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing
/// - `X-Frame-Options: DENY` — prevents clickjacking via iframes
/// - `Content-Security-Policy: default-src 'none'` — blocks all content loading (API-only server)
/// - `Cache-Control: no-store` — prevents caching of sensitive API responses
/// - `X-Permitted-Cross-Domain-Policies: none` — blocks cross-domain policy files
/// - `Strict-Transport-Security` — HSTS header, only when serving over HTTPS
async fn security_headers(request: Request, next: Next) -> Response {
    // Detect HTTPS before consuming the request:
    // Check the URI scheme or the X-Forwarded-Proto header (set by reverse proxies).
    let is_https = request.uri().scheme_str() == Some("https")
        || request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("https"))
            .unwrap_or(false);

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    if is_https {
        headers.insert(
            header::HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

/// Middleware that adds a unique request ID to every response.
///
/// Generates a UUID v4 and sets it as the `X-Request-Id` response header.
/// If the client sends an `X-Request-Id` header, that value is preserved.
async fn request_id(request: Request, next: Next) -> Response {
    let incoming_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 128)
        .map(|s| s.to_string());

    let mut response = next.run(request).await;
    let id = incoming_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if let Ok(val) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), val);
    }
    response
}

/// Middleware that requires API key authentication.
///
/// **Public endpoints** (no auth required): `/health`, `/api/metrics`, and all
/// `OPTIONS`/`HEAD` requests.
///
/// **All other endpoints** (including GET on `/api/policies`, `/api/audit/*`,
/// `/api/approvals/*`) require a valid `Bearer` token when `SENTINEL_API_KEY`
/// is configured. This prevents unauthenticated access to sensitive policy
/// configurations, audit logs, and pending approvals (Finding #25).
///
/// If no API key is configured, all requests are allowed (development mode).
async fn require_api_key(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // Always skip auth for preflight and HEAD
    if request.method() == Method::OPTIONS || request.method() == Method::HEAD {
        return next.run(request).await;
    }

    // Public endpoints: always accessible without auth
    let path = request.uri().path();
    if path == "/health" || path == "/api/metrics" {
        return next.run(request).await;
    }

    // Skip auth if no API key configured (development mode)
    let api_key = match &state.api_key {
        Some(key) => key.clone(),
        None => return next.run(request).await,
    };

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header {
        // RFC 7235: Authorization scheme comparison is case-insensitive.
        Some(ref h) if h.len() > 7 && h[..7].eq_ignore_ascii_case("bearer ") => {
            let token = &h[7..];
            if token.as_bytes().ct_eq(api_key.as_bytes()).into() {
                next.run(request).await
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid API key"})),
                )
                    .into_response()
            }
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Authentication required"})),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    policies_loaded: usize,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let count = state.policies.load().len();
    Json(HealthResponse {
        status: "ok".to_string(),
        policies_loaded: count,
    })
}

/// Request body for the evaluate endpoint.
///
/// Accepts an action plus an optional evaluation context for context-aware
/// policy evaluation (time windows, call limits, agent identity, etc.).
#[derive(Deserialize)]
struct EvaluateRequest {
    #[serde(flatten)]
    action: Action,
    #[serde(default)]
    context: Option<EvaluationContext>,
}

#[derive(Serialize)]
struct EvaluateResponse {
    verdict: Verdict,
    action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_id: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Auto-extract target_paths and target_domains from action parameters.
///
/// Scans string values in parameters for file paths (starting with `/`)
/// and URLs (starting with `http://` or `https://`), populating the
/// corresponding Action fields for path/domain policy enforcement.
fn auto_extract_targets(action: &mut Action) {
    scan_params_for_targets(
        &action.parameters,
        &mut action.target_paths,
        &mut action.target_domains,
    );
}

/// Maximum recursion depth for parameter scanning (defense-in-depth against stack overflow).
const MAX_PARAM_SCAN_DEPTH: usize = 32;

/// Maximum number of extracted paths + domains to prevent OOM from large parameter arrays.
const MAX_EXTRACTED_TARGETS: usize = 256;

fn scan_params_for_targets(
    value: &serde_json::Value,
    paths: &mut Vec<String>,
    domains: &mut Vec<String>,
) {
    scan_params_for_targets_inner(value, paths, domains, 0);
}

fn scan_params_for_targets_inner(
    value: &serde_json::Value,
    paths: &mut Vec<String>,
    domains: &mut Vec<String>,
    depth: usize,
) {
    if depth >= MAX_PARAM_SCAN_DEPTH {
        return;
    }
    if paths.len() + domains.len() >= MAX_EXTRACTED_TARGETS {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            let lower = s.to_lowercase();
            if let Some(lower_after_scheme) = lower.strip_prefix("file://") {
                // Preserve original path case for case-sensitive filesystems
                let after_scheme = &s[7..]; // skip "file://"
                let path_original = if lower_after_scheme.starts_with("localhost") {
                    &after_scheme["localhost".len()..]
                } else if after_scheme.starts_with('/') {
                    after_scheme
                } else {
                    after_scheme
                        .find('/')
                        .map(|i| &after_scheme[i..])
                        .unwrap_or("")
                };
                // Strip query strings and fragments
                let file_path = strip_query_and_fragment(path_original);
                if !file_path.is_empty() {
                    paths.push(file_path.to_string());
                }
            } else if let Some(scheme_end) = s.find("://") {
                // SECURITY (R15-EVAL-15): Extract domains from all schemes
                // with authority (http, https, ftp, ssh, wss, ldap, etc.),
                // not just http/https. Otherwise ftp://evil.com/file bypasses
                // network rules that block evil.com.
                let scheme = &lower[..scheme_end];
                // Only process if scheme looks valid (alphabetic, 1-10 chars)
                if !scheme.is_empty()
                    && scheme.len() <= 10
                    && scheme.chars().all(|c| c.is_ascii_alphabetic())
                {
                    if let Some(authority) = s.find("://").map(|i| &s[i + 3..]) {
                        let host_raw = authority.split('/').next().unwrap_or(authority);
                        // SECURITY (R12-EXT-2): Percent-decode authority before splitting on '@'.
                        // Without this, http://evil.com%40blocked.com bypasses domain matching.
                        let decoded =
                            percent_encoding::percent_decode_str(host_raw).decode_utf8_lossy();
                        let host = decoded.as_ref();
                        let host = host.split(':').next().unwrap_or(host);
                        let host = host.split('?').next().unwrap_or(host);
                        let host = host.split('#').next().unwrap_or(host);
                        let host = if let Some(pos) = host.rfind('@') {
                            &host[pos + 1..]
                        } else {
                            host
                        };
                        if !host.is_empty() {
                            domains.push(host.to_lowercase());
                        }
                    }
                }
            } else if s.starts_with('/') && !s.contains(' ') {
                // Strip query/fragments from raw paths
                let clean = strip_query_and_fragment(s);
                if !clean.is_empty() {
                    paths.push(clean.to_string());
                }
            } else if looks_like_relative_path(s) {
                // SECURITY (R11-PATH-3): Catch relative paths containing ..
                // or starting with ~/ that would bypass extraction. Prepend /
                // so they are visible to path policy checks.
                let clean = strip_query_and_fragment(s);
                if !clean.is_empty() {
                    // Convert to absolute for policy checking
                    paths.push(format!("/{}", clean));
                }
            }
        }
        serde_json::Value::Object(map) => {
            for val in map.values() {
                scan_params_for_targets_inner(val, paths, domains, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                scan_params_for_targets_inner(val, paths, domains, depth + 1);
            }
        }
        _ => {}
    }
}

/// Strip query string (`?...`) and fragment (`#...`) from a path.
fn strip_query_and_fragment(path: &str) -> &str {
    let path = path.split('?').next().unwrap_or(path);
    path.split('#').next().unwrap_or(path)
}

/// Detect relative paths that could bypass extraction.
///
/// Catches `../` traversal, `~/` home directory expansion, and `./` current
/// directory relative paths. These are not caught by the `starts_with('/')`
/// check for absolute paths but could be resolved by downstream tools.
fn looks_like_relative_path(s: &str) -> bool {
    if s.contains(' ') {
        return false; // Likely not a path
    }
    s.starts_with("../")
        || s.starts_with("./")
        || s.starts_with("~/")
        || s.contains("/../")
        || s == ".."
        || s == "~"
}

/// Derive the resolver identity from the authenticated principal.
///
/// SECURITY (R11-APPR-4): The `resolved_by` field in approval resolution must
/// reflect the actual authenticated identity, not a client-supplied string.
/// If a Bearer token is present, derive the identity from the token hash.
/// The client-supplied value is appended as a note but cannot override the
/// authenticated identity.
fn derive_resolver_identity(headers: &HeaderMap, client_value: &str) -> String {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
            let token = &auth[7..];
            if !token.is_empty() {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(token.as_bytes());
                let principal = format!("bearer:{}", hex::encode(&hash[..8]));
                if client_value != "anonymous" {
                    return format!("{} (note: {})", principal, client_value);
                }
                return principal;
            }
        }
    }
    client_value.to_string()
}

/// Sanitize client-supplied evaluation context.
///
/// The server evaluate endpoint is a stateless API — it has no session tracking.
/// Clients cannot be trusted to provide their own `call_counts` or
/// `previous_actions` because they could lie to bypass MaxCalls or
/// RequirePreviousAction policies. These fields are stripped.
///
/// SECURITY (R20-AGENT-ID): When the request is authenticated with a Bearer
/// token, `agent_id` is derived from the token hash (matching the approval
/// endpoint's `derive_resolver_identity` pattern). This prevents a client
/// from spoofing another agent's identity to bypass agent_id-based policies.
/// Client-supplied agent_id is only preserved as a note appended to the
/// derived principal, or used as-is when no auth is configured.
fn sanitize_context(
    context: Option<EvaluationContext>,
    headers: &HeaderMap,
) -> Option<EvaluationContext> {
    /// Maximum agent_id length to prevent memory abuse via oversized identifiers.
    const MAX_AGENT_ID_LEN: usize = 256;
    context.map(|ctx| {
        // Derive agent_id from authenticated principal when available.
        let client_agent_id = ctx
            .agent_id
            .filter(|id| !id.is_empty() && id.len() <= MAX_AGENT_ID_LEN);

        let agent_id = if let Some(auth) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
                let token = &auth[7..];
                if !token.is_empty() {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(token.as_bytes());
                    let principal = format!("bearer:{}", hex::encode(&hash[..8]));
                    // Append client-supplied agent_id as a note (not authoritative)
                    Some(match client_agent_id {
                        Some(ref client_id) => {
                            format!("{} (note: {})", principal, client_id)
                        }
                        None => principal,
                    })
                } else {
                    client_agent_id
                }
            } else {
                client_agent_id
            }
        } else {
            // No auth header — accept client-supplied agent_id as-is
            client_agent_id
        };

        EvaluationContext {
            // Override timestamp with server time — never trust client clocks
            timestamp: None,
            agent_id,
            // Strip session-state fields: the stateless server API has no session
            // tracking, so these must not be client-controlled
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
        }
    })
}

async fn evaluate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let eval_start = std::time::Instant::now();
    let mut action = req.action;

    // SECURITY (R10-1): Validate the deserialized action to catch null bytes,
    // oversized fields, and other malformed input before processing.
    if let Err(e) = action.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid action: {}", e),
            }),
        ));
    }

    // SECURITY: Sanitize client-supplied context to prevent spoofing of
    // session-state fields (call_counts, previous_actions, timestamp).
    // R20-AGENT-ID: Derive agent_id from auth header when present.
    let context = sanitize_context(req.context, &headers);

    // SECURITY (R10-2): Always run auto-extraction from parameters,
    // ignoring client-supplied target_paths/target_domains. A malicious
    // client could supply crafted paths that bypass path policy checks,
    // so we clear them and re-extract from the actual parameters.
    action.target_paths.clear();
    action.target_domains.clear();
    auto_extract_targets(&mut action);

    let policies = state.policies.load();

    let verdict = state
        .engine
        .load()
        .evaluate_action_with_context(&action, &policies, context.as_ref())
        .map_err(|e| {
            tracing::error!("Engine evaluation error: {}", e);
            state.metrics.record_error();
            crate::metrics::record_evaluation_verdict("error");
            crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Policy evaluation failed".to_string(),
                }),
            )
        })?;

    // If RequireApproval, create a pending approval.
    // Fail-closed: if approval creation fails, convert to Deny so the caller
    // can't proceed without a resolvable approval_id.
    let (verdict, approval_id) = if let Verdict::RequireApproval { ref reason } = verdict {
        // SECURITY (R9-2): Record the requester identity so the approval endpoint
        // can enforce separation of privilege (different principal must approve).
        let requester = derive_resolver_identity(&headers, "anonymous");
        let requested_by = if requester != "anonymous" {
            Some(requester)
        } else {
            None
        };
        match state
            .approvals
            .create(action.clone(), reason.clone(), requested_by)
            .await
        {
            Ok(id) => (verdict, Some(id)),
            Err(e) => {
                tracing::error!("Failed to create approval (fail-closed → Deny): {}", e);
                let deny_reason = "Approval required but could not be created".to_string();
                (
                    Verdict::Deny {
                        reason: deny_reason,
                    },
                    None,
                )
            }
        }
    } else {
        (verdict, None)
    };

    // Record metrics (both internal AtomicU64 and Prometheus)
    state.metrics.record_evaluation(&verdict);

    let verdict_label = match &verdict {
        Verdict::Allow => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::RequireApproval { .. } => "require_approval",
    };
    crate::metrics::record_evaluation_verdict(verdict_label);
    crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());

    // Log to audit — fire-and-forget on error (don't fail the request).
    // SECURITY (R16-AUDIT-3): Log at error level (not warn) because a silent
    // audit failure means security decisions proceed without an audit trail.
    // An attacker who fills the disk can suppress audit logging entirely.
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &verdict,
            json!({"source": "http", "approval_id": approval_id}),
        )
        .await
    {
        tracing::error!("AUDIT FAILURE: security decision not recorded: {}", e);
        state.metrics.record_error();
    } else {
        crate::metrics::increment_audit_entries();
    }

    Ok(Json(EvaluateResponse {
        verdict,
        action,
        approval_id,
    }))
}

async fn list_policies(State(state): State<AppState>) -> Json<Vec<Policy>> {
    let policies = state.policies.load();
    Json(policies.as_ref().clone())
}

async fn add_policy(
    State(state): State<AppState>,
    Json(policy): Json<Policy>,
) -> (StatusCode, Json<serde_json::Value>) {
    // SECURITY (R12-SRV-1): Validate policy fields before insertion.
    // Without validation, an attacker could POST a policy with id="*",
    // policy_type=Allow, priority=999999 to override all deny policies.

    // 1. Validate id: non-empty, no control chars, max 256 chars
    if policy.id.is_empty() || policy.id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy id must be non-empty"})),
        );
    }
    if policy.id.len() > 256 || policy.id.chars().any(|c| c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy id contains invalid characters or exceeds 256 chars"})),
        );
    }

    // 2. Validate name: non-empty, no control chars, max 256 chars
    if policy.name.is_empty() || policy.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy name must be non-empty"})),
        );
    }
    if policy.name.len() > 256 || policy.name.chars().any(|c| c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy name contains invalid characters or exceeds 256 chars"})),
        );
    }

    // 3. Validate priority is within a reasonable range.
    // SECURITY (R17-POL-1): Dynamic policies added via API are capped at ±1000
    // to prevent an attacker from shadowing config-loaded deny policies with
    // a max-priority Allow rule.
    if policy.priority < -1_000 || policy.priority > 1_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Dynamic policy priority must be between -1000 and 1000"})),
        );
    }

    // SECURITY (R17-POL-2): Reject wildcard-only IDs that match ALL tools.
    // An attacker with API access could POST id="*", type=Allow, priority=1000
    // to override all deny rules. Require at least a colon-separated scope.
    {
        let id_trimmed = policy.id.trim();
        if id_trimmed == "*" || id_trimmed == "*:*" {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error": "Wildcard-only policy IDs ('*', '*:*') are not allowed via API"}),
                ),
            );
        }
    }

    // SECURITY (R15-RACE-*): Hold write lock for the entire read-modify-write
    // sequence. This prevents TOCTOU races (duplicate-ID check, lost updates,
    // stale max-count check) between concurrent add/remove/reload operations.
    // The read path (evaluate) remains lock-free via ArcSwap::load().
    let _guard = state.policy_write_lock.lock().await;

    // 4. Reject duplicate policy IDs
    let existing = state.policies.load();
    if existing.iter().any(|p| p.id == policy.id) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": format!("Policy with id '{}' already exists", policy.id)})),
        );
    }

    // 5. Enforce max policy count (prevent resource exhaustion)
    if existing.len() >= 10_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Maximum policy count (10000) reached"})),
        );
    }

    // Build candidate policy list
    let id = policy.id.clone();
    let mut candidate = existing.as_ref().clone();
    candidate.push(policy.clone());
    PolicyEngine::sort_policies(&mut candidate);

    // Compile-first: verify the new policy set compiles before storing
    match PolicyEngine::with_policies(false, &candidate) {
        Ok(compiled_engine) => {
            // Store engine first (stricter), then policies (R12-INT-2)
            state.engine.store(Arc::new(compiled_engine));
            state.policies.store(Arc::new(candidate));
            tracing::info!("Added policy: {}", id);
        }
        Err(errors) => {
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            tracing::warn!("add_policy rejected: compilation failed: {:?}", msgs);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Policy compilation failed — policy NOT added",
                    "details": msgs,
                })),
            );
        }
    }

    // Audit trail for policy mutation
    let action = Action::new("sentinel", "add_policy", json!({"policy_id": id}));
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "policy_added"}),
        )
        .await
    {
        tracing::warn!("Failed to audit add_policy: {}", e);
    }

    (StatusCode::CREATED, Json(json!({"added": id})))
}

async fn remove_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // SECURITY (R15-RACE-*): Serialize with other policy mutations.
    let _guard = state.policy_write_lock.lock().await;

    let existing = state.policies.load();
    let candidate: Vec<Policy> = existing.iter().filter(|p| p.id != id).cloned().collect();
    let removed = existing.len().saturating_sub(candidate.len());

    if removed == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("No policy with id '{}'", id)})),
        );
    }

    // Compile-first: verify the remaining set compiles before storing
    match PolicyEngine::with_policies(false, &candidate) {
        Ok(compiled_engine) => {
            state.engine.store(Arc::new(compiled_engine));
            state.policies.store(Arc::new(candidate));
            tracing::info!("Removed {} policy(ies) with id: {}", removed, id);
        }
        Err(errors) => {
            // This is unlikely (removing a policy shouldn't break compilation)
            // but we stay fail-closed.
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            tracing::error!("remove_policy rejected: recompilation failed: {:?}", msgs);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Policy recompilation failed after removal — no changes applied",
                    "details": msgs,
                })),
            );
        }
    }

    // Audit trail for policy mutation
    let action = Action::new(
        "sentinel",
        "remove_policy",
        json!({"policy_id": id, "removed_count": removed}),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "policy_removed"}),
        )
        .await
    {
        tracing::warn!("Failed to audit remove_policy: {}", e);
    }

    (StatusCode::OK, Json(json!({"removed": removed, "id": id})))
}

async fn reload_policies(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let count = crate::reload_policies_from_file(&state, "api")
        .await
        .map_err(|e| {
            tracing::error!("{}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to reload policy configuration".to_string(),
                }),
            )
        })?;

    // SECURITY (R10-9): Do not return the full filesystem path in the response.
    // It leaks deployment layout information to any authenticated caller.
    Ok(Json(json!({"reloaded": count, "status": "ok"})))
}

/// SECURITY (R16-AUDIT-5): Default and maximum page size for audit entry listing.
/// Prevents memory DoS from loading the entire audit log into a single response.
const DEFAULT_AUDIT_PAGE_SIZE: usize = 100;
const MAX_AUDIT_PAGE_SIZE: usize = 1000;

/// Query parameters for paginated audit entry listing.
#[derive(Deserialize)]
struct AuditEntriesQuery {
    /// Maximum number of entries to return (default 100, max 1000).
    #[serde(default)]
    limit: Option<usize>,
    /// Number of entries to skip from the end (most recent first).
    #[serde(default)]
    offset: Option<usize>,
}

async fn audit_entries(
    State(state): State<AppState>,
    Query(params): Query<AuditEntriesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let entries = state.audit.load_entries().await.map_err(|e| {
        tracing::error!("Failed to load audit entries: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load audit entries".to_string(),
            }),
        )
    })?;

    let total = entries.len();
    let limit = params
        .limit
        .unwrap_or(DEFAULT_AUDIT_PAGE_SIZE)
        .min(MAX_AUDIT_PAGE_SIZE);
    let offset = params.offset.unwrap_or(0);

    // Return the most recent entries (tail of the list), paginated.
    let page: Vec<_> = entries.into_iter().rev().skip(offset).take(limit).collect();

    Ok(Json(
        json!({"total": total, "count": page.len(), "offset": offset, "limit": limit, "entries": page}),
    ))
}

/// Query parameters for the audit export endpoint.
#[derive(Deserialize)]
struct AuditExportQuery {
    /// Export format: "cef" or "jsonl". Default: "jsonl".
    format: Option<String>,
    /// Only include entries with timestamp >= this value (ISO 8601 string comparison).
    since: Option<String>,
    /// Maximum number of entries to export. Default: 100, max: 1000.
    limit: Option<usize>,
}

/// Export audit entries in SIEM-compatible formats (CEF or JSON Lines).
///
/// Query parameters:
/// - `format`: "cef" or "jsonl" (default: "jsonl")
/// - `since`: ISO 8601 timestamp filter (entries >= this value)
/// - `limit`: Maximum entries (default: 100, max: 1000)
///
/// Returns `text/plain` for CEF, `application/x-ndjson` for JSON Lines.
async fn audit_export(
    State(state): State<AppState>,
    Query(query): Query<AuditExportQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let format = query
        .format
        .as_deref()
        .and_then(sentinel_audit::export::ExportFormat::parse_format)
        .unwrap_or(sentinel_audit::export::ExportFormat::JsonLines);

    let limit = query.limit.unwrap_or(100).min(1000); // Cap at 1000

    let entries = state.audit.load_entries().await.map_err(|e| {
        tracing::error!("Failed to load audit entries for export: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load audit entries".to_string(),
            }),
        )
    })?;

    // Filter by `since` timestamp if provided (lexicographic comparison on ISO 8601)
    let filtered: Vec<_> = if let Some(ref since) = query.since {
        entries
            .into_iter()
            .filter(|e| e.timestamp.as_str() >= since.as_str())
            .take(limit)
            .collect()
    } else {
        entries.into_iter().take(limit).collect()
    };

    let body = sentinel_audit::export::format_entries(&filtered, format);

    let content_type = match format {
        sentinel_audit::export::ExportFormat::Cef => "text/plain",
        sentinel_audit::export::ExportFormat::JsonLines => "application/x-ndjson",
    };

    Ok(([(header::CONTENT_TYPE, content_type)], body))
}

async fn audit_report(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let report = state.audit.generate_report().await.map_err(|e| {
        tracing::error!("Failed to generate audit report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate audit report".to_string(),
            }),
        )
    })?;

    // SECURITY (R16-AUDIT-5): Return summary statistics only, not the full
    // entry list. The entries endpoint provides paginated access to individual
    // entries. Embedding all entries in the report response could exhaust
    // server memory with a large audit log.
    Ok(Json(json!({
        "total_entries": report.total_entries,
        "allow_count": report.allow_count,
        "deny_count": report.deny_count,
        "require_approval_count": report.require_approval_count,
    })))
}

async fn audit_verify(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let verification = state.audit.verify_chain().await.map_err(|e| {
        tracing::error!("Failed to verify audit chain: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to verify audit chain".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(verification).map_err(|e| {
        tracing::error!("Audit verification serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

// === Checkpoint Endpoints ===

async fn list_checkpoints(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let checkpoints = state.audit.load_checkpoints().await.map_err(|e| {
        tracing::error!("Failed to load checkpoints: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load checkpoints".to_string(),
            }),
        )
    })?;

    Ok(Json(
        json!({"count": checkpoints.len(), "checkpoints": checkpoints}),
    ))
}

async fn verify_checkpoints(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let verification = state.audit.verify_checkpoints().await.map_err(|e| {
        tracing::error!("Failed to verify checkpoints: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to verify checkpoints".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(verification).map_err(|e| {
        tracing::error!("Checkpoint verification serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

async fn create_checkpoint(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let checkpoint = state.audit.create_checkpoint().await.map_err(|e| {
        tracing::error!("Failed to create checkpoint: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create checkpoint".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(&checkpoint).map_err(|e| {
        tracing::error!("Checkpoint serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

// === Prometheus Metrics Endpoint ===

/// Serve Prometheus text exposition format metrics.
///
/// This endpoint is intentionally outside the auth middleware so that
/// Prometheus scrapers can access it without an API key. It only exposes
/// operational counters and gauges, not security-sensitive data.
async fn prometheus_metrics(State(state): State<AppState>) -> Response {
    match &state.prometheus_handle {
        Some(handle) => {
            // Update dynamic gauges before rendering
            let policy_count = state.policies.load().len();
            crate::metrics::set_policies_loaded(policy_count as f64);
            crate::metrics::set_uptime_seconds(state.metrics.start_time.elapsed().as_secs_f64());

            let body = handle.render();
            ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// === JSON Metrics Endpoint ===

async fn metrics_json(State(state): State<AppState>) -> Json<serde_json::Value> {
    let m = &state.metrics;
    let uptime = m.start_time.elapsed();
    Json(json!({
        "uptime_seconds": uptime.as_secs(),
        "policies_loaded": state.policies.load().len(),
        "evaluations": {
            "total": m.evaluations_total.load(Ordering::Relaxed),
            "allow": m.evaluations_allow.load(Ordering::Relaxed),
            "deny": m.evaluations_deny.load(Ordering::Relaxed),
            "require_approval": m.evaluations_require_approval.load(Ordering::Relaxed),
            "error": m.evaluations_error.load(Ordering::Relaxed),
        }
    }))
}

// === Approval Endpoints ===

async fn list_pending_approvals(State(state): State<AppState>) -> Json<serde_json::Value> {
    let pending = state.approvals.list_pending().await;
    // SECURITY (R11-APPR-10): Redact sensitive parameters before returning.
    // The approval listing may contain API keys, credentials, or PII in the
    // action parameters. Apply the same redaction used by the audit logger.
    let redacted: Vec<serde_json::Value> = pending
        .iter()
        .map(|a| {
            let mut val = serde_json::to_value(a).unwrap_or_default();
            if let Some(action) = val.get_mut("action") {
                if let Some(params) = action.get("parameters") {
                    let redacted_params = sentinel_audit::redact_keys_and_patterns(params);
                    action["parameters"] = redacted_params;
                }
            }
            val
        })
        .collect();
    Json(json!({"count": redacted.len(), "approvals": redacted}))
}

async fn get_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    let approval = state.approvals.get(&id).await.map_err(|e| {
        tracing::debug!("Approval lookup failed for '{}': {}", id, e);
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Approval not found".to_string(),
            }),
        )
    })?;

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R11-APPR-10): Redact parameters before returning
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = sentinel_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
    Ok(Json(value))
}

#[derive(Deserialize)]
struct ResolveRequest {
    #[serde(default = "default_resolver")]
    resolved_by: String,
}

fn default_resolver() -> String {
    "anonymous".to_string()
}

/// Maximum length for the `resolved_by` field (Finding B1: prevents multi-MB strings).
const MAX_RESOLVED_BY_LEN: usize = 1024;

/// Maximum length for approval ID path parameters.
/// UUIDs are 36 chars; 128 gives ample margin while preventing log bloat.
const MAX_APPROVAL_ID_LEN: usize = 128;

/// Validate an approval ID from a URL path parameter.
/// SECURITY (R16-APPR-1): Reject oversized or malformed IDs to prevent
/// log bloat and provide clean error messages.
fn validate_approval_id(id: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if id.is_empty() || id.len() > MAX_APPROVAL_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Approval ID must be 1-{} characters", MAX_APPROVAL_ID_LEN),
            }),
        ));
    }
    // SECURITY (R16-APPR-2): Reject control characters in approval IDs
    if id.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Approval ID contains invalid characters".to_string(),
            }),
        ));
    }
    Ok(())
}

/// Sanitize the resolved_by field: strip control characters.
/// SECURITY (R16-APPR-2): Prevents stored XSS via audit trail if
/// rendered in a web UI, and prevents log injection with newlines/tabs.
fn sanitize_resolved_by(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

async fn approve_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ResolveRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    // SECURITY (R11-APPR-4): Derive resolver identity from the authenticated
    // principal (Bearer token hash) rather than trusting the client-supplied
    // resolved_by field. The client value is kept as a note but the auth
    // identity is the authoritative record.
    let client_resolved_by = body
        .map(|b| b.resolved_by.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    let resolved_by =
        sanitize_resolved_by(&derive_resolver_identity(&headers, &client_resolved_by));

    if resolved_by.len() > MAX_RESOLVED_BY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "resolved_by exceeds maximum length of {} bytes",
                    MAX_RESOLVED_BY_LEN
                ),
            }),
        ));
    }

    let approval = state
        .approvals
        .approve(&id, &resolved_by)
        .await
        .map_err(|e| {
            let (status, msg) = match &e {
                sentinel_approval::ApprovalError::NotFound(_) => {
                    (StatusCode::NOT_FOUND, "Approval not found")
                }
                sentinel_approval::ApprovalError::AlreadyResolved(_) => {
                    (StatusCode::CONFLICT, "Approval already resolved")
                }
                sentinel_approval::ApprovalError::Expired(_) => {
                    (StatusCode::GONE, "Approval expired")
                }
                sentinel_approval::ApprovalError::Validation(ref msg) => {
                    // SECURITY (R9-2): Self-approval attempts return 403 Forbidden
                    tracing::warn!("Approval validation failed for '{}': {}", id, msg);
                    (StatusCode::FORBIDDEN, "Self-approval denied")
                }
                _ => {
                    tracing::error!("Approval approve error for '{}': {}", id, e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                }
            };
            (
                status,
                Json(ErrorResponse {
                    error: msg.to_string(),
                }),
            )
        })?;

    // M7: Audit trail for approval decisions
    {
        let audit_action = Action::new(
            "sentinel",
            "approval_resolved",
            json!({
                "approval_id": &id,
                "original_tool": &approval.action.tool,
                "original_function": &approval.action.function,
            }),
        );
        if let Err(e) = state
            .audit
            .log_entry(
                &audit_action,
                &Verdict::Allow,
                json!({
                    "source": "api",
                    "event": "approval_approved",
                    "resolved_by": &resolved_by,
                }),
            )
            .await
        {
            tracing::warn!("Failed to audit approval resolution for {}: {}", id, e);
        }
    }

    let value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

async fn deny_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ResolveRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    let client_resolved_by = body
        .map(|b| b.resolved_by.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    let resolved_by =
        sanitize_resolved_by(&derive_resolver_identity(&headers, &client_resolved_by));

    if resolved_by.len() > MAX_RESOLVED_BY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "resolved_by exceeds maximum length of {} bytes",
                    MAX_RESOLVED_BY_LEN
                ),
            }),
        ));
    }

    let approval = state.approvals.deny(&id, &resolved_by).await.map_err(|e| {
        let (status, msg) = match &e {
            sentinel_approval::ApprovalError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "Approval not found")
            }
            sentinel_approval::ApprovalError::AlreadyResolved(_) => {
                (StatusCode::CONFLICT, "Approval already resolved")
            }
            sentinel_approval::ApprovalError::Expired(_) => (StatusCode::GONE, "Approval expired"),
            _ => {
                tracing::error!("Approval deny error for '{}': {}", id, e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };
        (
            status,
            Json(ErrorResponse {
                error: msg.to_string(),
            }),
        )
    })?;

    // M7: Audit trail for approval decisions
    {
        let audit_action = Action::new(
            "sentinel",
            "approval_resolved",
            json!({
                "approval_id": &id,
                "original_tool": &approval.action.tool,
                "original_function": &approval.action.function,
            }),
        );
        if let Err(e) = state
            .audit
            .log_entry(
                &audit_action,
                &Verdict::Deny {
                    reason: "approval_denied".to_string(),
                },
                json!({
                    "source": "api",
                    "event": "approval_denied",
                    "resolved_by": &resolved_by,
                }),
            )
            .await
        {
            tracing::warn!("Failed to audit approval denial for {}: {}", id, e);
        }
    }

    let value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// Middleware that enforces per-category rate limits.
///
/// Categories:
/// - **evaluate**: POST /api/evaluate
/// - **admin**: All other non-GET/OPTIONS requests (policy changes, approvals)
/// - **readonly**: GET requests (health, audit, policy listing)
///
/// The `/health` endpoint is always exempt from rate limiting so that
/// load balancer probes are never throttled.
///
/// Returns 429 Too Many Requests with a `Retry-After` header when exceeded.
async fn rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // Health endpoint is exempt — load balancer probes must never be throttled
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }

    // Per-IP rate limiting (checked before global to catch single-IP floods)
    if let Some(ref per_ip) = state.rate_limits.per_ip {
        let client_ip = extract_client_ip(&request, &state.trusted_proxies);
        if let Some(retry_after) = per_ip.check(client_ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Json(json!({"error": "Rate limit exceeded. Try again later.", "retry_after_seconds": retry_after})),
            )
                .into_response();
        }
    }

    // Per-principal rate limiting (keyed by X-Principal header, Bearer token, or client IP)
    if let Some(ref per_principal) = state.rate_limits.per_principal {
        let principal_key = extract_principal_key(&request, &state.trusted_proxies);
        if let Some(retry_after) = per_principal.check(principal_key) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Json(json!({"error": "Rate limit exceeded. Try again later.", "retry_after_seconds": retry_after})),
            )
                .into_response();
        }
    }

    // Global per-category rate limiting
    let limiter = categorize_rate_limit(&state.rate_limits, request.method(), request.uri().path());

    if let Some(limiter) = limiter {
        if let Err(not_until) = limiter.check() {
            let wait = not_until.wait_time_from(governor::clock::DefaultClock::default().now());
            let retry_after = wait.as_secs().max(1);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Json(json!({"error": "Rate limit exceeded. Try again later.", "retry_after_seconds": retry_after})),
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Extract the client IP from the request using a secure trust model.
///
/// **When `trusted_proxies` is empty (default):** Proxy headers (`X-Forwarded-For`,
/// `X-Real-IP`) are ignored entirely. The connection IP from `ConnectInfo` is used,
/// falling back to 127.0.0.1 in test environments without real connections.
/// This prevents spoofing attacks where clients set arbitrary proxy headers.
///
/// **When `trusted_proxies` is configured:** The **rightmost untrusted** IP from the
/// `X-Forwarded-For` chain is used (RFC 7239). This is the last entry NOT in the
/// trusted proxy list. The leftmost entry is always attacker-controlled and must
/// never be used directly.
fn extract_client_ip(request: &Request, trusted_proxies: &[std::net::IpAddr]) -> std::net::IpAddr {
    // Get the real TCP connection IP from ConnectInfo (set by axum when using
    // into_make_service_with_connect_info). Falls back to localhost in tests.
    let connection_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    // If no trusted proxies configured, never trust proxy headers.
    // This is the safe default that prevents XFF spoofing.
    if trusted_proxies.is_empty() {
        return connection_ip;
    }

    // Only trust proxy headers if the direct connection comes from a trusted proxy.
    if !trusted_proxies.contains(&connection_ip) {
        return connection_ip;
    }

    // Trusted proxy path: parse X-Forwarded-For and find the rightmost
    // entry that is NOT a trusted proxy. This is the real client IP.
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(val) = xff.to_str() {
            // Walk from right to left, skipping trusted proxy IPs.
            for entry in val.rsplit(',') {
                if let Ok(ip) = entry.trim().parse::<std::net::IpAddr>() {
                    if !trusted_proxies.contains(&ip) {
                        return ip;
                    }
                }
            }
        }
    }

    // Fall back to X-Real-IP if set by a trusted proxy
    if let Some(xri) = request.headers().get("x-real-ip") {
        if let Ok(val) = xri.to_str() {
            if let Ok(ip) = val.trim().parse::<std::net::IpAddr>() {
                return ip;
            }
        }
    }

    // All XFF entries were trusted proxies — use connection IP
    connection_ip
}

/// Extract the principal key from the request for per-principal rate limiting.
///
/// Resolution order:
/// 1. `X-Principal` header — only trusted from connections originating from a
///    configured trusted proxy IP. When `trusted_proxies` is empty, X-Principal
///    is ignored entirely to prevent spoofing (KL1 hardening).
/// 2. Bearer token from the `Authorization` header — hashed with SHA-256 to
///    prevent raw token leakage in rate limit logs/maps (KL1 hardening).
/// 3. Client IP address as a string — fallback for unauthenticated requests.
///
/// Rate limiting now runs AFTER `require_api_key`, so by the time this
/// function is called, the Bearer token has already been validated.
fn extract_principal_key(request: &Request, trusted_proxies: &[std::net::IpAddr]) -> String {
    /// Maximum X-Principal header length to prevent memory abuse in rate-limit maps.
    const MAX_PRINCIPAL_LEN: usize = 256;
    // 1. X-Principal header — only trust from known proxies (KL1)
    if !trusted_proxies.is_empty() {
        let client_ip = extract_client_ip(request, trusted_proxies);
        if trusted_proxies.contains(&client_ip) {
            if let Some(principal) = request
                .headers()
                .get("x-principal")
                .and_then(|v| v.to_str().ok())
            {
                if !principal.is_empty() && principal.len() <= MAX_PRINCIPAL_LEN {
                    return format!("principal:{}", principal);
                }
            }
        }
    }

    // 2. Bearer token from Authorization header — hashed for privacy (KL1)
    if let Some(auth) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth
            .get(7..)
            .filter(|_| auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer "))
        {
            if !token.is_empty() {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(token.as_bytes());
                // 128-bit truncation is sufficient for rate limit bucketing
                return format!("bearer:{}", hex::encode(&hash[..16]));
            }
        }
    }

    // 3. Fallback to client IP
    let client_ip = extract_client_ip(request, trusted_proxies);
    format!("ip:{}", client_ip)
}

fn categorize_rate_limit<'a>(
    limits: &'a crate::RateLimits,
    method: &Method,
    path: &str,
) -> Option<&'a governor::DefaultDirectRateLimiter> {
    if path == "/api/evaluate" && method == Method::POST {
        limits.evaluate.as_ref()
    } else if method != Method::GET && method != Method::OPTIONS && method != Method::HEAD {
        limits.admin.as_ref()
    } else {
        limits.readonly.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;

    /// Helper to build a request with specific headers for testing extract_principal_key.
    fn build_request(headers: &[(&str, &str)]) -> Request {
        let mut builder = HttpRequest::builder().uri("/api/evaluate").method("POST");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    // --- KL1: X-Principal only trusted from trusted proxies ---

    #[test]
    fn test_principal_key_x_principal_ignored_without_trusted_proxies() {
        // With empty trusted_proxies, X-Principal header should be ignored
        let request = build_request(&[("x-principal", "alice")]);
        let key = extract_principal_key(&request, &[]);
        // Should fall through to IP fallback, not use X-Principal
        assert!(key.starts_with("ip:"), "Expected ip: prefix, got: {}", key);
    }

    #[test]
    fn test_principal_key_x_principal_trusted_from_known_proxy() {
        // With trusted_proxies and connection from a trusted IP, X-Principal is accepted
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let request = build_request(&[("x-principal", "alice")]);
        // In test environment, connection IP defaults to 127.0.0.1 (LOCALHOST)
        let key = extract_principal_key(&request, &trusted);
        assert_eq!(key, "principal:alice");
    }

    #[test]
    fn test_principal_key_x_principal_ignored_from_untrusted_ip() {
        // Trusted proxies configured but connection IP is not in the list
        let trusted = vec!["10.0.0.1".parse().unwrap()];
        let request = build_request(&[("x-principal", "alice")]);
        // Connection IP is 127.0.0.1 (test default), not in trusted list
        let key = extract_principal_key(&request, &trusted);
        assert!(
            !key.starts_with("principal:"),
            "X-Principal should be ignored from untrusted IP, got: {}",
            key
        );
    }

    // --- KL1: Bearer token hashed ---

    #[test]
    fn test_principal_key_bearer_token_hashed() {
        let request = build_request(&[("authorization", "Bearer my-secret-token")]);
        let key = extract_principal_key(&request, &[]);
        assert!(
            key.starts_with("bearer:"),
            "Expected bearer: prefix, got: {}",
            key
        );
        // Must NOT contain the raw token
        assert!(
            !key.contains("my-secret-token"),
            "Raw token should not appear in key: {}",
            key
        );
        // Hash should be 32 hex chars (128 bits = 16 bytes)
        let hash_part = key.strip_prefix("bearer:").unwrap();
        assert_eq!(hash_part.len(), 32, "Hash should be 32 hex chars");
    }

    #[test]
    fn test_principal_key_bearer_hash_deterministic() {
        let r1 = build_request(&[("authorization", "Bearer token-abc")]);
        let r2 = build_request(&[("authorization", "Bearer token-abc")]);
        let k1 = extract_principal_key(&r1, &[]);
        let k2 = extract_principal_key(&r2, &[]);
        assert_eq!(k1, k2, "Same token should produce same key");
    }

    #[test]
    fn test_principal_key_different_tokens_different_hashes() {
        let r1 = build_request(&[("authorization", "Bearer token-a")]);
        let r2 = build_request(&[("authorization", "Bearer token-b")]);
        let k1 = extract_principal_key(&r1, &[]);
        let k2 = extract_principal_key(&r2, &[]);
        assert_ne!(k1, k2, "Different tokens should produce different keys");
    }

    // --- KL1: IP fallback ---

    #[test]
    fn test_principal_key_fallback_to_ip() {
        let request = build_request(&[]);
        let key = extract_principal_key(&request, &[]);
        assert!(
            key.starts_with("ip:"),
            "Should fall back to IP, got: {}",
            key
        );
    }

    // --- Context sanitization tests ---

    #[test]
    fn test_sanitize_context_none_stays_none() {
        let headers = HeaderMap::new();
        assert!(sanitize_context(None, &headers).is_none());
    }

    #[test]
    fn test_sanitize_context_strips_call_counts_and_history() {
        let headers = HeaderMap::new();
        let mut call_counts = std::collections::HashMap::new();
        call_counts.insert("read_file".to_string(), 99);
        let spoofed = EvaluationContext {
            timestamp: Some("2026-01-01T00:00:00Z".to_string()),
            agent_id: Some("agent-a".to_string()),
            call_counts,
            previous_actions: vec!["login".to_string(), "auth".to_string()],
        };
        let sanitized = sanitize_context(Some(spoofed), &headers).unwrap();
        // agent_id preserved (no auth header)
        assert_eq!(sanitized.agent_id, Some("agent-a".to_string()));
        // Session-state fields stripped
        assert!(sanitized.call_counts.is_empty());
        assert!(sanitized.previous_actions.is_empty());
        // Timestamp overridden (set to None = server will use wall clock)
        assert!(sanitized.timestamp.is_none());
    }

    #[test]
    fn test_sanitize_context_preserves_agent_id_without_auth() {
        let headers = HeaderMap::new();
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some("my-agent".to_string()),
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
        };
        let sanitized = sanitize_context(Some(ctx), &headers).unwrap();
        assert_eq!(sanitized.agent_id, Some("my-agent".to_string()));
    }

    /// SECURITY (R20-AGENT-ID): When a Bearer token is present, agent_id
    /// must be derived from the token hash, not accepted from the client.
    #[test]
    fn test_sanitize_context_derives_agent_id_from_auth() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-secret-key".parse().unwrap(),
        );
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some("spoofed-agent".to_string()),
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
        };
        let sanitized = sanitize_context(Some(ctx), &headers).unwrap();
        let agent_id = sanitized.agent_id.unwrap();
        assert!(
            agent_id.starts_with("bearer:"),
            "agent_id should be derived from token hash, got: {}",
            agent_id
        );
        assert!(
            agent_id.contains("(note: spoofed-agent)"),
            "Client agent_id should appear as note, got: {}",
            agent_id
        );
    }

    /// SECURITY (R20-AGENT-ID): Without client agent_id, auth-derived only.
    #[test]
    fn test_sanitize_context_derives_agent_id_from_auth_no_client() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-secret-key".parse().unwrap(),
        );
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
        };
        let sanitized = sanitize_context(Some(ctx), &headers).unwrap();
        let agent_id = sanitized.agent_id.unwrap();
        assert!(
            agent_id.starts_with("bearer:"),
            "agent_id should be derived from token hash, got: {}",
            agent_id
        );
        assert!(
            !agent_id.contains("note:"),
            "No note when no client agent_id"
        );
    }

    #[test]
    fn test_sanitize_context_rejects_oversized_agent_id() {
        let headers = HeaderMap::new();
        let oversized_id = "a".repeat(257);
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some(oversized_id),
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
        };
        let sanitized = sanitize_context(Some(ctx), &headers).unwrap();
        assert!(
            sanitized.agent_id.is_none(),
            "Agent ID > 256 bytes should be rejected"
        );
    }

    #[test]
    fn test_sanitize_context_allows_max_length_agent_id() {
        let headers = HeaderMap::new();
        let max_id = "b".repeat(256);
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some(max_id.clone()),
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
        };
        let sanitized = sanitize_context(Some(ctx), &headers).unwrap();
        assert_eq!(sanitized.agent_id, Some(max_id));
    }

    #[test]
    fn test_sanitize_context_rejects_empty_agent_id() {
        let headers = HeaderMap::new();
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some("".to_string()),
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
        };
        let sanitized = sanitize_context(Some(ctx), &headers).unwrap();
        assert!(
            sanitized.agent_id.is_none(),
            "Empty agent_id should be rejected"
        );
    }

    #[test]
    fn test_principal_key_rejects_oversized_x_principal() {
        let oversized = "x".repeat(257);
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let request = build_request(&[("x-principal", &oversized)]);
        let key = extract_principal_key(&request, &trusted);
        assert!(
            !key.starts_with("principal:"),
            "Oversized X-Principal should be ignored"
        );
    }

    #[test]
    fn test_principal_key_allows_max_length_x_principal() {
        let max_principal = "y".repeat(256);
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let request = build_request(&[("x-principal", &max_principal)]);
        let key = extract_principal_key(&request, &trusted);
        assert_eq!(key, format!("principal:{}", max_principal));
    }

    // --- R11-PATH-3: Relative path detection ---

    #[test]
    fn test_looks_like_relative_path_traversal() {
        assert!(looks_like_relative_path("../etc/passwd"));
        assert!(looks_like_relative_path("./config.json"));
        assert!(looks_like_relative_path("~/secret.txt"));
        assert!(looks_like_relative_path("foo/../bar"));
        assert!(looks_like_relative_path(".."));
        assert!(looks_like_relative_path("~"));
    }

    #[test]
    fn test_looks_like_relative_path_rejects_non_paths() {
        assert!(!looks_like_relative_path("some normal text"));
        assert!(!looks_like_relative_path("/absolute/path"));
        assert!(!looks_like_relative_path("filename.txt"));
        assert!(!looks_like_relative_path(""));
        assert!(!looks_like_relative_path("hello world ../foo"));
    }

    // --- R11-APPR-4: Resolver identity from auth headers ---

    #[test]
    fn test_derive_resolver_identity_with_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-secret-token".parse().unwrap(),
        );
        let result = derive_resolver_identity(&headers, "anonymous");
        assert!(
            result.starts_with("bearer:"),
            "Expected bearer: prefix, got: {}",
            result
        );
        // Should be deterministic
        let result2 = derive_resolver_identity(&headers, "anonymous");
        assert_eq!(result, result2);
    }

    #[test]
    fn test_derive_resolver_identity_with_bearer_and_client_note() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-secret-token".parse().unwrap(),
        );
        let result = derive_resolver_identity(&headers, "admin-alice");
        assert!(result.contains("bearer:"), "Should contain bearer hash");
        assert!(
            result.contains("(note: admin-alice)"),
            "Should include client note: {}",
            result
        );
    }

    #[test]
    fn test_derive_resolver_identity_case_insensitive_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "BEARER my-secret-token".parse().unwrap(),
        );
        let result = derive_resolver_identity(&headers, "anonymous");
        assert!(
            result.starts_with("bearer:"),
            "Should handle uppercase BEARER: {}",
            result
        );
    }

    #[test]
    fn test_derive_resolver_identity_no_auth_falls_back() {
        let headers = HeaderMap::new();
        let result = derive_resolver_identity(&headers, "some-user");
        assert_eq!(result, "some-user");
    }

    #[test]
    fn test_derive_resolver_identity_non_bearer_auth_falls_back() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        let result = derive_resolver_identity(&headers, "some-user");
        assert_eq!(result, "some-user");
    }
}
