use axum::{
    extract::{DefaultBodyLimit, Extension, Path, Query, Request, State},
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

use crate::rbac::{rbac_middleware, RbacState};
use crate::tenant::{TenantContext, TenantState, tenant_middleware};
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
        // Tool registry endpoints (P2.1)
        .route("/api/registry/tools", get(list_registry_tools))
        .route(
            "/api/registry/tools/{name}/approve",
            post(approve_registry_tool),
        )
        .route(
            "/api/registry/tools/{name}/revoke",
            post(revoke_registry_tool),
        )
        // Tenant management endpoints (Phase 3)
        .route("/api/tenants", get(list_tenants))
        .route("/api/tenants", post(create_tenant))
        .route("/api/tenants/{id}", get(get_tenant))
        .route("/api/tenants/{id}", axum::routing::put(update_tenant))
        .route("/api/tenants/{id}", delete(delete_tenant))
        // Admin dashboard (P3.2)
        .route("/dashboard", get(crate::dashboard::dashboard_page))
        .route(
            "/dashboard/approvals/{id}/approve",
            post(crate::dashboard::dashboard_approve),
        )
        .route(
            "/dashboard/approvals/{id}/deny",
            post(crate::dashboard::dashboard_deny),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 3.1: Security Manager Admin APIs
        // ═══════════════════════════════════════════════════════════════════
        // Circuit Breaker (OWASP ASI08)
        .route("/api/circuit-breaker", get(list_circuit_breakers))
        .route("/api/circuit-breaker/stats", get(circuit_breaker_stats))
        .route("/api/circuit-breaker/{tool}", get(get_circuit_state))
        .route("/api/circuit-breaker/{tool}/reset", post(reset_circuit))
        // Shadow Agent Detection
        .route("/api/shadow-agents", get(list_shadow_agents))
        .route("/api/shadow-agents", post(register_shadow_agent))
        .route("/api/shadow-agents/{id}", delete(remove_shadow_agent))
        .route("/api/shadow-agents/{id}/trust", axum::routing::put(update_agent_trust))
        // Schema Lineage (OWASP ASI05)
        .route("/api/schema-lineage", get(list_schema_lineage))
        .route("/api/schema-lineage/{tool}", get(get_schema_lineage))
        .route("/api/schema-lineage/{tool}/trust", axum::routing::put(reset_schema_trust))
        .route("/api/schema-lineage/{tool}", delete(remove_schema_lineage))
        // Task State (MCP 2025-11-25 Async Tasks)
        .route("/api/tasks", get(list_tasks))
        .route("/api/tasks/stats", get(task_stats))
        .route("/api/tasks/{id}", get(get_task))
        .route("/api/tasks/{id}/cancel", post(cancel_task))
        // Auth Level (Step-Up Authentication)
        .route("/api/auth-levels/{session}", get(get_auth_level))
        .route("/api/auth-levels/{session}/upgrade", post(upgrade_auth_level))
        .route("/api/auth-levels/{session}", delete(clear_auth_level))
        // Sampling Detection
        .route("/api/sampling/stats", get(sampling_stats))
        .route("/api/sampling/{session}/reset", post(reset_sampling_stats))
        // Deputy Validation (OWASP ASI02)
        .route("/api/deputy/delegations", get(list_delegations))
        .route("/api/deputy/delegations", post(register_delegation))
        .route("/api/deputy/delegations/{session}", delete(remove_delegation))
        // ═══════════════════════════════════════════════════════════════════
        // Phase 6: Execution Graph Export
        // ═══════════════════════════════════════════════════════════════════
        .route("/api/graphs", get(list_graphs))
        .route("/api/graphs/{session}", get(get_graph))
        .route("/api/graphs/{session}/dot", get(get_graph_dot))
        .route("/api/graphs/{session}/stats", get(get_graph_stats))
        // SECURITY (R38-SRV-1): /metrics inside auth — exposes policy count
        // and pending approval count, which are security-sensitive (see R26-SRV-6).
        // SECURITY (R38-SRV-2): /metrics inside rate_limit — prevents scraper DoS.
        .route("/metrics", get(prometheus_metrics))
        // Tenant middleware (innermost - runs after auth, extracts tenant context)
        // When multi-tenancy is disabled, all requests get the default tenant.
        .route_layer(middleware::from_fn_with_state(
            TenantState {
                config: state.tenant_config.clone(),
                store: state.tenant_store.clone(),
            },
            tenant_middleware,
        ))
        // RBAC middleware (after tenant - runs after auth, checks permissions)
        // When RBAC is disabled, all requests get Admin role and pass through.
        .route_layer(middleware::from_fn_with_state(
            RbacState {
                config: state.rbac_config.clone(),
            },
            rbac_middleware,
        ))
        // SECURITY (R27-SRV-8): rate_limit MUST be outermost (applied last)
        // so it runs BEFORE auth. Previously auth was outermost, meaning
        // unauthenticated flood requests bypassed rate limiting entirely.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit));

    Router::new()
        .merge(authenticated)
        .layer(middleware::from_fn(request_id))
        .layer(middleware::from_fn(security_headers))
        // SECURITY: CSRF defense-in-depth via Origin/Referer validation
        .layer(middleware::from_fn_with_state(
            state.clone(),
            csrf_referer_check,
        ))
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
    let is_dashboard = request.uri().path().starts_with("/dashboard");

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
    // Dashboard serves inline <style> CSS, so it needs style-src 'unsafe-inline'.
    // All other routes use the strictest CSP: default-src 'none'.
    if is_dashboard {
        headers.insert(
            header::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
        );
    } else {
        headers.insert(
            header::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'"),
        );
    }
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
        // SECURITY (R31-SRV-6): Reject control characters (including TAB) in
        // client-supplied request IDs to prevent log injection attacks.
        .filter(|s| s.len() <= 128 && !s.chars().any(|c| c.is_control()))
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

/// Middleware that validates Origin/Referer headers on mutating requests.
///
/// This is a defense-in-depth CSRF protection layer. For state-changing requests
/// (POST, PUT, DELETE), we validate that the Origin or Referer header is present
/// and matches one of the allowed origins.
///
/// Validation rules:
/// - OPTIONS requests: skip (CORS preflight)
/// - GET/HEAD requests: skip (safe methods)
/// - POST/PUT/DELETE: require valid Origin or Referer
///
/// Origin matching:
/// - If `cors_origins` is empty: only localhost (127.0.0.1, ::1, localhost) allowed
/// - If `cors_origins` contains "*": any origin allowed (not recommended)
/// - Otherwise: origin must match one of the configured origins
async fn csrf_referer_check(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Skip validation for safe methods and CORS preflight
    let method = request.method().clone();
    if method == Method::OPTIONS || method == Method::GET || method == Method::HEAD {
        return next.run(request).await;
    }

    // For mutating methods, validate Origin or Referer
    let headers = request.headers();
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract origin from either header (prefer Origin, fall back to Referer)
    let request_origin = origin.or_else(|| {
        referer.and_then(|r| {
            // Extract origin from Referer URL (scheme + host + port)
            url::Url::parse(&r).ok().map(|u| {
                let port = u.port().map(|p| format!(":{}", p)).unwrap_or_default();
                format!("{}://{}{}", u.scheme(), u.host_str().unwrap_or(""), port)
            })
        })
    });

    // Validate the origin
    let is_valid = match &request_origin {
        None => {
            // No origin header - this could be a same-origin request from the browser
            // or a direct API call. For defense-in-depth, we allow it but log.
            // The main CSRF protection is the API key requirement.
            tracing::debug!("CSRF check: no Origin/Referer header, allowing (API key required)");
            true
        }
        Some(origin) => validate_origin(origin, &state.cors_origins),
    };

    if !is_valid {
        tracing::warn!(
            origin = ?request_origin,
            method = %method,
            path = %request.uri().path(),
            "CSRF check failed: origin not allowed"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Origin not allowed",
                "code": "CSRF_ORIGIN_MISMATCH"
            })),
        )
            .into_response();
    }

    next.run(request).await
}

/// Validate that an origin is in the allowed list.
///
/// SECURITY (R33-001): This function avoids timing side-channels by always
/// checking all configured origins rather than returning early on match.
/// This prevents attackers from enumerating allowed origins via timing analysis.
fn validate_origin(origin: &str, allowed_origins: &[String]) -> bool {
    // Wildcard allows everything (not secret, can return early)
    if allowed_origins.iter().any(|o| o == "*") {
        return true;
    }

    // Parse the origin to normalize it
    let origin_lower = origin.to_lowercase();

    // Check if it's localhost (always allowed for development)
    // SECURITY: Localhost detection is not timing-sensitive as these
    // prefixes are well-known and not secret.
    let is_localhost = origin_lower.starts_with("http://localhost")
        || origin_lower.starts_with("https://localhost")
        || origin_lower.starts_with("http://127.0.0.1")
        || origin_lower.starts_with("https://127.0.0.1")
        || origin_lower.starts_with("http://[::1]")
        || origin_lower.starts_with("https://[::1]");

    // If no origins configured, only allow localhost (strict default)
    if allowed_origins.is_empty() {
        return is_localhost;
    }

    // SECURITY (R33-001): Check all origins in constant time to prevent
    // timing side-channel that could reveal which origins are configured.
    // We accumulate the result and avoid early returns.
    let mut matched = false;
    for allowed in allowed_origins {
        let allowed_lower = allowed.to_lowercase();
        // Exact match
        if origin_lower == allowed_lower {
            matched = true;
            // Don't return early - continue checking to maintain constant time
        }
        // Prefix match when allowed has no port or just scheme:host
        if (!allowed_lower.contains(':') || allowed_lower.matches(':').count() == 1)
            && origin_lower.starts_with(&allowed_lower)
        {
            matched = true;
            // Don't return early
        }
    }

    // Return true if matched or if it's localhost (fallback)
    matched || is_localhost
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
    // SECURITY: Only skip auth for CORS preflight (OPTIONS).
    // HEAD requests MUST go through auth — they can reveal endpoint existence,
    // response sizes, and header values (R30-SRV-1).
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    // Public endpoints: always accessible without auth.
    // SECURITY (R38-SRV-1): /api/metrics removed — exposes policy count and
    // pending approval count (sensitive, per R26-SRV-6). /metrics (Prometheus)
    // is also now behind auth for the same reason.
    let path = request.uri().path();
    if path == "/health" {
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
            // SECURITY (R34-SRV-8): Hash before comparing to prevent length oracle.
            // ct_eq short-circuits on length mismatch; hashing normalizes to 32 bytes.
            use sha2::{Digest, Sha256};
            let token_hash = Sha256::digest(token.as_bytes());
            let key_hash = Sha256::digest(api_key.as_bytes());
            if token_hash.ct_eq(&key_hash).into() {
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

// SECURITY (R26-SRV-6): Health response no longer leaks policy count.
// Policy count is operational metrics, not health status. Moved to
// the authenticated /api/metrics endpoint.
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<String>,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    // Check cluster backend health if configured
    let cluster_status = match state.cluster_health().await {
        Ok(()) => None,
        Err(msg) => {
            tracing::warn!("Cluster health check failed: {}", msg);
            Some(msg)
        }
    };

    let status = if cluster_status.is_some() {
        "degraded".to_string()
    } else {
        "ok".to_string()
    };

    Json(HealthResponse {
        status,
        cluster: cluster_status,
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

/// SECURITY (R31-SRV-1): Redact action parameters before returning in the evaluate
/// response. Parameters may contain secrets (API keys, credentials) that should not
/// be echoed back over the wire where intermediary proxies/logs could capture them.
/// The caller already knows the parameters they submitted.
fn redact_response_action(mut action: Action) -> Action {
    action.parameters = serde_json::Value::Object(Default::default());
    // SECURITY (R32-SRV-2): Also clear extracted targets — they contain
    // file paths and domains derived from parameters, leaking the same info.
    action.target_paths.clear();
    action.target_domains.clear();
    action.resolved_ips.clear();
    action
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

pub fn scan_params_for_targets(
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
                                            // SECURITY (R32-SRV-3): Boundary check after "localhost" — must be
                                            // followed by '/' or end-of-string. Without this, file://localhost.evil.com
                                            // incorrectly strips "localhost" and extracts ".evil.com/path".
                                            // SECURITY (R33-SRV-2): Only extract paths from file://localhost/...
                                            // or file:///... (empty host). A file://remote-host/path reference
                                            // would silently discard the remote hostname and extract the path,
                                            // allowing policy bypass if the path matches an allowed pattern.
                let path_original = if lower_after_scheme == "localhost"
                    || lower_after_scheme.starts_with("localhost/")
                {
                    &after_scheme["localhost".len()..]
                } else if after_scheme.starts_with('/') {
                    after_scheme
                } else {
                    // Non-localhost, non-empty host — this is a remote file reference.
                    // Extract the hostname as a domain target instead of a path.
                    if let Some(slash_idx) = after_scheme.find('/') {
                        let host_part = &after_scheme[..slash_idx];
                        if !host_part.is_empty() {
                            domains.push(host_part.to_lowercase());
                        }
                    }
                    ""
                };
                // Strip query strings and fragments
                let file_path = strip_query_and_fragment(path_original);
                if !file_path.is_empty() {
                    // SECURITY (R29-SRV-2): Percent-decode file:// paths to prevent
                    // bypass via encoding (e.g., file:///etc/%70asswd → /etc/passwd).
                    let decoded =
                        percent_encoding::percent_decode_str(file_path).decode_utf8_lossy();
                    paths.push(decoded.into_owned());
                }
            } else if let Some(lower_scheme_end) = lower.find("://") {
                // SECURITY (R15-EVAL-15): Extract domains from all schemes
                // with authority (http, https, ftp, ssh, wss, ldap, etc.),
                // not just http/https. Otherwise ftp://evil.com/file bypasses
                // network rules that block evil.com.
                // SECURITY (R32-SRV-1): Use lower.find("://") instead of s.find("://")
                // for indexing into `lower`. Unicode case-folding can change byte length
                // (e.g., Turkish İ U+0130 → "i\u{0307}" changes from 2 to 3 bytes),
                // so byte offsets from `s` are invalid for `lower`.
                let scheme = &lower[..lower_scheme_end];
                // Only process if scheme looks valid (alphabetic, 1-10 chars)
                // SECURITY (R31-SRV-3): Skip data: URIs — they are inline content,
                // not network addresses. Extracting a "domain" from data: URIs
                // produces bogus entries (e.g., "text" from "data:text/plain,...").
                if !scheme.is_empty()
                    && scheme.len() <= 10
                    && scheme.chars().all(|c| c.is_ascii_alphabetic())
                    && scheme != "data"
                {
                    // SECURITY (R32-SRV-1): Use lower_scheme_end consistently.
                    // Since scheme is validated as all-ASCII, the byte offset is
                    // identical in both `s` and `lower`. Use `get()` for safety.
                    if let Some(authority) = s.get(lower_scheme_end + 3..) {
                        // SECURITY (R37-SRV-1): Normalize backslashes to forward slashes
                        // before splitting authority. Per the WHATWG URL Standard, `\` is
                        // treated as a path separator in special schemes (http, https, etc.).
                        // Without this, `http://evil.com\@allowed.com/path` would yield
                        // "evil.com\@allowed.com" as authority, and rfind('@') would then
                        // extract "allowed.com" — but the actual HTTP connection goes to
                        // evil.com.
                        let authority_normalized = authority.replace('\\', "/");
                        let host_raw = authority_normalized
                            .split('/')
                            .next()
                            .unwrap_or(&authority_normalized);
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
                    // SECURITY (R30-SRV-6): Percent-decode absolute paths for
                    // consistency with file:// URL handling (R29-SRV-2). Without
                    // this, /etc/%70asswd bypasses path policy checks.
                    let decoded = percent_encoding::percent_decode_str(clean).decode_utf8_lossy();
                    paths.push(decoded.into_owned());
                }
            } else if looks_like_relative_path(s) {
                // SECURITY (R11-PATH-3): Catch relative paths containing ..
                // or starting with ~/ that would bypass extraction. Prepend /
                // so they are visible to path policy checks.
                let clean = strip_query_and_fragment(s);
                if !clean.is_empty() {
                    // SECURITY (R30-SRV-6): Percent-decode relative paths too.
                    let decoded = percent_encoding::percent_decode_str(clean).decode_utf8_lossy();
                    paths.push(format!("/{}", decoded));
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
    // SECURITY (R34-SRV-6): Percent-decode before checking to catch ..%2F evasion.
    let decoded = percent_encoding::percent_decode_str(s).decode_utf8_lossy();
    let d = decoded.as_ref();
    // Also normalize backslashes for Windows-style traversals.
    let d_normalized = d.replace('\\', "/");
    let d = &d_normalized;
    d.starts_with("../")
        || d.starts_with("./")
        || d.starts_with("~/")
        || d.contains("/../")
        || d == ".."
        || d == "~"
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
                let principal = format!("bearer:{}", hex::encode(&hash[..16]));
                if client_value != "anonymous" {
                    // SECURITY (R34-SRV-7): Strip control characters from client value
                    // to prevent log injection via approval requested_by field.
                    let sanitized: String = client_value
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(256)
                        .collect();
                    return format!("{} (note: {})", principal, sanitized);
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
    tenant_id: Option<String>,
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
                    let principal = format!("bearer:{}", hex::encode(&hash[..16]));
                    // Append client-supplied agent_id as a note (not authoritative)
                    // SECURITY (R33-SRV-3): Strip control characters from client_id
                    // before embedding in agent_id string. Control chars could break
                    // log parsing or inject ANSI escape sequences.
                    Some(match client_agent_id {
                        Some(ref client_id) => {
                            let sanitized: String = client_id
                                .chars()
                                .filter(|c| !c.is_control())
                                .take(256)
                                .collect();
                            format!("{} (note: {})", principal, sanitized)
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

        // SECURITY (R21-SRV-3): Strip agent_identity — the stateless server
        // cannot validate JWTs (no JWKS configuration). Passing through an
        // unvalidated client-supplied agent_identity would let attackers forge
        // identity claims to match agent-identity-based policy conditions.
        // Only the HTTP proxy should populate this after JWT verification.
        EvaluationContext {
            // Override timestamp with server time — never trust client clocks
            timestamp: None,
            agent_id,
            agent_identity: None,
            // Strip session-state fields: the stateless server API has no session
            // tracking, so these must not be client-controlled
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            // Tenant ID is set by the tenant middleware, not client-controlled
            tenant_id,
        }
    })
}

#[tracing::instrument(
    name = "sentinel.policy_evaluation",
    skip(state, headers, req),
    fields(
        tool = %req.action.tool,
        function = %req.action.function,
        tenant_id = %tenant_ctx.tenant_id,
    )
)]
async fn evaluate(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
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
    // SECURITY: Tenant ID is extracted by middleware, never client-supplied.
    let context = sanitize_context(req.context, &headers, Some(tenant_ctx.tenant_id.clone()));

    // SECURITY (R10-2): Always run auto-extraction from parameters,
    // ignoring client-supplied target_paths/target_domains. A malicious
    // client could supply crafted paths that bypass path policy checks,
    // so we clear them and re-extract from the actual parameters.
    // SECURITY (R22-SRV-1): Also clear resolved_ips — a client could supply
    // crafted IPs to bypass DNS rebinding / private-IP checks entirely.
    action.target_paths.clear();
    action.target_domains.clear();
    action.resolved_ips.clear();
    auto_extract_targets(&mut action);

    // SECURITY (R15-CFG-2): Single atomic load of engine + policies.
    // Previously two separate loads had a microsecond-wide race.
    let snap = state.policy_state.load();

    // Tool registry check: if enabled, unknown or untrusted tools require approval.
    // This runs BEFORE engine evaluation so that completely unknown tools are caught
    // even if no policy explicitly covers them (fail-closed).
    if let Some(ref registry) = state.tool_registry {
        let tool_name = &action.tool;
        let trust = registry.check_trust_level(tool_name).await;
        match trust {
            sentinel_mcp::tool_registry::TrustLevel::Unknown => {
                // Unknown tool: register it and require approval
                registry.register_unknown(tool_name).await;
                let reason = format!(
                    "Tool '{}' is not in the registry — requires approval before use",
                    tool_name
                );
                let verdict = Verdict::RequireApproval {
                    reason: reason.clone(),
                };
                // SECURITY (R30-SRV-3): Defer metrics recording until after
                // approval creation — if creation fails, the final verdict is
                // Deny, not RequireApproval. Recording both double-counts.

                // Create pending approval if store available
                let requester = derive_resolver_identity(&headers, "anonymous");
                let requested_by = if requester != "anonymous" {
                    Some(requester)
                } else {
                    None
                };
                let approval_id = match state
                    .create_approval(action.clone(), reason, requested_by)
                    .await
                {
                    Ok(id) => Some(id),
                    Err(e) => {
                        tracing::error!(
                            "Failed to create approval for unknown tool (fail-closed → Deny): {:?}",
                            e
                        );
                        let deny = Verdict::Deny {
                            reason: "Unknown tool requires approval but could not be created"
                                .to_string(),
                        };
                        state.metrics.record_evaluation(&deny);
                        if let Err(e) = state
                            .audit
                            .log_entry(
                                &action,
                                &deny,
                                json!({"source": "http", "registry": "unknown_tool", "tenant_id": &tenant_ctx.tenant_id}),
                            )
                            .await
                        {
                            tracing::error!("AUDIT FAILURE: {}", e);
                        } else {
                            crate::metrics::increment_audit_entries();
                        }
                        return Ok(Json(EvaluateResponse {
                            verdict: deny,
                            action: redact_response_action(action),
                            approval_id: None,
                        }));
                    }
                };

                // Record RequireApproval metrics only on success path
                state.metrics.record_evaluation(&verdict);
                crate::metrics::record_evaluation_verdict("require_approval");
                crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());

                if let Err(e) = state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({"source": "http", "registry": "unknown_tool", "approval_id": approval_id, "tenant_id": &tenant_ctx.tenant_id}),
                    )
                    .await
                {
                    tracing::error!("AUDIT FAILURE: {}", e);
                } else {
                    crate::metrics::increment_audit_entries();
                }
                return Ok(Json(EvaluateResponse {
                    verdict,
                    action: redact_response_action(action),
                    approval_id,
                }));
            }
            sentinel_mcp::tool_registry::TrustLevel::Untrusted { score } => {
                let reason = format!(
                    "Tool '{}' trust score ({:.2}) is below threshold — requires approval",
                    tool_name, score
                );
                let verdict = Verdict::RequireApproval {
                    reason: reason.clone(),
                };
                // SECURITY (R30-SRV-3): Defer metrics until after approval creation

                let requester = derive_resolver_identity(&headers, "anonymous");
                let requested_by = if requester != "anonymous" {
                    Some(requester)
                } else {
                    None
                };
                let approval_id = match state
                    .create_approval(action.clone(), reason, requested_by)
                    .await
                {
                    Ok(id) => Some(id),
                    Err(e) => {
                        tracing::error!(
                            "Failed to create approval for untrusted tool (fail-closed → Deny): {:?}",
                            e
                        );
                        let deny = Verdict::Deny {
                            reason: "Untrusted tool requires approval but could not be created"
                                .to_string(),
                        };
                        state.metrics.record_evaluation(&deny);
                        if let Err(e) = state
                            .audit
                            .log_entry(
                                &action,
                                &deny,
                                json!({"source": "http", "registry": "untrusted_tool", "tenant_id": &tenant_ctx.tenant_id}),
                            )
                            .await
                        {
                            tracing::error!("AUDIT FAILURE: {}", e);
                        } else {
                            crate::metrics::increment_audit_entries();
                        }
                        return Ok(Json(EvaluateResponse {
                            verdict: deny,
                            action: redact_response_action(action),
                            approval_id: None,
                        }));
                    }
                };

                // Record RequireApproval metrics only on success path
                state.metrics.record_evaluation(&verdict);
                crate::metrics::record_evaluation_verdict("require_approval");
                crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());

                if let Err(e) = state
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({"source": "http", "registry": "untrusted_tool", "approval_id": approval_id, "tenant_id": &tenant_ctx.tenant_id}),
                    )
                    .await
                {
                    tracing::error!("AUDIT FAILURE: {}", e);
                } else {
                    crate::metrics::increment_audit_entries();
                }
                return Ok(Json(EvaluateResponse {
                    verdict,
                    action: redact_response_action(action),
                    approval_id,
                }));
            }
            sentinel_mcp::tool_registry::TrustLevel::Trusted => {
                // Trusted — proceed to engine evaluation
            }
        }
    }

    let verdict = snap
        .engine
        .evaluate_action_with_context(&action, &snap.policies, context.as_ref())
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
            .create_approval(action.clone(), reason.clone(), requested_by)
            .await
        {
            Ok(id) => (verdict, Some(id)),
            Err(e) => {
                tracing::error!("Failed to create approval (fail-closed → Deny): {:?}", e);
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

    // Record tool call in registry on Allow (for trust score tracking)
    if matches!(verdict, Verdict::Allow) {
        if let Some(ref registry) = state.tool_registry {
            registry.record_call(&action.tool).await;
        }
    }

    // Log to audit — fire-and-forget on error (don't fail the request).
    // SECURITY (R16-AUDIT-3): Log at error level (not warn) because a silent
    // audit failure means security decisions proceed without an audit trail.
    // An attacker who fills the disk can suppress audit logging entirely.
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &verdict,
            json!({"source": "http", "approval_id": approval_id, "tenant_id": &tenant_ctx.tenant_id}),
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
        action: redact_response_action(action),
        approval_id,
    }))
}

#[tracing::instrument(name = "sentinel.list_policies", skip(state))]
async fn list_policies(State(state): State<AppState>) -> Json<Vec<Policy>> {
    let snap = state.policy_state.load();
    Json(snap.policies.clone())
}

#[tracing::instrument(
    name = "sentinel.add_policy",
    skip(state),
    fields(policy_id = %policy.id)
)]
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
    let existing = state.policy_state.load();
    if existing.policies.iter().any(|p| p.id == policy.id) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": format!("Policy with id '{}' already exists", policy.id)})),
        );
    }

    // 5. Enforce max policy count (prevent resource exhaustion)
    if existing.policies.len() >= 10_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Maximum policy count (10000) reached"})),
        );
    }

    // Build candidate policy list
    let id = policy.id.clone();
    let mut candidate = existing.policies.clone();
    candidate.push(policy.clone());
    PolicyEngine::sort_policies(&mut candidate);

    // Compile-first: verify the new policy set compiles before storing
    match PolicyEngine::with_policies(false, &candidate) {
        Ok(compiled_engine) => {
            // SECURITY (R15-CFG-2): Single atomic swap of engine + policies.
            state.policy_state.store(Arc::new(crate::PolicySnapshot {
                engine: compiled_engine,
                policies: candidate,
            }));
            tracing::info!("Added policy: {}", id);
        }
        Err(errors) => {
            // SECURITY (R26-SRV-5): Log detailed errors server-side but return
            // generic message to the client. Detailed compiler errors can leak
            // regex patterns and rule structures from existing policies.
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            tracing::warn!("add_policy rejected: compilation failed: {:?}", msgs);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Policy validation failed — policy NOT added",
                    "policy_id": id,
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
    } else {
        crate::metrics::increment_audit_entries();
    }

    (StatusCode::CREATED, Json(json!({"added": id})))
}

#[tracing::instrument(
    name = "sentinel.remove_policy",
    skip(state),
    fields(policy_id = %id)
)]
async fn remove_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // SECURITY (R23-SRV-4): Validate the path param (same rules as add_policy).
    if id.is_empty() || id.len() > 256 || id.chars().any(|c| c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid policy id"})),
        );
    }

    // SECURITY (R15-RACE-*): Serialize with other policy mutations.
    let _guard = state.policy_write_lock.lock().await;

    let existing = state.policy_state.load();
    let candidate: Vec<Policy> = existing
        .policies
        .iter()
        .filter(|p| p.id != id)
        .cloned()
        .collect();
    let removed = existing.policies.len().saturating_sub(candidate.len());

    if removed == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("No policy with id '{}'", id)})),
        );
    }

    // Compile-first: verify the remaining set compiles before storing
    match PolicyEngine::with_policies(false, &candidate) {
        Ok(compiled_engine) => {
            // SECURITY (R15-CFG-2): Single atomic swap of engine + policies.
            state.policy_state.store(Arc::new(crate::PolicySnapshot {
                engine: compiled_engine,
                policies: candidate,
            }));
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
    } else {
        crate::metrics::increment_audit_entries();
    }

    (StatusCode::OK, Json(json!({"removed": removed, "id": id})))
}

#[tracing::instrument(name = "sentinel.reload_policies", skip(state))]
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

#[tracing::instrument(name = "sentinel.audit_entries", skip(state, params))]
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
/// SECURITY (R38-SRV-1/R38-SRV-2): This endpoint is behind auth and rate
/// limiting because it exposes `sentinel_policies_loaded` and pending approval
/// counts, which are security-sensitive (see R26-SRV-6). Prometheus scrapers
/// must provide a valid API key via Bearer token.
async fn prometheus_metrics(State(state): State<AppState>) -> Response {
    match &state.prometheus_handle {
        Some(handle) => {
            // Update dynamic gauges before rendering
            let policy_count = state.policy_state.load().policies.len();
            crate::metrics::set_policies_loaded(policy_count as f64);
            crate::metrics::set_uptime_seconds(state.metrics.start_time.elapsed().as_secs_f64());
            let pending_count = state.pending_approval_count().await.unwrap_or(0);
            crate::metrics::set_active_sessions(pending_count as f64);

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
        "policies_loaded": state.policy_state.load().policies.len(),
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
    let pending = match state.list_pending_approvals().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to list pending approvals: {:?}", e);
            return Json(json!({"count": 0, "approvals": [], "error": "Backend unavailable"}));
        }
    };
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

    let approval = state.get_approval(&id).await.map_err(|e| {
        tracing::debug!("Approval lookup failed for '{}': {:?}", id, e);
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
        .approve_approval(&id, &resolved_by)
        .await
        .map_err(|e| {
            let (status, msg) = match &e {
                crate::ApprovalOpError::NotFound(_) => {
                    (StatusCode::NOT_FOUND, "Approval not found")
                }
                crate::ApprovalOpError::AlreadyResolved(_) => {
                    (StatusCode::CONFLICT, "Approval already resolved")
                }
                crate::ApprovalOpError::Expired(_) => (StatusCode::GONE, "Approval expired"),
                crate::ApprovalOpError::Validation(ref msg) => {
                    // SECURITY (R9-2): Self-approval attempts return 403 Forbidden
                    tracing::warn!("Approval validation failed for '{}': {}", id, msg);
                    (StatusCode::FORBIDDEN, "Self-approval denied")
                }
                _ => {
                    tracing::error!("Approval approve error for '{}': {:?}", id, e);
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
        } else {
            crate::metrics::increment_audit_entries();
        }
    }

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R29-SRV-1): Redact parameters before returning (same as get_approval)
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = sentinel_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
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

    let approval = state.deny_approval(&id, &resolved_by).await.map_err(|e| {
        let (status, msg) = match &e {
            crate::ApprovalOpError::NotFound(_) => (StatusCode::NOT_FOUND, "Approval not found"),
            crate::ApprovalOpError::AlreadyResolved(_) => {
                (StatusCode::CONFLICT, "Approval already resolved")
            }
            crate::ApprovalOpError::Expired(_) => (StatusCode::GONE, "Approval expired"),
            _ => {
                tracing::error!("Approval deny error for '{}': {:?}", id, e);
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
        } else {
            crate::metrics::increment_audit_entries();
        }
    }

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R29-SRV-1): Redact parameters before returning (same as get_approval)
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = sentinel_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
    Ok(Json(value))
}

// === Tool Registry Endpoints (P2.1) ===

/// Maximum length for tool names in registry operations.
const MAX_TOOL_NAME_LEN: usize = 256;

/// Validate a tool name from a URL path parameter.
fn validate_tool_name(name: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if name.is_empty() || name.len() > MAX_TOOL_NAME_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Tool name must be 1-{} characters", MAX_TOOL_NAME_LEN),
            }),
        ));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Tool name contains invalid characters".to_string(),
            }),
        ));
    }
    Ok(())
}

/// List all tools in the registry with their trust scores.
///
/// GET /api/registry/tools
///
/// Returns a JSON object with:
/// - `count`: number of registered tools
/// - `trust_threshold`: the configured trust threshold
/// - `tools`: array of tool entries with trust scores
async fn list_registry_tools(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let registry = state.tool_registry.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool registry is not enabled".to_string(),
            }),
        )
    })?;

    let tools = registry.list().await;
    let threshold = registry.trust_threshold();

    Ok(Json(json!({
        "count": tools.len(),
        "trust_threshold": threshold,
        "tools": tools,
    })))
}

/// Approve a tool in the registry (set admin_approved = true).
///
/// POST /api/registry/tools/{name}/approve
///
/// Returns the updated tool entry on success.
async fn approve_registry_tool(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_tool_name(&name)?;

    // SECURITY (R34-SRV-3): Record the authenticated principal in audit trail.
    let approved_by = derive_resolver_identity(&headers, "anonymous");

    let registry = state.tool_registry.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool registry is not enabled".to_string(),
            }),
        )
    })?;

    let entry = registry.approve(&name).await.map_err(|e| match e {
        sentinel_mcp::tool_registry::RegistryError::NotFound(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Tool '{}' not found in registry", name),
            }),
        ),
        _ => {
            tracing::error!("Registry approve error for '{}': {}", name, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to approve tool".to_string(),
                }),
            )
        }
    })?;

    // Persist the change
    if let Err(e) = registry.persist().await {
        tracing::warn!(
            "Failed to persist registry after approving '{}': {}",
            name,
            e
        );
    }

    // Audit trail
    let action = Action::new(
        "sentinel",
        "registry_tool_approved",
        json!({
            "tool_id": &name,
            "trust_score": entry.trust_score,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "registry_tool_approved", "approved_by": &approved_by}),
        )
        .await
    {
        tracing::warn!("Failed to audit registry approval for {}: {}", name, e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    let value = serde_json::to_value(&entry).map_err(|e| {
        tracing::error!("Registry entry serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// Revoke admin approval for a tool in the registry (set admin_approved = false).
///
/// POST /api/registry/tools/{name}/revoke
///
/// Returns the updated tool entry on success.
async fn revoke_registry_tool(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_tool_name(&name)?;

    // SECURITY (R34-SRV-3): Record the authenticated principal in audit trail.
    let revoked_by = derive_resolver_identity(&headers, "anonymous");

    let registry = state.tool_registry.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool registry is not enabled".to_string(),
            }),
        )
    })?;

    let entry = registry.revoke(&name).await.map_err(|e| match e {
        sentinel_mcp::tool_registry::RegistryError::NotFound(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Tool '{}' not found in registry", name),
            }),
        ),
        _ => {
            tracing::error!("Registry revoke error for '{}': {}", name, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to revoke tool approval".to_string(),
                }),
            )
        }
    })?;

    // Persist the change
    if let Err(e) = registry.persist().await {
        tracing::warn!(
            "Failed to persist registry after revoking '{}': {}",
            name,
            e
        );
    }

    // Audit trail
    let action = Action::new(
        "sentinel",
        "registry_tool_revoked",
        json!({
            "tool_id": &name,
            "trust_score": entry.trust_score,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "registry_tool_revoked", "revoked_by": &revoked_by}),
        )
        .await
    {
        tracing::warn!("Failed to audit registry revocation for {}: {}", name, e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    let value = serde_json::to_value(&entry).map_err(|e| {
        tracing::error!("Registry entry serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Management Endpoints (Phase 3)
// ────────────────────────────────────────────────────────────────────────────

/// Response type for tenant operations.
#[derive(Serialize)]
struct TenantResponse {
    tenant: crate::tenant::Tenant,
}

/// Request type for creating/updating a tenant.
#[derive(Deserialize)]
struct TenantRequest {
    id: String,
    name: String,
    #[serde(default = "default_true_for_tenant")]
    enabled: bool,
    #[serde(default)]
    quotas: Option<crate::tenant::TenantQuotas>,
    #[serde(default)]
    metadata: std::collections::HashMap<String, String>,
}

fn default_true_for_tenant() -> bool {
    true
}

/// List all tenants.
///
/// Returns an empty list if no tenant store is configured.
async fn list_tenants(
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::tenant::Tenant>>, (StatusCode, Json<ErrorResponse>)> {
    let tenants = match &state.tenant_store {
        Some(store) => store.list_tenants(),
        None => vec![],
    };
    Ok(Json(tenants))
}

/// Get a specific tenant by ID.
async fn get_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TenantResponse>, (StatusCode, Json<ErrorResponse>)> {
    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured".to_string(),
            }),
        )
    })?;

    let tenant = store.get_tenant(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Tenant not found: {}", id),
            }),
        )
    })?;

    Ok(Json(TenantResponse { tenant }))
}

/// Create a new tenant.
async fn create_tenant(
    State(state): State<AppState>,
    Json(req): Json<TenantRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Validate tenant ID
    if let Err(e) = crate::tenant::validate_tenant_id(&req.id) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e.to_string() }),
        ));
    }

    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured".to_string(),
            }),
        )
    })?;

    let now = chrono::Utc::now().to_rfc3339();
    let tenant = crate::tenant::Tenant {
        id: req.id,
        name: req.name,
        enabled: req.enabled,
        quotas: req.quotas.unwrap_or_default(),
        metadata: req.metadata,
        created_at: Some(now.clone()),
        updated_at: Some(now),
    };

    store.create_tenant(tenant.clone()).map_err(|e| match e {
        crate::tenant::TenantError::InvalidTenantId(msg) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse { error: msg }),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        ),
    })?;

    Ok((StatusCode::CREATED, Json(TenantResponse { tenant })))
}

/// Update an existing tenant.
async fn update_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TenantRequest>,
) -> Result<Json<TenantResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate that path ID matches body ID
    if id != req.id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Tenant ID in path must match ID in body".to_string(),
            }),
        ));
    }

    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured".to_string(),
            }),
        )
    })?;

    // Get existing tenant to preserve created_at
    let existing = store.get_tenant(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Tenant not found: {}", id),
            }),
        )
    })?;

    let now = chrono::Utc::now().to_rfc3339();
    let tenant = crate::tenant::Tenant {
        id: req.id,
        name: req.name,
        enabled: req.enabled,
        quotas: req.quotas.unwrap_or_default(),
        metadata: req.metadata,
        created_at: existing.created_at,
        updated_at: Some(now),
    };

    store.update_tenant(tenant.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(TenantResponse { tenant }))
}

/// Delete a tenant.
async fn delete_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Don't allow deleting the default tenant
    if id == crate::tenant::DEFAULT_TENANT_ID {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot delete the default tenant".to_string(),
            }),
        ));
    }

    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured".to_string(),
            }),
        )
    })?;

    store.delete_tenant(&id).map_err(|e| match e {
        crate::tenant::TenantError::TenantNotFound(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Tenant not found: {}", id),
            }),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        ),
    })?;

    Ok(StatusCode::NO_CONTENT)
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 3.1: Security Manager Admin API Handlers
// ═══════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// Circuit Breaker Handlers (OWASP ASI08)
// ─────────────────────────────────────────────────────────────────────────────

/// List all circuit breaker states.
///
/// GET /api/circuit-breaker
async fn list_circuit_breakers(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let cb = state.circuit_breaker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Circuit breaker is not enabled".to_string(),
            }),
        )
    })?;

    let tools = cb.tracked_tools();
    let mut entries = Vec::new();

    for tool in tools {
        let state = cb.get_state(&tool);
        let stats = cb.get_stats(&tool);
        entries.push(json!({
            "tool": tool,
            "state": format!("{:?}", state),
            "stats": stats,
        }));
    }

    Ok(Json(json!({
        "count": entries.len(),
        "circuits": entries,
    })))
}

/// Get circuit breaker statistics summary.
///
/// GET /api/circuit-breaker/stats
async fn circuit_breaker_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let cb = state.circuit_breaker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Circuit breaker is not enabled".to_string(),
            }),
        )
    })?;

    let summary = cb.summary();
    Ok(Json(json!({
        "total": summary.total,
        "open": summary.open,
        "half_open": summary.half_open,
        "closed": summary.closed,
    })))
}

/// Get circuit breaker state for a specific tool.
///
/// GET /api/circuit-breaker/{tool}
async fn get_circuit_state(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let cb = state.circuit_breaker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Circuit breaker is not enabled".to_string(),
            }),
        )
    })?;

    let circuit_state = cb.get_state(&tool);
    let stats = cb.get_stats(&tool);
    let recovering = cb.is_recovering(&tool);

    Ok(Json(json!({
        "tool": tool,
        "state": format!("{:?}", circuit_state),
        "stats": stats,
        "recovering": recovering,
    })))
}

/// Reset circuit breaker for a specific tool.
///
/// POST /api/circuit-breaker/{tool}/reset
async fn reset_circuit(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let cb = state.circuit_breaker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Circuit breaker is not enabled".to_string(),
            }),
        )
    })?;

    cb.reset(&tool);

    Ok(Json(json!({
        "tool": tool,
        "state": "Closed",
        "message": "Circuit breaker reset successfully",
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// Shadow Agent Detection Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// List all known agents.
///
/// GET /api/shadow-agents
async fn list_shadow_agents(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let detector = state.shadow_agent.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow agent detection is not enabled".to_string(),
            }),
        )
    })?;

    let agent_ids = detector.known_ids();
    let count = detector.known_count();

    Ok(Json(json!({
        "count": count,
        "agent_ids": agent_ids,
    })))
}

/// Register a known agent.
///
/// POST /api/shadow-agents
#[derive(Deserialize)]
struct RegisterAgentRequest {
    agent_id: String,
    fingerprint: sentinel_types::AgentFingerprint,
}

async fn register_shadow_agent(
    State(state): State<AppState>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let detector = state.shadow_agent.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow agent detection is not enabled".to_string(),
            }),
        )
    })?;

    detector.register_agent(req.fingerprint.clone(), &req.agent_id);

    Ok(Json(json!({
        "agent_id": req.agent_id,
        "message": "Agent registered successfully",
    })))
}

/// Remove a known agent.
///
/// DELETE /api/shadow-agents/{id}
///
/// Note: This endpoint removes the agent from tracking. The agent can be
/// re-registered by calling POST /api/shadow-agents again.
async fn remove_shadow_agent(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Note: ShadowAgentDetector doesn't have a remove method.
    // Agents are managed via trust level updates instead.
    // This endpoint exists for API completeness but returns a message.
    Ok(Json(json!({
        "agent_id": id,
        "message": "Agent removal is handled via trust level (set to 0 to distrust)",
    })))
}

/// Update agent trust level.
///
/// PUT /api/shadow-agents/{id}/trust
#[derive(Deserialize)]
struct UpdateTrustRequest {
    trust_level: u8,
}

async fn update_agent_trust(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateTrustRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _detector = state.shadow_agent.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow agent detection is not enabled".to_string(),
            }),
        )
    })?;

    // Note: Trust updates require the fingerprint, not just the ID.
    // This endpoint exists for API completeness. In practice, trust is
    // updated automatically based on agent behavior.
    let trust = sentinel_types::TrustLevel::from_u8(req.trust_level);

    Ok(Json(json!({
        "agent_id": id,
        "requested_trust_level": format!("{:?}", trust),
        "message": "Trust level updates require fingerprint; agent trust is managed automatically",
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Lineage Handlers (OWASP ASI05)
// ─────────────────────────────────────────────────────────────────────────────

/// List all tracked tool schemas.
///
/// GET /api/schema-lineage
async fn list_schema_lineage(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.schema_lineage.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Schema lineage tracking is not enabled".to_string(),
            }),
        )
    })?;

    let count = tracker.tracked_count();

    Ok(Json(json!({
        "tracked_count": count,
    })))
}

/// Get schema lineage for a specific tool.
///
/// GET /api/schema-lineage/{tool}
async fn get_schema_lineage(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.schema_lineage.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Schema lineage tracking is not enabled".to_string(),
            }),
        )
    })?;

    let lineage = tracker.get_lineage(&tool).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("No lineage found for tool '{}'", tool),
            }),
        )
    })?;

    let trust_score = tracker.get_trust_score(&tool);

    Ok(Json(json!({
        "tool": tool,
        "schema_hash": lineage.schema_hash,
        "first_seen": lineage.first_seen,
        "last_seen": lineage.last_seen,
        "version_count": lineage.version_history.len(),
        "trust_score": trust_score,
    })))
}

/// Reset trust score for a tool's schema.
///
/// PUT /api/schema-lineage/{tool}/trust
#[derive(Deserialize)]
struct ResetTrustRequest {
    trust_score: f32,
}

async fn reset_schema_trust(
    State(state): State<AppState>,
    Path(tool): Path<String>,
    Json(req): Json<ResetTrustRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.schema_lineage.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Schema lineage tracking is not enabled".to_string(),
            }),
        )
    })?;

    tracker.reset_trust(&tool, req.trust_score);

    Ok(Json(json!({
        "tool": tool,
        "trust_score": req.trust_score,
        "message": "Trust score reset",
    })))
}

/// Remove schema lineage for a tool.
///
/// DELETE /api/schema-lineage/{tool}
async fn remove_schema_lineage(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.schema_lineage.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Schema lineage tracking is not enabled".to_string(),
            }),
        )
    })?;

    tracker.remove(&tool);

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────────────────────
// Task State Handlers (MCP 2025-11-25 Async Tasks)
// ─────────────────────────────────────────────────────────────────────────────

/// List task summary.
///
/// GET /api/tasks
///
/// Returns summary of tracked tasks. Use /api/tasks/stats for detailed statistics.
async fn list_tasks(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let manager = state.task_state.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task state management is not enabled".to_string(),
            }),
        )
    })?;

    let active_count = manager.active_count().await;

    Ok(Json(json!({
        "active_count": active_count,
        "message": "Use /api/tasks/stats for detailed statistics or /api/tasks/{id} for specific task",
    })))
}

/// Get task statistics.
///
/// GET /api/tasks/stats
async fn task_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let manager = state.task_state.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task state management is not enabled".to_string(),
            }),
        )
    })?;

    let stats = manager.stats().await;

    Ok(Json(json!({
        "total": stats.total,
        "pending": stats.pending,
        "running": stats.running,
        "completed": stats.completed,
        "failed": stats.failed,
        "cancelled": stats.cancelled,
        "expired": stats.expired,
        "active": stats.active(),
    })))
}

/// Get a specific task.
///
/// GET /api/tasks/{id}
async fn get_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let manager = state.task_state.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task state management is not enabled".to_string(),
            }),
        )
    })?;

    let task = manager.get_task(&id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Task '{}' not found", id),
            }),
        )
    })?;

    Ok(Json(serde_json::to_value(task).unwrap_or(json!({}))))
}

/// Cancel a task.
///
/// POST /api/tasks/{id}/cancel
async fn cancel_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let manager = state.task_state.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task state management is not enabled".to_string(),
            }),
        )
    })?;

    manager
        .update_status(&id, sentinel_types::TaskStatus::Cancelled)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    Ok(Json(json!({
        "task_id": id,
        "status": "cancelled",
        "message": "Task cancelled successfully",
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth Level Handlers (Step-Up Authentication)
// ─────────────────────────────────────────────────────────────────────────────

/// Get auth level for a session.
///
/// GET /api/auth-levels/{session}
async fn get_auth_level(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.auth_level.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Auth level tracking is not enabled".to_string(),
            }),
        )
    })?;

    let level = tracker.get_level(&session).await;
    let info = tracker.get_session_info(&session).await;

    Ok(Json(json!({
        "session": session,
        "level": format!("{:?}", level),
        "info": info.map(|i| json!({
            "level": format!("{:?}", i.level),
            "age_secs": i.age.as_secs(),
            "expires_in_secs": i.expires_in.map(|d| d.as_secs()),
        })),
    })))
}

/// Upgrade auth level for a session.
///
/// POST /api/auth-levels/{session}/upgrade
#[derive(Deserialize)]
struct UpgradeAuthRequest {
    level: String,
    #[serde(default)]
    expires_secs: Option<u64>,
}

async fn upgrade_auth_level(
    State(state): State<AppState>,
    Path(session): Path<String>,
    Json(req): Json<UpgradeAuthRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.auth_level.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Auth level tracking is not enabled".to_string(),
            }),
        )
    })?;

    let level = match req.level.to_lowercase().as_str() {
        "none" => sentinel_types::AuthLevel::None,
        "basic" => sentinel_types::AuthLevel::Basic,
        "oauth" => sentinel_types::AuthLevel::OAuth,
        "oauth_mfa" | "oauthmfa" => sentinel_types::AuthLevel::OAuthMfa,
        "hardware_key" | "hardwarekey" => sentinel_types::AuthLevel::HardwareKey,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid auth level: {}. Valid levels: none, basic, oauth, oauth_mfa, hardware_key",
                        req.level
                    ),
                }),
            ))
        }
    };

    let expires = req.expires_secs.map(std::time::Duration::from_secs);
    tracker.upgrade(&session, level, expires).await;

    Ok(Json(json!({
        "session": session,
        "level": format!("{:?}", level),
        "message": "Auth level upgraded",
    })))
}

/// Clear auth level for a session.
///
/// DELETE /api/auth-levels/{session}
async fn clear_auth_level(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.auth_level.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Auth level tracking is not enabled".to_string(),
            }),
        )
    })?;

    tracker.remove(&session).await;

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────────────────────
// Sampling Detection Handlers
// ─────────────────────────────────────────────────────────────────────────────

/// Get sampling detection statistics.
///
/// GET /api/sampling/stats
async fn sampling_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let detector = state.sampling_detector.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Sampling detection is not enabled".to_string(),
            }),
        )
    })?;

    let session_count = detector.session_count();

    Ok(Json(json!({
        "session_count": session_count,
        "message": "Use /api/sampling/{session}/reset to clear session stats",
    })))
}

/// Reset sampling stats for a session.
///
/// POST /api/sampling/{session}/reset
async fn reset_sampling_stats(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let detector = state.sampling_detector.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Sampling detection is not enabled".to_string(),
            }),
        )
    })?;

    detector.clear_session(&session);

    Ok(Json(json!({
        "session": session,
        "message": "Sampling stats cleared",
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// Deputy Validation Handlers (OWASP ASI02)
// ─────────────────────────────────────────────────────────────────────────────

/// List active delegation count.
///
/// GET /api/deputy/delegations
async fn list_delegations(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let deputy = state.deputy.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Deputy validation is not enabled".to_string(),
            }),
        )
    })?;

    let active_count = deputy.active_count();

    Ok(Json(json!({
        "active_count": active_count,
    })))
}

/// Register a delegation.
///
/// POST /api/deputy/delegations
#[derive(Deserialize)]
struct RegisterDelegationRequest {
    session_id: String,
    from_principal: String,
    to_principal: String,
    allowed_tools: Vec<String>,
    #[serde(default)]
    expires_secs: Option<u64>,
}

async fn register_delegation(
    State(state): State<AppState>,
    Json(req): Json<RegisterDelegationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let deputy = state.deputy.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Deputy validation is not enabled".to_string(),
            }),
        )
    })?;

    // Note: expires_secs is captured but not currently used by DeputyValidator.
    // This allows future API compatibility if expiration is added.
    let _expires = req.expires_secs.map(std::time::Duration::from_secs);

    deputy
        .register_delegation(
            &req.session_id,
            &req.from_principal,
            &req.to_principal,
            &req.allowed_tools,
        )
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    Ok(Json(json!({
        "session_id": req.session_id,
        "from": req.from_principal,
        "to": req.to_principal,
        "allowed_tools": req.allowed_tools,
        "message": "Delegation registered",
    })))
}

/// Remove a delegation.
///
/// DELETE /api/deputy/delegations/{session}
async fn remove_delegation(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let deputy = state.deputy.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Deputy validation is not enabled".to_string(),
            }),
        )
    })?;

    deputy.remove_context(&session);

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution Graph Export Handlers (Phase 6)
// ─────────────────────────────────────────────────────────────────────────────

/// Query parameters for graph listing.
#[derive(Deserialize)]
struct GraphListQuery {
    /// Filter by tool name.
    tool: Option<String>,
    /// Maximum number of results.
    limit: Option<usize>,
    /// Offset for pagination.
    offset: Option<usize>,
}

/// List all execution graph sessions.
///
/// GET /api/graphs
async fn list_graphs(
    State(state): State<AppState>,
    Query(params): Query<GraphListQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let store = state.exec_graph_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Execution graph tracking is not enabled".to_string(),
            }),
        )
    })?;

    let sessions = store.list_sessions().await;
    let total = sessions.len();
    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    // If filtering by tool, we need to check each graph
    let filtered: Vec<_> = if let Some(ref tool_filter) = params.tool {
        let mut result = Vec::new();
        for session_id in &sessions {
            if let Some(graph) = store.get(session_id).await {
                if graph.metadata.unique_tools.contains(tool_filter) {
                    result.push(json!({
                        "session_id": session_id,
                        "node_count": graph.nodes.len(),
                        "started_at": graph.metadata.started_at,
                        "ended_at": graph.metadata.ended_at,
                    }));
                }
            }
        }
        result.into_iter().skip(offset).take(limit).collect()
    } else {
        let mut result = Vec::new();
        for session_id in sessions.iter().skip(offset).take(limit) {
            if let Some(graph) = store.get(session_id).await {
                result.push(json!({
                    "session_id": session_id,
                    "node_count": graph.nodes.len(),
                    "started_at": graph.metadata.started_at,
                    "ended_at": graph.metadata.ended_at,
                }));
            }
        }
        result
    };

    Ok(Json(json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "graphs": filtered,
    })))
}

/// Get an execution graph in JSON format.
///
/// GET /api/graphs/{session}
async fn get_graph(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let store = state.exec_graph_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Execution graph tracking is not enabled".to_string(),
            }),
        )
    })?;

    let graph = store.get(&session).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Graph not found for session: {}", session),
            }),
        )
    })?;

    let json_value = serde_json::to_value(&graph).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize graph: {}", e),
            }),
        )
    })?;

    Ok(Json(json_value))
}

/// Get an execution graph in DOT (Graphviz) format.
///
/// GET /api/graphs/{session}/dot
async fn get_graph_dot(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let store = state.exec_graph_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Execution graph tracking is not enabled".to_string(),
            }),
        )
    })?;

    let graph = store.get(&session).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Graph not found for session: {}", session),
            }),
        )
    })?;

    let dot = graph.to_dot();

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/vnd.graphviz")],
        dot,
    )
        .into_response())
}

/// Get execution graph statistics.
///
/// GET /api/graphs/{session}/stats
async fn get_graph_stats(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let store = state.exec_graph_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Execution graph tracking is not enabled".to_string(),
            }),
        )
    })?;

    let graph = store.get(&session).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Graph not found for session: {}", session),
            }),
        )
    })?;

    let stats = graph.statistics();

    Ok(Json(serde_json::to_value(&stats).unwrap_or_else(|_| json!({}))))
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
            crate::metrics::increment_rate_limit_rejections();
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
            crate::metrics::increment_rate_limit_rejections();
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
            crate::metrics::increment_rate_limit_rejections();
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

    // SECURITY (R33-SRV-1): Use get_all() to collect ALL X-Forwarded-For headers,
    // not just the first. An attacker behind a trusted proxy can send multiple XFF
    // headers; .get() only reads the first, allowing the attacker to inject a spoofed
    // IP in a second header that the proxy appended to the first.
    // Combine all headers into a single comma-separated string before parsing.
    let xff_values: Vec<&str> = request
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !xff_values.is_empty() {
        let combined = xff_values.join(",");
        // Walk from right to left, skipping trusted proxy IPs.
        for entry in combined.rsplit(',') {
            if let Ok(ip) = entry.trim().parse::<std::net::IpAddr>() {
                if !trusted_proxies.contains(&ip) {
                    return ip;
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
/// Rate limiting runs BEFORE `require_api_key` (outermost middleware),
/// so the Bearer token may not yet be validated when this is called.
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
    // Check for endpoint-specific limits first (takes priority)
    if let Some(limiter) = limits.get_endpoint_limiter(path) {
        return Some(limiter);
    }

    // SECURITY (R41-SRV-4): Match any method for /api/evaluate, not just POST.
    // The rate limit middleware runs before routing, so a PUT /api/evaluate
    // would be categorized as "admin" instead of "evaluate", bypassing
    // tighter evaluate limits when admin_rps > evaluate_rps.
    if path == "/api/evaluate" {
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
        assert!(sanitize_context(None, &headers, None).is_none());
    }

    #[test]
    fn test_sanitize_context_strips_call_counts_and_history() {
        let headers = HeaderMap::new();
        let mut call_counts = std::collections::HashMap::new();
        call_counts.insert("read_file".to_string(), 99);
        let spoofed = EvaluationContext {
            timestamp: Some("2026-01-01T00:00:00Z".to_string()),
            agent_id: Some("agent-a".to_string()),
            agent_identity: None,
            call_counts,
            previous_actions: vec!["login".to_string(), "auth".to_string()],
            call_chain: Vec::new(),
            tenant_id: None,
        };
        let sanitized = sanitize_context(Some(spoofed), &headers, None).unwrap();
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
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
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
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
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
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
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
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
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
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
        assert_eq!(sanitized.agent_id, Some(max_id));
    }

    #[test]
    fn test_sanitize_context_rejects_empty_agent_id() {
        let headers = HeaderMap::new();
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some("".to_string()),
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
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

    // --- R34-SRV-4: Token hash uses 16 bytes (128-bit) ---

    #[test]
    fn test_derive_resolver_identity_uses_128bit_hash() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer test-token-123".parse().unwrap(),
        );
        let identity = derive_resolver_identity(&headers, "anonymous");
        // Should be "bearer:" + 32 hex chars (16 bytes = 128 bits)
        assert!(identity.starts_with("bearer:"));
        let hex_part = &identity[7..];
        assert_eq!(
            hex_part.len(),
            32,
            "hash truncation should be 16 bytes (32 hex chars)"
        );
    }

    // --- R34-SRV-6: Percent-encoded relative path detection ---

    #[test]
    fn test_looks_like_relative_path_percent_encoded() {
        // Percent-encoded ../ should be detected
        assert!(looks_like_relative_path("..%2F..%2Fetc%2Fpasswd"));
        assert!(looks_like_relative_path("..%2fetc%2fpasswd"));
        assert!(looks_like_relative_path(".%2Fconfig.json"));
        assert!(looks_like_relative_path("~%2Fsecret.txt"));
        assert!(looks_like_relative_path("foo%2F..%2Fbar"));
    }

    #[test]
    fn test_looks_like_relative_path_backslash() {
        assert!(looks_like_relative_path("..\\etc\\passwd"));
        assert!(looks_like_relative_path(".\\config.json"));
        assert!(looks_like_relative_path("foo\\..\\bar"));
    }

    // --- R34-SRV-7: Control char sanitization in derive_resolver_identity ---

    #[test]
    fn test_derive_resolver_identity_strips_control_chars() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer mytoken".parse().unwrap());
        let identity = derive_resolver_identity(&headers, "user\x00\x0a\x0dname");
        assert!(!identity.contains('\x00'));
        assert!(!identity.contains('\x0a'));
        assert!(!identity.contains('\x0d'));
        assert!(identity.contains("(note: username)"));
    }

    // --- R34-SRV-8: Hash-based auth comparison ---

    #[test]
    fn test_auth_comparison_constant_time_hash() {
        // This is a unit test verifying the hash-comparison approach works.
        // We can't easily test timing, but verify correct accept/reject.
        use sha2::{Digest, Sha256};
        let key = "correct-api-key";
        let good_token = "correct-api-key";
        let bad_token = "wrong-api-key";

        let key_hash = Sha256::digest(key.as_bytes());
        let good_hash = Sha256::digest(good_token.as_bytes());
        let bad_hash = Sha256::digest(bad_token.as_bytes());

        use subtle::ConstantTimeEq;
        assert!(bool::from(key_hash.ct_eq(&good_hash)));
        assert!(!bool::from(key_hash.ct_eq(&bad_hash)));
    }

    // --- R37-SRV-1: Backslash as path separator in domain extraction ---

    #[test]
    fn test_scan_params_backslash_authority_bypass() {
        // SECURITY (R37-SRV-1): Backslash in URL authority must be treated as
        // path separator per WHATWG URL Standard. Without normalization,
        // http://evil.com\@allowed.com/path would extract "allowed.com"
        // instead of "evil.com".
        let mut paths = Vec::new();
        let mut domains = Vec::new();
        let value = serde_json::json!("http://evil.com\\@allowed.com/path");
        scan_params_for_targets_inner(&value, &mut paths, &mut domains, 0);
        assert!(
            domains.contains(&"evil.com".to_string()),
            "Should extract evil.com as the domain, got: {:?}",
            domains
        );
        assert!(
            !domains.contains(&"allowed.com".to_string()),
            "Should NOT extract allowed.com (it is after the backslash-path), got: {:?}",
            domains
        );
    }

    #[test]
    fn test_scan_params_backslash_no_at_sign() {
        // Backslash without @ — the backslash is a path separator, so only
        // the part before it is the authority host.
        let mut paths = Vec::new();
        let mut domains = Vec::new();
        let value = serde_json::json!("https://example.com\\malicious-path");
        scan_params_for_targets_inner(&value, &mut paths, &mut domains, 0);
        assert!(
            domains.contains(&"example.com".to_string()),
            "Should extract example.com, got: {:?}",
            domains
        );
    }

    // --- R41-SRV-4: Rate limit category bypass via method override ---

    #[test]
    fn test_categorize_rate_limit_put_evaluate_uses_evaluate_bucket() {
        // SECURITY (R41-SRV-4): A PUT /api/evaluate must use the evaluate
        // rate limit bucket, not fall through to admin. The rate limit
        // middleware runs before routing, so non-POST methods to /api/evaluate
        // would consume the wrong bucket if we only match POST.
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let limits = crate::RateLimits {
            evaluate: Some(RateLimiter::direct(Quota::per_second(
                NonZeroU32::new(10).unwrap(),
            ))),
            admin: Some(RateLimiter::direct(Quota::per_second(
                NonZeroU32::new(100).unwrap(),
            ))),
            readonly: None,
            per_ip: None,
            per_principal: None,
            endpoint_limits: std::collections::HashMap::new(),
        };

        // POST should use evaluate bucket
        let limiter_post = categorize_rate_limit(&limits, &Method::POST, "/api/evaluate");
        assert!(
            limiter_post.is_some(),
            "POST /api/evaluate must match evaluate bucket"
        );

        // PUT should also use evaluate bucket, not admin
        let limiter_put = categorize_rate_limit(&limits, &Method::PUT, "/api/evaluate");
        assert!(
            limiter_put.is_some(),
            "PUT /api/evaluate must match evaluate bucket"
        );

        // Verify both return the same limiter (evaluate, not admin)
        // by checking they are the same pointer
        let ptr_post = limiter_post.unwrap() as *const _;
        let ptr_put = limiter_put.unwrap() as *const _;
        assert_eq!(
            ptr_post, ptr_put,
            "PUT /api/evaluate must use the same (evaluate) rate limiter as POST"
        );

        // Also verify DELETE, PATCH, GET all use evaluate bucket for this path
        for method in &[Method::DELETE, Method::PATCH, Method::GET, Method::HEAD] {
            let limiter = categorize_rate_limit(&limits, method, "/api/evaluate");
            let ptr = limiter.unwrap() as *const _;
            assert_eq!(
                ptr, ptr_post,
                "{:?} /api/evaluate must use evaluate bucket, not admin or readonly",
                method
            );
        }
    }

    // --- CSRF Referer/Origin Validation Tests (Phase 5) ---

    #[test]
    fn test_validate_origin_localhost_allowed_by_default() {
        let origins: Vec<String> = vec![];

        assert!(validate_origin("http://localhost", &origins));
        assert!(validate_origin("http://localhost:3000", &origins));
        assert!(validate_origin("https://localhost", &origins));
        assert!(validate_origin("http://127.0.0.1", &origins));
        assert!(validate_origin("http://127.0.0.1:8080", &origins));
        assert!(validate_origin("http://[::1]", &origins));
        assert!(validate_origin("https://[::1]:443", &origins));
    }

    #[test]
    fn test_validate_origin_external_blocked_by_default() {
        let origins: Vec<String> = vec![];

        assert!(!validate_origin("http://example.com", &origins));
        assert!(!validate_origin("https://attacker.com", &origins));
        assert!(!validate_origin("http://192.168.1.1", &origins));
    }

    #[test]
    fn test_validate_origin_wildcard_allows_all() {
        let origins = vec!["*".to_string()];

        assert!(validate_origin("http://example.com", &origins));
        assert!(validate_origin("https://attacker.com", &origins));
        assert!(validate_origin("http://localhost", &origins));
    }

    #[test]
    fn test_validate_origin_configured_origins() {
        let origins = vec![
            "https://app.example.com".to_string(),
            "https://admin.example.com".to_string(),
        ];

        assert!(validate_origin("https://app.example.com", &origins));
        assert!(validate_origin("https://admin.example.com", &origins));
        // localhost is always allowed as fallback
        assert!(validate_origin("http://localhost", &origins));
        // Other origins blocked
        assert!(!validate_origin("https://attacker.com", &origins));
        assert!(!validate_origin("https://example.com", &origins));
    }

    #[test]
    fn test_validate_origin_case_insensitive() {
        let origins = vec!["https://APP.Example.COM".to_string()];

        assert!(validate_origin("https://app.example.com", &origins));
        assert!(validate_origin("https://APP.EXAMPLE.COM", &origins));
        assert!(validate_origin("https://App.Example.Com", &origins));
    }

    #[test]
    fn test_validate_origin_with_port() {
        let origins = vec!["https://app.example.com:8443".to_string()];

        assert!(validate_origin("https://app.example.com:8443", &origins));
        // Different port should not match exact origin
        assert!(!validate_origin("https://app.example.com:9000", &origins));
        // No port should not match origin with port
        assert!(!validate_origin("https://app.example.com", &origins));
    }

    // --- Per-Endpoint Rate Limiting Tests (Phase 5) ---

    #[test]
    fn test_endpoint_limit_takes_priority() {
        use std::num::NonZeroU32;

        let limits = crate::RateLimits::new_with_burst(Some(100), None, Some(50), None, Some(25), None)
            .with_endpoint_limit("/api/special", NonZeroU32::new(10).unwrap(), None);

        // Endpoint-specific limit should be returned
        let limiter = categorize_rate_limit(&limits, &Method::POST, "/api/special");
        assert!(limiter.is_some());

        // Different endpoint falls back to category limits
        let limiter = categorize_rate_limit(&limits, &Method::POST, "/api/evaluate");
        assert!(limiter.is_some());
    }

    #[test]
    fn test_endpoint_limit_prefix_matching() {
        use std::num::NonZeroU32;

        let limits = crate::RateLimits::new_with_burst(Some(100), None, Some(50), None, Some(25), None)
            .with_endpoint_limit("/api/audit", NonZeroU32::new(10).unwrap(), None);

        // Exact match
        assert!(limits.get_endpoint_limiter("/api/audit").is_some());
        // Prefix match
        assert!(limits.get_endpoint_limiter("/api/audit/entries").is_some());
        assert!(limits.get_endpoint_limiter("/api/audit/report").is_some());
        // Non-match
        assert!(limits.get_endpoint_limiter("/api/policies").is_none());
    }

    #[test]
    fn test_endpoint_limit_longest_match_wins() {
        use std::num::NonZeroU32;

        let limits = crate::RateLimits::new_with_burst(None, None, None, None, None, None)
            .with_endpoint_limit("/api", NonZeroU32::new(100).unwrap(), None)
            .with_endpoint_limit("/api/audit", NonZeroU32::new(50).unwrap(), None)
            .with_endpoint_limit("/api/audit/checkpoint", NonZeroU32::new(10).unwrap(), None);

        // Most specific match should win
        let l1 = limits.get_endpoint_limiter("/api/audit/checkpoint");
        let l2 = limits.get_endpoint_limiter("/api/audit/entries");
        let l3 = limits.get_endpoint_limiter("/api/policies");

        // All should have limiters (from different prefix matches)
        assert!(l1.is_some());
        assert!(l2.is_some());
        assert!(l3.is_some());

        // Pointers should be different (different limiters)
        assert!(!std::ptr::eq(l1.unwrap() as *const _, l2.unwrap() as *const _));
    }
}
