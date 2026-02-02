use axum::{
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use sentinel_config::PolicyConfig;
use sentinel_engine::PolicyEngine;
use sentinel_types::{Action, Policy, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::Ordering;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use governor::clock::Clock;

use subtle::ConstantTimeEq;

use crate::AppState;

pub fn build_router(state: AppState) -> Router {
    // Build CORS layer from configured origins.
    // Default (empty vec) = localhost only. "*" = any origin.
    let cors = build_cors_layer(&state.cors_origins);

    Router::new()
        .route("/health", get(health))
        .route("/api/evaluate", post(evaluate))
        .route("/api/policies", get(list_policies))
        .route("/api/policies", post(add_policy))
        .route("/api/policies/reload", post(reload_policies))
        .route("/api/policies/:id", delete(remove_policy))
        .route("/api/audit/entries", get(audit_entries))
        .route("/api/audit/report", get(audit_report))
        .route("/api/audit/verify", get(audit_verify))
        .route("/api/approvals/pending", get(list_pending_approvals))
        .route("/api/approvals/:id", get(get_approval))
        .route("/api/approvals/:id/approve", post(approve_approval))
        .route("/api/approvals/:id/deny", post(deny_approval))
        .route("/api/metrics", get(metrics))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit))
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
            "http://localhost".parse::<HeaderValue>().unwrap(),
            "http://127.0.0.1".parse::<HeaderValue>().unwrap(),
            "http://[::1]".parse::<HeaderValue>().unwrap(),
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
async fn security_headers(request: Request, next: Next) -> Response {
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

/// Middleware that requires API key authentication for mutating (non-GET) requests.
/// If no API key is configured in AppState, all requests are allowed.
async fn require_api_key(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // Skip auth for read-only methods
    if request.method() == Method::GET || request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    // Skip auth if no API key configured
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
        Some(ref h) if h.starts_with("Bearer ") => {
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
            Json(json!({"error": "Missing or invalid Authorization header. Expected: Bearer <api_key>"})),
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

async fn evaluate(
    State(state): State<AppState>,
    Json(action): Json<Action>,
) -> Result<Json<EvaluateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let policies = state.policies.load();

    let verdict = state
        .engine
        .evaluate_action(&action, &policies)
        .map_err(|e| {
            tracing::error!("Engine evaluation error: {}", e);
            state.metrics.record_error();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    // If RequireApproval, create a pending approval.
    // Fail-closed: if approval creation fails, convert to Deny so the caller
    // can't proceed without a resolvable approval_id.
    let (verdict, approval_id) = if let Verdict::RequireApproval { ref reason } = verdict {
        match state.approvals.create(action.clone(), reason.clone()).await {
            Ok(id) => (verdict, Some(id)),
            Err(e) => {
                tracing::error!("Failed to create approval (fail-closed → Deny): {}", e);
                let deny_reason = format!("Approval required but could not be created: {}", e);
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

    // Record metrics
    state.metrics.record_evaluation(&verdict);

    // Log to audit — fire-and-forget on error (don't fail the request)
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &verdict,
            json!({"source": "http", "approval_id": approval_id}),
        )
        .await
    {
        tracing::warn!("Failed to write audit entry: {}", e);
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
    let id = policy.id.clone();
    state.policies.rcu(|old| {
        let mut new = old.as_ref().clone();
        new.push(policy.clone());
        PolicyEngine::sort_policies(&mut new);
        new
    });
    tracing::info!("Added policy: {}", id);

    // Audit trail for policy mutation
    let action = Action {
        tool: "sentinel".to_string(),
        function: "add_policy".to_string(),
        parameters: json!({"policy_id": id}),
    };
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
    let before = state.policies.load().len();
    state.policies.rcu(|old| {
        let mut new = old.as_ref().clone();
        new.retain(|p| p.id != id);
        new
    });
    let after = state.policies.load().len();
    let removed = before.saturating_sub(after);

    if removed > 0 {
        tracing::info!("Removed {} policy(ies) with id: {}", removed, id);

        // Audit trail for policy mutation
        let action = Action {
            tool: "sentinel".to_string(),
            function: "remove_policy".to_string(),
            parameters: json!({"policy_id": id, "removed_count": removed}),
        };
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
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("No policy with id '{}'", id)})),
        )
    }
}

async fn reload_policies(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let config_path = state.config_path.as_str();

    let policy_config = PolicyConfig::load_file(config_path).map_err(|e| {
        tracing::error!("Failed to reload config from {}: {}", config_path, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to reload: {}", e),
            }),
        )
    })?;

    let mut new_policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut new_policies);
    let count = new_policies.len();
    state.policies.store(std::sync::Arc::new(new_policies));
    tracing::info!("Reloaded {} policies from {}", count, config_path);

    // Audit trail for policy reload
    let action = Action {
        tool: "sentinel".to_string(),
        function: "reload_policies".to_string(),
        parameters: json!({"config_path": config_path, "policy_count": count}),
    };
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "policies_reloaded"}),
        )
        .await
    {
        tracing::warn!("Failed to audit reload_policies: {}", e);
    }

    Ok(Json(json!({"reloaded": count, "config": config_path})))
}

async fn audit_entries(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let entries = state.audit.load_entries().await.map_err(|e| {
        tracing::error!("Failed to load audit entries: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(json!({"count": entries.len(), "entries": entries})))
}

async fn audit_report(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let report = state.audit.generate_report().await.map_err(|e| {
        tracing::error!("Failed to generate audit report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(report).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Serialization error: {}", e),
            }),
        )
    })?;
    Ok(Json(value))
}

async fn audit_verify(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let verification = state.audit.verify_chain().await.map_err(|e| {
        tracing::error!("Failed to verify audit chain: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(verification).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Serialization error: {}", e),
            }),
        )
    })?;
    Ok(Json(value))
}

// === Metrics Endpoint ===

async fn metrics(State(state): State<AppState>) -> Json<serde_json::Value> {
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
    Json(json!({"count": pending.len(), "approvals": pending}))
}

async fn get_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let approval = state.approvals.get(&id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(approval).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Serialization error: {}", e),
            }),
        )
    })?;
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

async fn approve_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<ResolveRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let resolved_by = body
        .map(|b| b.resolved_by.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    let approval = state
        .approvals
        .approve(&id, &resolved_by)
        .await
        .map_err(|e| {
            let status = match &e {
                sentinel_approval::ApprovalError::NotFound(_) => StatusCode::NOT_FOUND,
                sentinel_approval::ApprovalError::AlreadyResolved(_) => StatusCode::CONFLICT,
                sentinel_approval::ApprovalError::Expired(_) => StatusCode::GONE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    let value = serde_json::to_value(approval).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Serialization error: {}", e),
            }),
        )
    })?;
    Ok(Json(value))
}

async fn deny_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<ResolveRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let resolved_by = body
        .map(|b| b.resolved_by.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    let approval = state.approvals.deny(&id, &resolved_by).await.map_err(|e| {
        let status = match &e {
            sentinel_approval::ApprovalError::NotFound(_) => StatusCode::NOT_FOUND,
            sentinel_approval::ApprovalError::AlreadyResolved(_) => StatusCode::CONFLICT,
            sentinel_approval::ApprovalError::Expired(_) => StatusCode::GONE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(approval).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Serialization error: {}", e),
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

fn categorize_rate_limit<'a>(
    limits: &'a crate::RateLimits,
    method: &Method,
    path: &str,
) -> Option<&'a governor::DefaultDirectRateLimiter> {
    if path == "/api/evaluate" && method == Method::POST {
        limits.evaluate.as_ref()
    } else if method != Method::GET && method != Method::OPTIONS {
        limits.admin.as_ref()
    } else {
        limits.readonly.as_ref()
    }
}
