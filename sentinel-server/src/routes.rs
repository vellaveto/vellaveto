use axum::{
    extract::{Path, Request, State},
    http::{header, Method, StatusCode},
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
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::AppState;

pub fn build_router(state: AppState) -> Router {
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
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]),
        )
        .with_state(state)
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
            if token == api_key.as_str() {
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
    let count = state.policies.read().await.len();
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
    let policies = state.policies.read().await;

    let verdict = state
        .engine
        .evaluate_action(&action, &policies)
        .map_err(|e| {
            tracing::error!("Engine evaluation error: {}", e);
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
    let policies = state.policies.read().await;
    Json(policies.clone())
}

async fn add_policy(
    State(state): State<AppState>,
    Json(policy): Json<Policy>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut policies = state.policies.write().await;
    let id = policy.id.clone();
    policies.push(policy);
    PolicyEngine::sort_policies(&mut policies);
    tracing::info!("Added policy: {}", id);
    (StatusCode::CREATED, Json(json!({"added": id})))
}

async fn remove_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut policies = state.policies.write().await;
    let before = policies.len();
    policies.retain(|p| p.id != id);
    let removed = before - policies.len();

    if removed > 0 {
        tracing::info!("Removed {} policy(ies) with id: {}", removed, id);
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
    *state.policies.write().await = new_policies;
    tracing::info!("Reloaded {} policies from {}", count, config_path);

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
