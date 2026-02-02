use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use sentinel_config::PolicyConfig;
use sentinel_types::{Action, Policy, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::cors::CorsLayer;
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
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
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

    // Log to audit — fire-and-forget on error (don't fail the request)
    if let Err(e) = state
        .audit
        .log_entry(&action, &verdict, json!({"source": "http"}))
        .await
    {
        tracing::warn!("Failed to write audit entry: {}", e);
    }

    Ok(Json(EvaluateResponse {
        verdict,
        action,
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

    let new_policies = policy_config.to_policies();
    let count = new_policies.len();
    *state.policies.write().await = new_policies;
    tracing::info!("Reloaded {} policies from {}", count, config_path);

    Ok(Json(
        json!({"reloaded": count, "config": config_path}),
    ))
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

    Ok(Json(serde_json::to_value(report).unwrap_or_default()))
}