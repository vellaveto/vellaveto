//! Circuit Breaker route handlers (OWASP ASI08).
//!
//! This module provides REST API endpoints for circuit breaker management
//! including state inspection, statistics, and manual reset.
//!
//! Endpoints:
//! - `GET /api/circuit-breaker` - List all circuit breaker states
//! - `GET /api/circuit-breaker/stats` - Get circuit breaker statistics summary
//! - `GET /api/circuit-breaker/{tool}` - Get circuit state for a specific tool
//! - `POST /api/circuit-breaker/{tool}/reset` - Reset circuit breaker for a tool

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// SECURITY (FIND-R67-004-006): Maximum number of circuit breaker entries returned by list endpoint.
const MAX_CIRCUIT_LIST: usize = 1000;

/// List all circuit breaker states.
///
/// GET /api/circuit-breaker
pub async fn list_circuit_breakers(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let cb = state.circuit_breaker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Circuit breaker is not enabled. Set [circuit_breaker] enabled = true in your config file and restart the server.".to_string(),
            }),
        )
    })?;

    let tools = cb.tracked_tools();
    let total = tools.len();
    let mut entries = Vec::new();

    // SECURITY (FIND-R67-004-006): Cap response to prevent unbounded serialization.
    for tool in tools.iter().take(MAX_CIRCUIT_LIST) {
        let circuit_state = cb.get_state(tool);
        let stats = cb.get_stats(tool);
        entries.push(json!({
            "tool": tool,
            "state": format!("{:?}", circuit_state),
            "stats": stats,
        }));
    }

    Ok(Json(json!({
        "count": entries.len(),
        "total": total,
        "truncated": total > MAX_CIRCUIT_LIST,
        "circuits": entries,
    })))
}

/// Get circuit breaker statistics summary.
///
/// GET /api/circuit-breaker/stats
pub async fn circuit_breaker_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let cb = state.circuit_breaker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Circuit breaker is not enabled. Set [circuit_breaker] enabled = true in your config file and restart the server.".to_string(),
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
pub async fn get_circuit_state(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&tool, "tool")?;

    let cb = state.circuit_breaker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Circuit breaker is not enabled. Set [circuit_breaker] enabled = true in your config file and restart the server.".to_string(),
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
pub async fn reset_circuit(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&tool, "tool")?;

    let cb = state.circuit_breaker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Circuit breaker is not enabled. Set [circuit_breaker] enabled = true in your config file and restart the server.".to_string(),
            }),
        )
    })?;

    if let Err(reason) = cb.reset(&tool) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: reason }),
        ));
    }

    Ok(Json(json!({
        "tool": tool,
        "state": "Closed",
        "message": "Circuit breaker reset successfully",
    })))
}
