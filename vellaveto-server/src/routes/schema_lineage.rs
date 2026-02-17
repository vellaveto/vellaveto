//! Schema Lineage route handlers (OWASP ASI05).
//!
//! This module provides REST API endpoints for schema lineage tracking
//! and trust management, detecting schema drift attacks.
//!
//! Endpoints:
//! - `GET /api/schema-lineage` - List all tracked tool schemas
//! - `GET /api/schema-lineage/{tool}` - Get schema lineage for a specific tool
//! - `PUT /api/schema-lineage/{tool}/trust` - Reset trust score for a tool's schema
//! - `DELETE /api/schema-lineage/{tool}` - Remove schema lineage for a tool

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// List all tracked tool schemas.
///
/// GET /api/schema-lineage
pub async fn list_schema_lineage(
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
pub async fn get_schema_lineage(
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

/// Request body for resetting trust score.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetTrustRequest {
    pub trust_score: f32,
}

/// Reset trust score for a tool's schema.
///
/// PUT /api/schema-lineage/{tool}/trust
pub async fn reset_schema_trust(
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
pub async fn remove_schema_lineage(
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
