// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

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
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use vellaveto_types::{Action, Verdict};

use crate::routes::approval::derive_resolver_identity;
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
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&tool, "tool")?;

    let tracker = state.schema_lineage.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Schema lineage tracking is not enabled".to_string(),
            }),
        )
    })?;

    // SECURITY (FIND-R51-011): Generic error — do not echo tool name.
    let lineage = tracker.get_lineage(&tool).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool lineage not found".to_string(),
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
    headers: HeaderMap,
    Json(req): Json<ResetTrustRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&tool, "tool")?;

    // SECURITY (FIND-R51-001): Validate trust_score is finite and within [0.0, 1.0].
    // NaN, Infinity, negative, and >1.0 values are rejected.
    if !req.trust_score.is_finite() || req.trust_score < 0.0 || req.trust_score > 1.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "trust_score must be a finite number in the range [0.0, 1.0]".to_string(),
            }),
        ));
    }

    let tracker = state.schema_lineage.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Schema lineage tracking is not enabled".to_string(),
            }),
        )
    })?;

    tracker.reset_trust(&tool, req.trust_score);

    // SECURITY (FIND-R215-003): Audit trail for schema trust reset.
    let reset_by = derive_resolver_identity(&headers, "anonymous");
    let action = Action::new(
        "vellaveto",
        "schema_trust_reset",
        json!({ "tool": &tool, "trust_score": req.trust_score }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({
                "source": "api",
                "event": "schema_lineage.trust_reset",
                "tool": &tool,
                "trust_score": req.trust_score,
                "reset_by": &reset_by,
            }),
        )
        .await
    {
        tracing::warn!("Failed to audit schema trust reset for {}: {}", tool, e);
    } else {
        crate::metrics::increment_audit_entries();
    }

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
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&tool, "tool")?;

    let tracker = state.schema_lineage.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Schema lineage tracking is not enabled".to_string(),
            }),
        )
    })?;

    tracker.remove(&tool);

    // SECURITY (FIND-R215-003): Audit trail for schema lineage removal.
    let removed_by = derive_resolver_identity(&headers, "anonymous");
    let action = Action::new(
        "vellaveto",
        "schema_lineage_removed",
        json!({ "tool": &tool }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({
                "source": "api",
                "event": "schema_lineage.removed",
                "tool": &tool,
                "removed_by": &removed_by,
            }),
        )
        .await
    {
        tracing::warn!("Failed to audit schema lineage removal for {}: {}", tool, e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    Ok(StatusCode::NO_CONTENT)
}
