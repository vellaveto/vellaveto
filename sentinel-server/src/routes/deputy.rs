//! Deputy Validation route handlers (OWASP ASI02).
//!
//! This module provides REST API endpoints for deputy validation
//! and delegation management.
//!
//! Endpoints:
//! - `GET /api/deputy/delegations` - List active delegation count
//! - `POST /api/deputy/delegations` - Register a delegation
//! - `DELETE /api/deputy/delegations/{session}` - Remove a delegation

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// List active delegation count.
///
/// GET /api/deputy/delegations
pub async fn list_delegations(
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

/// Request body for registering a delegation.
#[derive(Deserialize)]
pub struct RegisterDelegationRequest {
    pub session_id: String,
    pub from_principal: String,
    pub to_principal: String,
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub expires_secs: Option<u64>,
}

/// Register a delegation.
///
/// POST /api/deputy/delegations
pub async fn register_delegation(
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
pub async fn remove_delegation(
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
