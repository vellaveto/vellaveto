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

/// Maximum length for string fields in delegation requests.
const MAX_FIELD_LEN: usize = 256;
/// Maximum length for session_id.
const MAX_SESSION_ID_LEN: usize = 128;
/// Maximum number of entries in allowed_tools.
const MAX_TOOLS_LEN: usize = 100;
/// Maximum expiration in seconds (30 days).
const MAX_EXPIRES_SECS: u64 = 86400 * 30;

/// Validate a string field: reject if too long or contains control characters.
/// SECURITY (FIND-R41-011): Rejects ALL control characters (including \n, \t)
/// to prevent log injection in identifier fields.
fn validate_field(
    value: &str,
    field_name: &str,
    max_len: usize,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if value.len() > max_len {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("{} exceeds maximum length of {}", field_name, max_len),
            }),
        ));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("{} contains invalid control characters", field_name),
            }),
        ));
    }
    Ok(())
}

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

    // Validate input fields before processing.
    validate_field(&req.session_id, "session_id", MAX_SESSION_ID_LEN)?;
    validate_field(&req.from_principal, "from_principal", MAX_FIELD_LEN)?;
    validate_field(&req.to_principal, "to_principal", MAX_FIELD_LEN)?;

    // SECURITY (FIND-R42-018): Reject self-delegation.
    if req.from_principal == req.to_principal {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "from_principal and to_principal must differ".to_string(),
            }),
        ));
    }

    if req.allowed_tools.len() > MAX_TOOLS_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "allowed_tools exceeds maximum of {} entries",
                    MAX_TOOLS_LEN
                ),
            }),
        ));
    }
    for (i, tool) in req.allowed_tools.iter().enumerate() {
        validate_field(tool, &format!("allowed_tools[{}]", i), MAX_FIELD_LEN)?;
    }

    if let Some(secs) = req.expires_secs {
        if secs == 0 || secs > MAX_EXPIRES_SECS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "expires_secs must be between 1 and {} (30 days)",
                        MAX_EXPIRES_SECS
                    ),
                }),
            ));
        }
    }

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

    // SECURITY (FIND-R42-016): Validate path parameter length.
    validate_field(&session, "session", MAX_SESSION_ID_LEN)?;

    deputy.remove_context(&session);

    Ok(StatusCode::NO_CONTENT)
}
