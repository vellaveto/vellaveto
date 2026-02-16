//! Governance route handlers (Phase 26).
//!
//! Endpoints:
//! - `GET /api/governance/shadow-report` — full shadow AI discovery report
//! - `GET /api/governance/unregistered-agents` — list unregistered agents
//! - `GET /api/governance/unapproved-tools` — list unapproved tools
//! - `GET /api/governance/least-agency/{agent_id}/{session_id}` — least-agency report
//!
//! **RBAC note (FIND-R44-049):** These endpoints are protected by the API key
//! authentication middleware and RBAC layer configured in the server router.
//! Granular governance permissions (e.g., read-only shadow report vs. full
//! governance admin) should be configured via the RBAC policy definitions.
//! See the server's middleware chain in `main.rs` for auth enforcement.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// GET /api/governance/shadow-report
///
/// Returns the full shadow AI discovery report: unregistered agents,
/// unapproved tools, unknown servers, and aggregate risk score.
pub async fn shadow_report(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let discovery = state.shadow_ai_discovery.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow AI discovery is not enabled".to_string(),
            }),
        )
    })?;

    let report = discovery.generate_report();
    let value = serde_json::to_value(report).map_err(|e| {
        tracing::error!("Failed to serialize shadow report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize shadow report".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// GET /api/governance/unregistered-agents
///
/// Returns just the list of unregistered agents with their metadata.
pub async fn unregistered_agents(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let discovery = state.shadow_ai_discovery.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow AI discovery is not enabled".to_string(),
            }),
        )
    })?;

    let report = discovery.generate_report();
    Ok(Json(json!({
        "count": report.unregistered_agents.len(),
        "agents": report.unregistered_agents,
    })))
}

/// GET /api/governance/unapproved-tools
///
/// Returns just the list of unapproved tools with their metadata.
pub async fn unapproved_tools(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let discovery = state.shadow_ai_discovery.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow AI discovery is not enabled".to_string(),
            }),
        )
    })?;

    let report = discovery.generate_report();
    Ok(Json(json!({
        "count": report.unapproved_tools.len(),
        "tools": report.unapproved_tools,
    })))
}

/// GET /api/governance/least-agency/{agent_id}/{session_id}
///
/// Returns the least-agency compliance report for a specific agent/session,
/// including usage ratio, unused permissions, and narrowing recommendations.
pub async fn least_agency_report(
    State(state): State<AppState>,
    Path((agent_id, session_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Validate input lengths
    if agent_id.len() > 128 || session_id.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "agent_id or session_id too long (max 128)".to_string(),
            }),
        ));
    }
    if agent_id.chars().any(|c| c.is_control()) || session_id.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "agent_id or session_id contains control characters".to_string(),
            }),
        ));
    }

    let tracker = state.least_agency_tracker.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Least agency tracking is not enabled".to_string(),
            }),
        )
    })?;

    // FIND-R44-050: Use generic error message to prevent agent/session enumeration
    let report = tracker.generate_report(&agent_id, &session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "No tracking data found".to_string(),
            }),
        )
    })?;

    // Also check for auto-revocation candidates
    let auto_revoke_candidates = tracker.check_auto_revoke(&agent_id, &session_id);

    Ok(Json(json!({
        "report": report,
        "enforcement_mode": tracker.enforcement_mode(),
        "auto_revoke_candidates": auto_revoke_candidates,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_format() {
        let err = ErrorResponse {
            error: "test error".to_string(),
        };
        let json = serde_json::to_string(&err);
        assert!(json.is_ok());
        assert!(json.unwrap().contains("test error"));
    }
}
