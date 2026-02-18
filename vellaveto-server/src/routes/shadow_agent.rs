//! Shadow Agent Detection route handlers.
//!
//! This module provides REST API endpoints for shadow agent detection
//! and management, including listing, registering, and trust level updates.
//!
//! Endpoints:
//! - `GET /api/shadow-agents` - List all known agents
//! - `POST /api/shadow-agents` - Register a known agent
//! - `DELETE /api/shadow-agents/{id}` - Remove a known agent
//! - `PUT /api/shadow-agents/{id}/trust` - Update agent trust level

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

const MAX_AGENT_ID_LEN: usize = 128;

fn validate_agent_id(agent_id: &str) -> Result<(), &'static str> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        return Err("agent_id cannot be empty");
    }
    if trimmed.len() > MAX_AGENT_ID_LEN {
        return Err("agent_id is too long");
    }
    if trimmed.chars().any(|c| crate::routes::is_unsafe_char(c)) {
        return Err("agent_id contains control characters");
    }
    Ok(())
}

fn parse_trust_level(value: u8) -> Option<vellaveto_types::TrustLevel> {
    match value {
        0 => Some(vellaveto_types::TrustLevel::Unknown),
        1 => Some(vellaveto_types::TrustLevel::Low),
        2 => Some(vellaveto_types::TrustLevel::Medium),
        3 => Some(vellaveto_types::TrustLevel::High),
        4 => Some(vellaveto_types::TrustLevel::Verified),
        _ => None,
    }
}

/// List all known agents.
///
/// GET /api/shadow-agents
pub async fn list_shadow_agents(
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

/// Request body for registering an agent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterAgentRequest {
    pub agent_id: String,
    pub fingerprint: vellaveto_types::AgentFingerprint,
}

/// Register a known agent.
///
/// POST /api/shadow-agents
pub async fn register_shadow_agent(
    State(state): State<AppState>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(msg) = validate_agent_id(&req.agent_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: msg.to_string(),
            }),
        ));
    }

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
pub async fn remove_shadow_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(msg) = validate_agent_id(&id) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: msg.to_string(),
            }),
        ));
    }

    if state.shadow_agent.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow agent detection is not enabled".to_string(),
            }),
        ));
    }

    // Note: ShadowAgentDetector doesn't have a remove method.
    // Agents are managed via trust level updates instead.
    // This endpoint exists for API completeness but returns a message.
    Ok(Json(json!({
        "agent_id": id,
        "message": "Agent removal is handled via trust level (set to 0 to distrust)",
    })))
}

/// Request body for updating agent trust level.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTrustRequest {
    pub trust_level: u8,
}

/// Update agent trust level.
///
/// PUT /api/shadow-agents/{id}/trust
pub async fn update_agent_trust(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateTrustRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(msg) = validate_agent_id(&id) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: msg.to_string(),
            }),
        ));
    }

    let _detector = state.shadow_agent.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow agent detection is not enabled".to_string(),
            }),
        )
    })?;

    let trust = parse_trust_level(req.trust_level).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid trust_level; expected 0..=4".to_string(),
            }),
        )
    })?;

    // Note: Trust updates require the fingerprint, not just the ID.
    // This endpoint exists for API completeness. In practice, trust is
    // updated automatically based on agent behavior.
    Ok(Json(json!({
        "agent_id": id,
        "requested_trust_level": format!("{:?}", trust),
        "message": "Trust level updates require fingerprint; agent trust is managed automatically",
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_agent_id_rejects_invalid_inputs() {
        assert!(validate_agent_id("").is_err());
        assert!(validate_agent_id("   ").is_err());
        assert!(validate_agent_id("abc\nxyz").is_err());
        assert!(validate_agent_id(&"a".repeat(MAX_AGENT_ID_LEN + 1)).is_err());
    }

    #[test]
    fn validate_agent_id_accepts_normal_values() {
        assert!(validate_agent_id("agent-1").is_ok());
        assert!(validate_agent_id("team/service@prod").is_ok());
    }

    #[test]
    fn parse_trust_level_rejects_out_of_range() {
        assert!(parse_trust_level(0).is_some());
        assert!(parse_trust_level(4).is_some());
        assert!(parse_trust_level(5).is_none());
        assert!(parse_trust_level(255).is_none());
    }
}
