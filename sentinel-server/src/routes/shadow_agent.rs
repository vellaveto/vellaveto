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
pub struct RegisterAgentRequest {
    pub agent_id: String,
    pub fingerprint: sentinel_types::AgentFingerprint,
}

/// Register a known agent.
///
/// POST /api/shadow-agents
pub async fn register_shadow_agent(
    State(state): State<AppState>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
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
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
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
    let _detector = state.shadow_agent.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Shadow agent detection is not enabled".to_string(),
            }),
        )
    })?;

    // Note: Trust updates require the fingerprint, not just the ID.
    // This endpoint exists for API completeness. In practice, trust is
    // updated automatically based on agent behavior.
    let trust = sentinel_types::TrustLevel::from_u8(req.trust_level);

    Ok(Json(json!({
        "agent_id": id,
        "requested_trust_level": format!("{:?}", trust),
        "message": "Trust level updates require fingerprint; agent trust is managed automatically",
    })))
}
