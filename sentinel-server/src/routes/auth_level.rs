//! Auth Level route handlers (Step-Up Authentication).
//!
//! This module provides REST API endpoints for step-up authentication
//! level tracking and management.
//!
//! Endpoints:
//! - `GET /api/auth-levels/{session}` - Get auth level for a session
//! - `POST /api/auth-levels/{session}/upgrade` - Upgrade auth level for a session
//! - `DELETE /api/auth-levels/{session}` - Clear auth level for a session

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Get auth level for a session.
///
/// GET /api/auth-levels/{session}
pub async fn get_auth_level(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.auth_level.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Auth level tracking is not enabled".to_string(),
            }),
        )
    })?;

    let level = tracker.get_level(&session).await;
    let info = tracker.get_session_info(&session).await;

    Ok(Json(json!({
        "session": session,
        "level": format!("{:?}", level),
        "info": info.map(|i| json!({
            "level": format!("{:?}", i.level),
            "age_secs": i.age.as_secs(),
            "expires_in_secs": i.expires_in.map(|d| d.as_secs()),
        })),
    })))
}

/// Request body for upgrading auth level.
#[derive(Deserialize)]
pub struct UpgradeAuthRequest {
    pub level: String,
    #[serde(default)]
    pub expires_secs: Option<u64>,
}

/// Upgrade auth level for a session.
///
/// POST /api/auth-levels/{session}/upgrade
pub async fn upgrade_auth_level(
    State(state): State<AppState>,
    Path(session): Path<String>,
    Json(req): Json<UpgradeAuthRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.auth_level.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Auth level tracking is not enabled".to_string(),
            }),
        )
    })?;

    let level = match req.level.to_lowercase().as_str() {
        "none" => sentinel_types::AuthLevel::None,
        "basic" => sentinel_types::AuthLevel::Basic,
        "oauth" => sentinel_types::AuthLevel::OAuth,
        "oauth_mfa" | "oauthmfa" => sentinel_types::AuthLevel::OAuthMfa,
        "hardware_key" | "hardwarekey" => sentinel_types::AuthLevel::HardwareKey,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid auth level: {}. Valid levels: none, basic, oauth, oauth_mfa, hardware_key",
                        req.level
                    ),
                }),
            ))
        }
    };

    let expires = req.expires_secs.map(std::time::Duration::from_secs);
    tracker.upgrade(&session, level, expires).await;

    Ok(Json(json!({
        "session": session,
        "level": format!("{:?}", level),
        "message": "Auth level upgraded",
    })))
}

/// Clear auth level for a session.
///
/// DELETE /api/auth-levels/{session}
pub async fn clear_auth_level(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let tracker = state.auth_level.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Auth level tracking is not enabled".to_string(),
            }),
        )
    })?;

    tracker.remove(&session).await;

    Ok(StatusCode::NO_CONTENT)
}
