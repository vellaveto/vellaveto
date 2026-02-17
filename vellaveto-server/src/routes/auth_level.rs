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

/// SECURITY (FIND-R51-004): Maximum allowed value for expires_secs (24 hours).
/// Prevents unbounded session durations from a single API call.
const MAX_AUTH_EXPIRES_SECS: u64 = 86400;

/// Get auth level for a session.
///
/// GET /api/auth-levels/{session}
pub async fn get_auth_level(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&session, "session")?;

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
#[serde(deny_unknown_fields)]
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
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&session, "session")?;

    let tracker = state.auth_level.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Auth level tracking is not enabled".to_string(),
            }),
        )
    })?;

    // SECURITY (FIND-R51-004): Validate expires_secs is bounded.
    if let Some(secs) = req.expires_secs {
        if secs > MAX_AUTH_EXPIRES_SECS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "expires_secs must not exceed {} (24 hours)",
                        MAX_AUTH_EXPIRES_SECS
                    ),
                }),
            ));
        }
    }

    let level = match req.level.to_lowercase().as_str() {
        "none" => vellaveto_types::AuthLevel::None,
        "basic" => vellaveto_types::AuthLevel::Basic,
        "oauth" => vellaveto_types::AuthLevel::OAuth,
        "oauth_mfa" | "oauthmfa" => vellaveto_types::AuthLevel::OAuthMfa,
        "hardware_key" | "hardwarekey" => vellaveto_types::AuthLevel::HardwareKey,
        // SECURITY (FIND-R51-014): Do not echo raw input in error message.
        _ => return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error:
                    "Invalid auth level. Valid levels: none, basic, oauth, oauth_mfa, hardware_key"
                        .to_string(),
            }),
        )),
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
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&session, "session")?;

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
