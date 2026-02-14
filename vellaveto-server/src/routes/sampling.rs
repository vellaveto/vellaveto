//! Sampling Detection route handlers.
//!
//! This module provides REST API endpoints for sampling detection
//! statistics and management.
//!
//! Endpoints:
//! - `GET /api/sampling/stats` - Get sampling detection statistics
//! - `POST /api/sampling/{session}/reset` - Reset sampling stats for a session

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Get sampling detection statistics.
///
/// GET /api/sampling/stats
pub async fn sampling_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let detector = state.sampling_detector.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Sampling detection is not enabled".to_string(),
            }),
        )
    })?;

    let session_count = detector.session_count();

    Ok(Json(json!({
        "session_count": session_count,
        "message": "Use /api/sampling/{session}/reset to clear session stats",
    })))
}

/// Reset sampling stats for a session.
///
/// POST /api/sampling/{session}/reset
pub async fn reset_sampling_stats(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let detector = state.sampling_detector.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Sampling detection is not enabled".to_string(),
            }),
        )
    })?;

    detector.clear_session(&session);

    Ok(Json(json!({
        "session": session,
        "message": "Sampling stats cleared",
    })))
}
