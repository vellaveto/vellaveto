// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Task State route handlers (MCP 2025-11-25 Async Tasks).
//!
//! This module provides REST API endpoints for MCP async task management.
//!
//! Endpoints:
//! - `GET /api/tasks` - List task summary
//! - `GET /api/tasks/stats` - Get task statistics
//! - `GET /api/tasks/{id}` - Get a specific task
//! - `POST /api/tasks/{id}/cancel` - Cancel a task

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// List task summary.
///
/// GET /api/tasks
///
/// Returns summary of tracked tasks. Use /api/tasks/stats for detailed statistics.
pub async fn list_tasks(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let manager = state.task_state.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task state management is not enabled".to_string(),
            }),
        )
    })?;

    let active_count = manager.active_count().await;

    Ok(Json(json!({
        "active_count": active_count,
        "message": "Use /api/tasks/stats for detailed statistics or /api/tasks/{id} for specific task",
    })))
}

/// Get task statistics.
///
/// GET /api/tasks/stats
pub async fn task_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let manager = state.task_state.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task state management is not enabled".to_string(),
            }),
        )
    })?;

    let stats = manager.stats().await;

    Ok(Json(json!({
        "total": stats.total,
        "pending": stats.pending,
        "running": stats.running,
        "completed": stats.completed,
        "failed": stats.failed,
        "cancelled": stats.cancelled,
        "expired": stats.expired,
        "active": stats.active(),
    })))
}

/// Get a specific task.
///
/// GET /api/tasks/{id}
pub async fn get_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&id, "id")?;

    let manager = state.task_state.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task state management is not enabled".to_string(),
            }),
        )
    })?;

    // SECURITY (FIND-R51-011): Generic error — do not echo task ID.
    let task = manager.get_task(&id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task not found".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(task).map_err(|e| {
        tracing::error!("Failed to serialize task: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize task".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// Cancel a task.
///
/// POST /api/tasks/{id}/cancel
///
/// SECURITY (FIND-R60-001): Requires authorization via `can_cancel()`. The agent
/// identity is derived from the Authorization header (Bearer token hash). Without
/// auth, the agent_id is None which `can_cancel` handles per configuration:
/// - `require_self_cancel`: denies when no requester identity is provided
/// - `allow_cancellation`: denies when agent is not in the allowed list
pub async fn cancel_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param(&id, "id")?;

    let manager = state.task_state.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Task state management is not enabled".to_string(),
            }),
        )
    })?;

    // SECURITY (FIND-R60-001): Extract agent identity from auth context for
    // authorization. Derive from Bearer token hash to match approval route pattern.
    let agent_id: Option<String> = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| {
            if auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
                let token = &auth[7..];
                if !token.is_empty() {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(token.as_bytes());
                    Some(format!("bearer:{}", hex::encode(&hash[..16])))
                } else {
                    None
                }
            } else {
                None
            }
        });

    // SECURITY (FIND-R60-001): Check can_cancel authorization before mutating state.
    // This enforces require_self_cancel and allow_cancellation policies that were
    // previously bypassed by calling update_status directly.
    match manager.can_cancel(&id, agent_id.as_deref()).await {
        Ok(true) => { /* authorized */ }
        Ok(false) => {
            tracing::warn!(
                "Task cancellation denied: task_id={}, agent={:?}",
                id,
                agent_id
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not authorized to cancel this task".to_string(),
                }),
            ));
        }
        Err(e) => {
            tracing::warn!("Task cancellation check failed: {}", e);
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Task not found".to_string(),
                }),
            ));
        }
    }

    // SECURITY (FIND-R51-017): Generic error — do not leak state machine details.
    manager
        .update_status(&id, vellaveto_types::TaskStatus::Cancelled)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to cancel task: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Cannot cancel task".to_string(),
                }),
            )
        })?;

    Ok(Json(json!({
        "task_id": id,
        "status": "cancelled",
        "message": "Task cancelled successfully",
    })))
}
