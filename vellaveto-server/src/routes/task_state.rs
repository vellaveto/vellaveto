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
    http::StatusCode,
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
pub async fn cancel_task(
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
