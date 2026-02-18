//! Execution Graph Export route handlers (Phase 6).
//!
//! This module provides REST API endpoints for execution graph
//! visualization and export.
//!
//! Endpoints:
//! - `GET /api/graphs` - List all execution graph sessions
//! - `GET /api/graphs/{session}` - Get an execution graph in JSON format
//! - `GET /api/graphs/{session}/dot` - Get an execution graph in DOT format
//! - `GET /api/graphs/{session}/stats` - Get execution graph statistics

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum number of sessions to scan when filtering by tool.
const MAX_TOOL_FILTER_SCAN: usize = 10_000;

/// Maximum tool filter parameter length.
const MAX_TOOL_FILTER_LEN: usize = 256;

/// Query parameters for graph listing.
#[derive(Deserialize)]
pub struct GraphListQuery {
    /// Filter by tool name.
    pub tool: Option<String>,
    /// Maximum number of results.
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

/// List all execution graph sessions.
///
/// GET /api/graphs
pub async fn list_graphs(
    State(state): State<AppState>,
    Query(params): Query<GraphListQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let store = state.exec_graph_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Execution graph tracking is not enabled".to_string(),
            }),
        )
    })?;

    let sessions = store.list_sessions().await;
    let total = sessions.len();
    let limit = params.limit.unwrap_or(100).min(1000);
    // SECURITY (FIND-R49-006): Cap offset to prevent unreasonable pagination.
    let offset = params.offset.unwrap_or(0).min(1_000_000);

    // SECURITY (FIND-R49-002): Validate tool filter parameter.
    if let Some(ref tool_filter) = params.tool {
        if tool_filter.is_empty() || tool_filter.len() > MAX_TOOL_FILTER_LEN {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid tool filter parameter".to_string(),
                }),
            ));
        }
        if tool_filter.chars().any(crate::routes::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "tool filter contains control characters".to_string(),
                }),
            ));
        }
    }

    // If filtering by tool, we need to check each graph
    let filtered: Vec<_> = if let Some(ref tool_filter) = params.tool {
        let mut result = Vec::new();
        for session_id in sessions.iter().take(MAX_TOOL_FILTER_SCAN) {
            if let Some(graph) = store.get(session_id).await {
                if graph.metadata.unique_tools.contains(tool_filter) {
                    result.push(json!({
                        "session_id": session_id,
                        "node_count": graph.nodes.len(),
                        "started_at": graph.metadata.started_at,
                        "ended_at": graph.metadata.ended_at,
                    }));
                }
            }
        }
        result.into_iter().skip(offset).take(limit).collect()
    } else {
        let mut result = Vec::new();
        for session_id in sessions.iter().skip(offset).take(limit) {
            if let Some(graph) = store.get(session_id).await {
                result.push(json!({
                    "session_id": session_id,
                    "node_count": graph.nodes.len(),
                    "started_at": graph.metadata.started_at,
                    "ended_at": graph.metadata.ended_at,
                }));
            }
        }
        result
    };

    Ok(Json(json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "graphs": filtered,
    })))
}

/// Get an execution graph in JSON format.
///
/// GET /api/graphs/{session}
pub async fn get_graph(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R48-003): Validate session path parameter length and control chars.
    if session.len() > 128 || session.chars().any(crate::routes::is_unsafe_char) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid session ID".to_string(),
            }),
        ));
    }

    let store = state.exec_graph_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Execution graph tracking is not enabled".to_string(),
            }),
        )
    })?;

    let graph = store.get(&session).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Graph not found".to_string(),
            }),
        )
    })?;

    let json_value = serde_json::to_value(&graph).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize graph: {}", e),
            }),
        )
    })?;

    Ok(Json(json_value))
}

/// Get an execution graph in DOT (Graphviz) format.
///
/// GET /api/graphs/{session}/dot
pub async fn get_graph_dot(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R48-003): Validate session path parameter.
    if session.len() > 128 || session.chars().any(crate::routes::is_unsafe_char) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid session ID".to_string(),
            }),
        ));
    }

    let store = state.exec_graph_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Execution graph tracking is not enabled".to_string(),
            }),
        )
    })?;

    let graph = store.get(&session).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Graph not found".to_string(),
            }),
        )
    })?;

    let dot = graph.to_dot();

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/vnd.graphviz")],
        dot,
    )
        .into_response())
}

/// Get execution graph statistics.
///
/// GET /api/graphs/{session}/stats
pub async fn get_graph_stats(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R48-003): Validate session path parameter.
    if session.len() > 128 || session.chars().any(crate::routes::is_unsafe_char) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid session ID".to_string(),
            }),
        ));
    }

    let store = state.exec_graph_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Execution graph tracking is not enabled".to_string(),
            }),
        )
    })?;

    let graph = store.get(&session).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Graph not found".to_string(),
            }),
        )
    })?;

    let stats = graph.statistics();

    let value = serde_json::to_value(&stats).map_err(|e| {
        tracing::error!("Failed to serialize graph stats: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize graph statistics".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}
