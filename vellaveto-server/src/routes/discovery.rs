//! Discovery route handlers (Phase 34).
//!
//! Endpoints:
//! - `POST /api/discovery/search` — programmatic tool discovery search
//! - `GET /api/discovery/index/stats` — index statistics
//! - `POST /api/discovery/reindex` — trigger IDF rebuild (Phase 34.4)
//! - `GET /api/discovery/tools` — list all indexed tools (Phase 34.4)

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum query length for discovery searches.
const MAX_QUERY_LENGTH: usize = 1024;

/// Maximum max_results parameter.
const MAX_RESULTS_PARAM: usize = 20;

/// Maximum number of tools returned by the list endpoint.
const MAX_TOOLS_LIST: usize = 100;

/// Maximum length of the server_id query parameter.
const MAX_SERVER_ID_LENGTH: usize = 256;

/// Request body for `POST /api/discovery/search`.
#[derive(Debug, Deserialize)]
pub struct DiscoverySearchRequest {
    /// Natural language description of the desired tool.
    pub query: String,
    /// Maximum number of results (default: 5, max: 20).
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    /// Optional token budget for returned schemas.
    #[serde(default)]
    pub token_budget: Option<usize>,
}

fn default_max_results() -> usize {
    5
}

/// POST /api/discovery/search
///
/// Search the tool discovery index for tools matching a natural language query.
/// Results are ranked by relevance, filtered by policy, and bounded by token budget.
pub async fn discovery_search(
    State(state): State<AppState>,
    Json(body): Json<DiscoverySearchRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let engine = state.discovery_engine.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool discovery is not enabled".to_string(),
            }),
        )
    })?;

    // Validate query length
    if body.query.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "query must not be empty".to_string(),
            }),
        ));
    }
    if body.query.len() > MAX_QUERY_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("query length {} exceeds max {}", body.query.len(), MAX_QUERY_LENGTH),
            }),
        ));
    }
    if body.query.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "query contains control characters".to_string(),
            }),
        ));
    }

    // Validate max_results
    let max_results = body.max_results.min(MAX_RESULTS_PARAM);
    if max_results == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "max_results must be > 0".to_string(),
            }),
        ));
    }

    // Allow all tools through the API (policy filtering is session-based)
    let result = engine
        .discover(&body.query, max_results, body.token_budget, &|_| true)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Discovery error: {}", e),
                }),
            )
        })?;

    // Audit log the query
    if let Some(ref audit) = state.discovery_audit {
        let _ = audit
            .log_discovery_event(
                "query",
                json!({
                    "query": &body.query,
                    "results_count": result.tools.len(),
                    "total_candidates": result.total_candidates,
                    "policy_filtered": result.policy_filtered,
                }),
            )
            .await;
    }

    Ok(Json(serde_json::to_value(result).unwrap_or_else(|_| {
        json!({"error": "serialization failed"})
    })))
}

/// GET /api/discovery/index/stats
///
/// Returns statistics about the tool discovery index.
pub async fn discovery_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let engine = state.discovery_engine.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool discovery is not enabled".to_string(),
            }),
        )
    })?;

    let stats = engine.index_stats().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Discovery error: {}", e),
            }),
        )
    })?;

    Ok(Json(serde_json::to_value(stats).unwrap_or_else(|_| {
        json!({"error": "serialization failed"})
    })))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 34.4: Reindex + List Tools
// ═══════════════════════════════════════════════════════════════════════════════

/// POST /api/discovery/reindex
///
/// Trigger a full rebuild of the IDF weights in the discovery index.
/// This is useful after manual tool metadata changes or bulk ingestion.
pub async fn discovery_reindex(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let engine = state.discovery_engine.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool discovery is not enabled".to_string(),
            }),
        )
    })?;

    engine.index().rebuild_idf().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Reindex failed: {}", e),
            }),
        )
    })?;

    let total_tools = engine.index().len().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to read index size: {}", e),
            }),
        )
    })?;

    // Audit log the reindex event
    if let Some(ref audit) = state.discovery_audit {
        let _ = audit
            .log_discovery_event(
                "reindex",
                json!({
                    "total_tools": total_tools,
                }),
            )
            .await;
    }

    Ok(Json(json!({
        "status": "ok",
        "total_tools": total_tools,
    })))
}

/// Query parameters for `GET /api/discovery/tools`.
#[derive(Debug, Deserialize)]
pub struct DiscoveryToolsQuery {
    /// Filter by originating MCP server ID.
    #[serde(default)]
    pub server_id: Option<String>,
    /// Filter by sensitivity level (low, medium, high).
    #[serde(default)]
    pub sensitivity: Option<String>,
}

/// GET /api/discovery/tools
///
/// List all indexed tools, optionally filtered by server_id and/or sensitivity.
/// Results are capped at 100 to prevent response explosion.
pub async fn discovery_tools(
    State(state): State<AppState>,
    Query(params): Query<DiscoveryToolsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let engine = state.discovery_engine.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool discovery is not enabled".to_string(),
            }),
        )
    })?;

    // Validate server_id parameter if provided
    if let Some(ref sid) = params.server_id {
        if sid.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "server_id must not be empty".to_string(),
                }),
            ));
        }
        if sid.len() > MAX_SERVER_ID_LENGTH {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "server_id length {} exceeds max {}",
                        sid.len(),
                        MAX_SERVER_ID_LENGTH
                    ),
                }),
            ));
        }
        if sid.chars().any(|c| c.is_control()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "server_id contains control characters".to_string(),
                }),
            ));
        }
    }

    // Parse and validate sensitivity parameter
    let sensitivity_filter = match params.sensitivity.as_deref() {
        Some("low") => Some(vellaveto_types::ToolSensitivity::Low),
        Some("medium") => Some(vellaveto_types::ToolSensitivity::Medium),
        Some("high") => Some(vellaveto_types::ToolSensitivity::High),
        Some(other) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "invalid sensitivity '{}'; must be one of: low, medium, high",
                        other
                    ),
                }),
            ));
        }
        None => None,
    };

    // Get all tool IDs
    let tool_ids = engine.index().tool_ids().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list tools: {}", e),
            }),
        )
    })?;

    // Collect and filter tools, capped at MAX_TOOLS_LIST
    let mut tools = Vec::new();
    for tool_id in &tool_ids {
        if tools.len() >= MAX_TOOLS_LIST {
            break;
        }

        let metadata = match engine.index().get(tool_id) {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to read tool {}: {}", tool_id, e),
                    }),
                ));
            }
        };

        // Apply server_id filter
        if let Some(ref sid) = params.server_id {
            if metadata.server_id != *sid {
                continue;
            }
        }

        // Apply sensitivity filter
        if let Some(ref sensitivity) = sensitivity_filter {
            if metadata.sensitivity != *sensitivity {
                continue;
            }
        }

        tools.push(metadata);
    }

    let total = tools.len();

    Ok(Json(json!({
        "tools": serde_json::to_value(&tools).unwrap_or_else(|_| json!([])),
        "total": total,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_request_deserialize_defaults() {
        let json = r#"{"query": "read file"}"#;
        let req: DiscoverySearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.query, "read file");
        assert_eq!(req.max_results, 5);
        assert!(req.token_budget.is_none());
    }

    #[test]
    fn test_search_request_deserialize_full() {
        let json = r#"{"query": "read file", "max_results": 10, "token_budget": 5000}"#;
        let req: DiscoverySearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.max_results, 10);
        assert_eq!(req.token_budget, Some(5000));
    }

    #[test]
    fn test_tools_query_deserialize_empty() {
        let json = r#"{}"#;
        let query: DiscoveryToolsQuery = serde_json::from_str(json).unwrap();
        assert!(query.server_id.is_none());
        assert!(query.sensitivity.is_none());
    }

    #[test]
    fn test_tools_query_deserialize_with_filters() {
        let json = r#"{"server_id": "my_server", "sensitivity": "high"}"#;
        let query: DiscoveryToolsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.server_id.as_deref(), Some("my_server"));
        assert_eq!(query.sensitivity.as_deref(), Some("high"));
    }

    #[test]
    fn test_tools_query_deserialize_partial() {
        let json = r#"{"sensitivity": "low"}"#;
        let query: DiscoveryToolsQuery = serde_json::from_str(json).unwrap();
        assert!(query.server_id.is_none());
        assert_eq!(query.sensitivity.as_deref(), Some("low"));
    }
}
