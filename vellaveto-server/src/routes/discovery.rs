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

/// SECURITY (FIND-R46-006): Maximum token_budget to prevent excessive computation.
/// Token budgets above this are unreasonable and could cause DoS through
/// schema serialization of thousands of tools.
const MAX_TOKEN_BUDGET: usize = 1_000_000;

/// Maximum length of the server_id query parameter.
const MAX_SERVER_ID_LENGTH: usize = 256;

/// Request body for `POST /api/discovery/search`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
                error: "Tool discovery is not enabled. Set [discovery] enabled = true in your config file and restart the server.".to_string(),
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
                error: format!(
                    "query length {} exceeds max {}",
                    body.query.len(),
                    MAX_QUERY_LENGTH
                ),
            }),
        ));
    }
    if body.query.chars().any(crate::routes::is_unsafe_char) {
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

    // SECURITY (FIND-R46-006): Validate token_budget upper bound.
    if let Some(budget) = body.token_budget {
        if budget > MAX_TOKEN_BUDGET {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("token_budget {} exceeds max {}", budget, MAX_TOKEN_BUDGET),
                }),
            ));
        }
    }

    // SECURITY (FIND-R46-004): Policy filtering for the discovery API is
    // session-based and happens within the ProxyBridge relay. The REST API
    // returns all tools because it serves administrative/developer use cases.
    // Route-level authentication is enforced by the middleware layer applied
    // to all /api/* routes in the router configuration (see routes/main.rs).
    let result = engine
        .discover(&body.query, max_results, body.token_budget, &|_| true)
        .map_err(|e| {
            tracing::warn!(error = %e, "Discovery query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Discovery query failed".to_string(),
                }),
            )
        })?;

    // Audit log the query
    // SECURITY (FIND-R46-013): Log audit failures instead of silently discarding.
    if let Some(ref audit) = state.discovery_audit {
        if let Err(e) = audit
            .log_discovery_event(
                "query",
                json!({
                    "query": &body.query,
                    "results_count": result.tools.len(),
                    "total_candidates": result.total_candidates,
                    "policy_filtered": result.policy_filtered,
                }),
            )
            .await
        {
            tracing::warn!(error = %e, "Failed to audit-log discovery search query");
        }
    }

    let value = serde_json::to_value(result).map_err(|e| {
        tracing::error!("Failed to serialize discovery search result: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize discovery result".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
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
                error: "Tool discovery is not enabled. Set [discovery] enabled = true in your config file and restart the server.".to_string(),
            }),
        )
    })?;

    let stats = engine.index_stats().map_err(|e| {
        // SECURITY (FIND-R64-006): Redact internal error details from client response.
        tracing::warn!(error = %e, "Discovery index stats failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Discovery index operation failed".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(stats).map_err(|e| {
        tracing::error!("Failed to serialize discovery stats: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize discovery stats".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
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
                error: "Tool discovery is not enabled. Set [discovery] enabled = true in your config file and restart the server.".to_string(),
            }),
        )
    })?;

    engine.index().rebuild_idf().map_err(|e| {
        // SECURITY (FIND-R65-001): Redact internal error details.
        tracing::warn!(error = %e, "Discovery reindex failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Reindex failed".to_string(),
            }),
        )
    })?;

    let total_tools = engine.index().len().map_err(|e| {
        // SECURITY (FIND-R65-001): Redact internal error details.
        tracing::warn!(error = %e, "Failed to read discovery index size");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to read index size".to_string(),
            }),
        )
    })?;

    // Audit log the reindex event
    // SECURITY (FIND-R46-013): Log audit failures instead of silently discarding.
    if let Some(ref audit) = state.discovery_audit {
        if let Err(e) = audit
            .log_discovery_event(
                "reindex",
                json!({
                    "total_tools": total_tools,
                }),
            )
            .await
        {
            tracing::warn!(error = %e, "Failed to audit-log discovery reindex");
        }
    }

    Ok(Json(json!({
        "status": "ok",
        "total_tools": total_tools,
    })))
}

/// Query parameters for `GET /api/discovery/tools`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
                error: "Tool discovery is not enabled. Set [discovery] enabled = true in your config file and restart the server.".to_string(),
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
        if sid.chars().any(crate::routes::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "server_id contains control characters".to_string(),
                }),
            ));
        }
    }

    // SECURITY (FIND-R48-005): Validate sensitivity parameter length before reflecting.
    if let Some(ref s) = params.sensitivity {
        if s.len() > 32 || s.chars().any(crate::routes::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid sensitivity parameter".to_string(),
                }),
            ));
        }
    }

    // Parse and validate sensitivity parameter
    let sensitivity_filter = match params.sensitivity.as_deref() {
        Some("low") => Some(vellaveto_types::ToolSensitivity::Low),
        Some("medium") => Some(vellaveto_types::ToolSensitivity::Medium),
        Some("high") => Some(vellaveto_types::ToolSensitivity::High),
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid sensitivity; must be one of: low, medium, high".to_string(),
                }),
            ));
        }
        None => None,
    };

    // Get all tool IDs
    let tool_ids = engine.index().tool_ids().map_err(|e| {
        // SECURITY (FIND-R65-001): Redact internal error details.
        tracing::warn!(error = %e, "Failed to list discovery tool IDs");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to list tools".to_string(),
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
                tracing::warn!(tool_id = %tool_id, error = %e, "Failed to read tool from discovery index");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to read tool from discovery index".to_string(),
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

    let tools_value = serde_json::to_value(&tools).map_err(|e| {
        tracing::error!("Failed to serialize discovery tools list: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize tools list".to_string(),
            }),
        )
    })?;
    Ok(Json(json!({
        "tools": tools_value,
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

    // SECURITY (FIND-R46-006): token_budget upper bound
    #[test]
    fn test_search_request_deserialize_large_token_budget() {
        let json = r#"{"query": "test", "token_budget": 999999}"#;
        let req: DiscoverySearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.token_budget, Some(999999));
        // 999999 < MAX_TOKEN_BUDGET (1_000_000), so valid
    }

    #[test]
    fn test_max_token_budget_constant() {
        assert_eq!(MAX_TOKEN_BUDGET, 1_000_000);
    }
}
