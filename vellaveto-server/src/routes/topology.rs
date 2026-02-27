//! Topology management route handlers.
//!
//! Endpoints:
//! - `GET /api/topology` — return current topology snapshot (JSON)
//! - `GET /api/topology/status` — return guard status (loaded/bypassed, fingerprint, counts)
//! - `POST /api/topology/recrawl` — trigger immediate re-crawl
//! - `DELETE /api/topology/servers/{name}` — remove a server from the probe + trigger re-crawl

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// GET /api/topology
///
/// Return the current topology snapshot as JSON.
pub async fn topology_snapshot(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let guard = state.topology_guard.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Topology crawling is not enabled. Set [topology] enabled = true in config."
                    .to_string(),
            }),
        )
    })?;

    // SECURITY (R230-SRV-3): Cap snapshot response to prevent DoS via large topologies.
    const MAX_SNAPSHOT_NODES: usize = 5_000;

    match guard.current() {
        Some(topology) => {
            if topology.node_count() > MAX_SNAPSHOT_NODES {
                return Ok(Json(json!({
                    "status": "truncated",
                    "message": "Topology too large for full snapshot. Use /api/topology/status for summary.",
                    "node_count": topology.node_count(),
                    "edge_count": topology.edge_count(),
                    "server_count": topology.server_count(),
                })));
            }
            let snapshot = topology.to_snapshot();
            Ok(Json(
                serde_json::to_value(snapshot).unwrap_or(json!({"error": "serialization failed"})),
            ))
        }
        None => Ok(Json(json!({
            "status": "bypassed",
            "message": "No topology loaded yet"
        }))),
    }
}

/// GET /api/topology/status
///
/// Return guard status: loaded/bypassed, fingerprint, server/tool counts, crawled_at.
pub async fn topology_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let guard = state.topology_guard.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Topology crawling is not enabled. Set [topology] enabled = true in config."
                    .to_string(),
            }),
        )
    })?;

    match guard.current() {
        Some(topology) => {
            let crawled_at_epoch = topology
                .crawled_at()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            Ok(Json(json!({
                "status": "loaded",
                "fingerprint": topology.fingerprint_hex(),
                "server_count": topology.server_count(),
                "node_count": topology.node_count(),
                "edge_count": topology.edge_count(),
                "tool_count": topology.tool_names().len(),
                "server_names": topology.server_names(),
                "crawled_at_epoch_secs": crawled_at_epoch,
            })))
        }
        None => Ok(Json(json!({
            "status": "bypassed",
            "fingerprint": null,
            "server_count": 0,
            "node_count": 0,
            "edge_count": 0,
            "tool_count": 0,
            "server_names": [],
            "crawled_at_epoch_secs": null,
        }))),
    }
}

/// POST /api/topology/recrawl
///
/// Trigger an immediate re-crawl via the recrawl trigger handle.
pub async fn topology_recrawl(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let trigger = state.recrawl_trigger.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Topology crawling is not enabled or recrawl scheduler not running."
                    .to_string(),
            }),
        )
    })?;

    trigger.notify_one();

    // SECURITY (R230-SRV-4): Audit-log mutating topology actions.
    tracing::info!(action = "topology_recrawl", "Topology re-crawl triggered via REST API");

    Ok(Json(json!({
        "status": "recrawl_triggered",
        "message": "Re-crawl has been triggered. Check /api/topology/status for updated state."
    })))
}

/// DELETE /api/topology/servers/{name}
///
/// Remove a server from the static probe and trigger a re-crawl.
pub async fn topology_remove_server(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Validate path parameter
    crate::routes::validate_path_param(&name, "server name")?;

    let probe = state.topology_probe.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Topology crawling is not enabled.".to_string(),
            }),
        )
    })?;

    // SECURITY (R230-SRV-8): Reject path traversal characters in server name.
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "server name contains invalid characters".to_string(),
            }),
        ));
    }

    let removed = probe.remove_server(&name);

    // SECURITY (R230-SRV-4): Audit-log mutating topology actions.
    tracing::info!(action = "topology_remove_server", server = %name, removed = removed, "Server removal requested via REST API");

    if !removed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Server '{}' not found in topology probe", name),
            }),
        ));
    }

    // Trigger re-crawl if available
    if let Some(ref trigger) = state.recrawl_trigger {
        trigger.notify_one();
    }

    Ok(Json(json!({
        "status": "removed",
        "server": name,
        "message": "Server removed from probe. Re-crawl triggered."
    })))
}
