//! Memory Injection Defense (MINJA) route handlers.
//!
//! This module provides REST API endpoints for memory security management
//! including entry inspection, quarantine, provenance tracking, and namespaces.
//!
//! Endpoints:
//! - `GET /api/memory/entries` - List memory entries with filters
//! - `GET /api/memory/entries/{id}` - Get specific memory entry
//! - `POST /api/memory/entries/{id}/quarantine` - Quarantine an entry
//! - `POST /api/memory/entries/{id}/release` - Release from quarantine
//! - `GET /api/memory/integrity/{session}` - Verify memory integrity for a session
//! - `GET /api/memory/provenance/{id}` - Get entry provenance
//! - `GET /api/memory/namespaces` - List namespaces
//! - `POST /api/memory/namespaces` - Create namespace
//! - `POST /api/memory/namespaces/{id}/share` - Request namespace sharing
//! - `GET /api/memory/stats` - Get memory security statistics

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use vellaveto_types::{NamespaceAccessType, QuarantineDetection};

use crate::AppState;

/// Query parameters for listing memory entries.
#[derive(Debug, Deserialize)]
pub struct ListMemoryEntriesQuery {
    pub session_id: Option<String>,
    pub quarantined_only: Option<bool>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// List memory entries with optional filters.
pub async fn list_memory_entries(
    State(state): State<AppState>,
    Query(params): Query<ListMemoryEntriesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);
    let quarantined_only = params.quarantined_only.unwrap_or(false);

    let entries = manager
        .list_entries(
            params.session_id.as_deref(),
            quarantined_only,
            limit,
            offset,
        )
        .await;

    Ok(Json(json!({
        "count": entries.len(),
        "entries": entries,
        "offset": offset,
        "limit": limit,
    })))
}

/// Get a specific memory entry by ID.
pub async fn get_memory_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    match manager.get_entry(&id).await {
        Some(entry) => Ok(Json(json!({"entry": entry}))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Memory entry not found"})),
        )),
    }
}

/// Request body for quarantine action.
#[derive(Debug, Deserialize)]
pub struct QuarantineRequest {
    pub reason: Option<String>,
    pub triggered_by: Option<String>,
}

/// Quarantine a memory entry.
pub async fn quarantine_memory_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<QuarantineRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    let reason = body
        .reason
        .unwrap_or_else(|| "Manual quarantine via API".to_string());

    let result = manager
        .quarantine_entry(
            &id,
            QuarantineDetection::ManualQuarantine,
            body.triggered_by.as_deref(),
        )
        .await;

    match result {
        Ok(()) => Ok(Json(json!({
            "success": true,
            "message": format!("Entry '{}' quarantined", id),
            "reason": reason,
        }))),
        Err(vellaveto_mcp::memory_security::MemorySecurityError::EntryNotFound(_)) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Entry '{}' not found", id)})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

/// Release a memory entry from quarantine.
pub async fn release_memory_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    match manager.release_entry(&id).await {
        Ok(()) => Ok(Json(json!({
            "success": true,
            "message": format!("Entry '{}' released from quarantine", id),
        }))),
        Err(vellaveto_mcp::memory_security::MemorySecurityError::EntryNotFound(_)) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Entry '{}' not found", id)})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

/// Verify memory integrity for a session.
pub async fn verify_memory_integrity(
    State(state): State<AppState>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    let report = manager.verify_session_integrity(&session).await;
    Ok(Json(json!({ "report": report })))
}

/// Get provenance chain for a memory entry.
pub async fn get_memory_provenance(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    let chain = manager.get_provenance_chain(&id).await;
    Ok(Json(json!({
        "entry_id": id,
        "chain_length": chain.len(),
        "provenance": chain,
    })))
}

/// List memory namespaces.
pub async fn list_memory_namespaces(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    let namespaces = manager.list_namespaces().await;
    Ok(Json(json!({
        "count": namespaces.len(),
        "namespaces": namespaces,
    })))
}

/// Request body for creating a namespace.
#[derive(Debug, Deserialize)]
pub struct CreateNamespaceRequest {
    #[serde(alias = "id")]
    pub name: String,
    #[serde(default)]
    #[serde(alias = "owner_agent")]
    pub owner: Option<String>,
    #[serde(default)]
    pub isolation_level: Option<String>,
}

/// Create a new memory namespace.
pub async fn create_memory_namespace(
    State(state): State<AppState>,
    Json(body): Json<CreateNamespaceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    // Keep backward compatibility with older request shape:
    // `name` is used as namespace ID, and owner defaults to "api".
    let owner = body.owner.as_deref().unwrap_or("api");
    match manager.create_namespace(&body.name, owner).await {
        Ok(ns) => Ok(Json(json!({
            "success": true,
            "namespace": ns,
        }))),
        Err(vellaveto_mcp::memory_security::MemorySecurityError::AlreadyExists(id)) => Err((
            StatusCode::CONFLICT,
            Json(json!({"error": format!("Namespace '{}' already exists", id)})),
        )),
        Err(vellaveto_mcp::memory_security::MemorySecurityError::CapacityExceeded(msg)) => {
            Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": msg}))))
        }
        Err(vellaveto_mcp::memory_security::MemorySecurityError::NamespacesDisabled) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Namespaces are disabled"})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

/// Request body for sharing a namespace.
#[derive(Debug, Deserialize)]
pub struct ShareNamespaceRequest {
    #[serde(alias = "requester_agent")]
    pub target_agent: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub access_type: Option<String>,
}

fn parse_access_type(value: &str) -> Option<NamespaceAccessType> {
    match value.to_ascii_lowercase().as_str() {
        "read" => Some(NamespaceAccessType::Read),
        "write" => Some(NamespaceAccessType::Write),
        "full" => Some(NamespaceAccessType::Full),
        _ => None,
    }
}

fn permissions_to_access_type(permissions: &[String]) -> Result<NamespaceAccessType, &'static str> {
    let mut has_write = false;

    for permission in permissions {
        match permission.to_ascii_lowercase().as_str() {
            "read" => {}
            "write" => has_write = true,
            "full" => return Ok(NamespaceAccessType::Full),
            _ => {
                return Err("Invalid permission. Allowed values: read, write, full");
            }
        }
    }

    if has_write {
        Ok(NamespaceAccessType::Write)
    } else {
        Ok(NamespaceAccessType::Read)
    }
}

/// Request sharing access to a namespace.
pub async fn share_memory_namespace(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ShareNamespaceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    let access_type = if let Some(access_type_str) = body.access_type.as_deref() {
        match parse_access_type(access_type_str) {
            Some(v) => v,
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"error": "Invalid access_type. Must be 'read', 'write', or 'full'"}),
                    ),
                ))
            }
        }
    } else {
        match permissions_to_access_type(&body.permissions) {
            Ok(v) => v,
            Err(e) => return Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
        }
    };

    match manager
        .request_share(&id, &body.target_agent, access_type)
        .await
    {
        Ok(request) => Ok(Json(json!({
            "success": true,
            "request": request,
            "namespace_id": id,
            "requester_agent": body.target_agent,
            "permissions": body.permissions,
        }))),
        Err(vellaveto_mcp::memory_security::MemorySecurityError::NamespacesDisabled) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Namespaces are disabled"})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

/// Get memory security statistics.
pub async fn memory_security_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.memory_security else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Memory security not enabled"})),
        ));
    };

    let stats = manager.get_stats().await;
    Ok(Json(json!({
        "stats": stats,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_namespace_request_accepts_legacy_shape() {
        let req: CreateNamespaceRequest =
            serde_json::from_value(json!({"id": "ns-legacy", "owner_agent": "agent-a"}))
                .expect("legacy shape should deserialize");
        assert_eq!(req.name, "ns-legacy");
        assert_eq!(req.owner.as_deref(), Some("agent-a"));
    }

    #[test]
    fn create_namespace_request_accepts_current_shape() {
        let req: CreateNamespaceRequest =
            serde_json::from_value(json!({"name": "ns-current", "owner": "agent-b"}))
                .expect("current shape should deserialize");
        assert_eq!(req.name, "ns-current");
        assert_eq!(req.owner.as_deref(), Some("agent-b"));
    }

    #[test]
    fn share_namespace_request_accepts_requester_agent_alias() {
        let req: ShareNamespaceRequest = serde_json::from_value(json!({
            "requester_agent": "agent-c",
            "access_type": "write"
        }))
        .expect("requester_agent alias should deserialize");
        assert_eq!(req.target_agent, "agent-c");
        assert_eq!(req.access_type.as_deref(), Some("write"));
    }

    #[test]
    fn permissions_to_access_type_rejects_unknown_values() {
        let result = permissions_to_access_type(&["execute".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_access_type_accepts_valid_values() {
        assert!(matches!(
            parse_access_type("read"),
            Some(NamespaceAccessType::Read)
        ));
        assert!(matches!(
            parse_access_type("WRITE"),
            Some(NamespaceAccessType::Write)
        ));
        assert!(matches!(
            parse_access_type("full"),
            Some(NamespaceAccessType::Full)
        ));
        assert!(parse_access_type("invalid").is_none());
    }
}
