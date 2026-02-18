//! Tool Registry route handlers.
//!
//! This module provides REST API endpoints for tool registry management,
//! including listing, approval, and revocation of tools.
//!
//! Endpoints:
//! - `GET /api/registry/tools` - List all registered tools
//! - `POST /api/registry/tools/{name}/approve` - Approve a tool
//! - `POST /api/registry/tools/{name}/revoke` - Revoke tool approval

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::json;
use vellaveto_types::{Action, Verdict};

use crate::routes::approval::derive_resolver_identity;
use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum length for tool names in registry operations.
const MAX_TOOL_NAME_LEN: usize = 256;

/// Validate a tool name from a URL path parameter.
fn validate_tool_name(name: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if name.is_empty() || name.len() > MAX_TOOL_NAME_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Tool name must be 1-{} characters", MAX_TOOL_NAME_LEN),
            }),
        ));
    }
    if name.chars().any(crate::routes::is_unsafe_char) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Tool name contains invalid characters".to_string(),
            }),
        ));
    }
    Ok(())
}

/// List all tools in the registry with their trust scores.
///
/// GET /api/registry/tools
///
/// Returns a JSON object with:
/// - `count`: number of registered tools
/// - `trust_threshold`: the configured trust threshold
/// - `tools`: array of tool entries with trust scores
pub async fn list_registry_tools(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let registry = state.tool_registry.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool registry is not enabled".to_string(),
            }),
        )
    })?;

    let tools = registry.list().await;
    let threshold = registry.trust_threshold();

    Ok(Json(json!({
        "count": tools.len(),
        "trust_threshold": threshold,
        "tools": tools,
    })))
}

/// Approve a tool in the registry (set admin_approved = true).
///
/// POST /api/registry/tools/{name}/approve
///
/// Returns the updated tool entry on success.
///
/// # Security
///
/// - Validates tool name for length and control characters
/// - Records the authenticated principal in the audit trail
/// - Persists the change to the registry file
pub async fn approve_registry_tool(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_tool_name(&name)?;

    // SECURITY (R34-SRV-3): Record the authenticated principal in audit trail.
    let approved_by = derive_resolver_identity(&headers, "anonymous");

    let registry = state.tool_registry.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool registry is not enabled".to_string(),
            }),
        )
    })?;

    let entry = registry.approve(&name).await.map_err(|e| match e {
        vellaveto_mcp::tool_registry::RegistryError::NotFound(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Tool '{}' not found in registry", name),
            }),
        ),
        _ => {
            tracing::error!("Registry approve error for '{}': {}", name, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to approve tool".to_string(),
                }),
            )
        }
    })?;

    // Persist the change
    if let Err(e) = registry.persist().await {
        tracing::warn!(
            "Failed to persist registry after approving '{}': {}",
            name,
            e
        );
    }

    // Audit trail
    let action = Action::new(
        "vellaveto",
        "registry_tool_approved",
        json!({
            "tool_id": &name,
            "trust_score": entry.trust_score,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "registry_tool_approved", "approved_by": &approved_by}),
        )
        .await
    {
        tracing::warn!("Failed to audit registry approval for {}: {}", name, e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    let value = serde_json::to_value(&entry).map_err(|e| {
        tracing::error!("Registry entry serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// Revoke admin approval for a tool in the registry (set admin_approved = false).
///
/// POST /api/registry/tools/{name}/revoke
///
/// Returns the updated tool entry on success.
///
/// # Security
///
/// - Validates tool name for length and control characters
/// - Records the authenticated principal in the audit trail
/// - Persists the change to the registry file
pub async fn revoke_registry_tool(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_tool_name(&name)?;

    // SECURITY (R34-SRV-3): Record the authenticated principal in audit trail.
    let revoked_by = derive_resolver_identity(&headers, "anonymous");

    let registry = state.tool_registry.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tool registry is not enabled".to_string(),
            }),
        )
    })?;

    let entry = registry.revoke(&name).await.map_err(|e| match e {
        vellaveto_mcp::tool_registry::RegistryError::NotFound(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Tool '{}' not found in registry", name),
            }),
        ),
        _ => {
            tracing::error!("Registry revoke error for '{}': {}", name, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to revoke tool approval".to_string(),
                }),
            )
        }
    })?;

    // Persist the change
    if let Err(e) = registry.persist().await {
        tracing::warn!(
            "Failed to persist registry after revoking '{}': {}",
            name,
            e
        );
    }

    // Audit trail
    let action = Action::new(
        "vellaveto",
        "registry_tool_revoked",
        json!({
            "tool_id": &name,
            "trust_score": entry.trust_score,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "registry_tool_revoked".to_string(),
            },
            json!({"source": "api", "event": "registry_tool_revoked", "revoked_by": &revoked_by}),
        )
        .await
    {
        tracing::warn!("Failed to audit registry revocation for {}: {}", name, e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    let value = serde_json::to_value(&entry).map_err(|e| {
        tracing::error!("Registry entry serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}
