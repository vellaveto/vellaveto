//! Non-Human Identity (NHI) Lifecycle route handlers.
//!
//! This module provides REST API endpoints for NHI agent identity management
//! including registration, status changes, delegations, and behavioral baselines.
//!
//! Endpoints:
//! - `GET /api/nhi/agents` - List NHI agents
//! - `POST /api/nhi/agents` - Register new agent
//! - `GET /api/nhi/agents/{id}` - Get agent details
//! - `DELETE /api/nhi/agents/{id}` - Revoke agent
//! - `POST /api/nhi/agents/{id}/activate` - Activate agent
//! - `POST /api/nhi/agents/{id}/suspend` - Suspend agent
//! - `GET /api/nhi/agents/{id}/baseline` - Get behavioral baseline
//! - `POST /api/nhi/agents/{id}/check` - Check behavior against baseline
//! - `GET /api/nhi/delegations` - List delegations
//! - `POST /api/nhi/delegations` - Create delegation
//! - `GET /api/nhi/delegations/{from}/{to}` - Get delegation
//! - `DELETE /api/nhi/delegations/{from}/{to}` - Revoke delegation
//! - `GET /api/nhi/delegations/{id}/chain` - Get delegation chain
//! - `POST /api/nhi/agents/{id}/rotate` - Rotate credentials
//! - `GET /api/nhi/expiring` - Get expiring identities
//! - `POST /api/nhi/dpop/nonce` - Generate DPoP nonce
//! - `GET /api/nhi/stats` - Get NHI statistics

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use sentinel_types::{NhiAttestationType, NhiIdentityStatus};
use serde_json::json;
use std::collections::HashMap;

use crate::AppState;

/// List all NHI agent identities.
pub async fn list_nhi_agents(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let status_filter = params.get("status").and_then(|s| match s.as_str() {
        "active" => Some(NhiIdentityStatus::Active),
        "suspended" => Some(NhiIdentityStatus::Suspended),
        "revoked" => Some(NhiIdentityStatus::Revoked),
        "expired" => Some(NhiIdentityStatus::Expired),
        "probationary" => Some(NhiIdentityStatus::Probationary),
        _ => None,
    });

    let agents = manager.list_identities(status_filter).await;
    Ok(Json(json!({"agents": agents})))
}

/// Register a new NHI agent identity.
pub async fn register_nhi_agent(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let name = body["name"].as_str().unwrap_or("unnamed");
    let attestation_type = match body["attestation_type"].as_str().unwrap_or("jwt") {
        "jwt" => NhiAttestationType::Jwt,
        "mtls" => NhiAttestationType::Mtls,
        "spiffe" => NhiAttestationType::Spiffe,
        "dpop" => NhiAttestationType::DPoP,
        "api_key" => NhiAttestationType::ApiKey,
        _ => NhiAttestationType::Jwt,
    };
    let spiffe_id = body["spiffe_id"].as_str();
    let public_key = body["public_key"].as_str();
    let key_algorithm = body["key_algorithm"].as_str();
    let ttl_secs = body["ttl_secs"].as_u64();
    let tags: Vec<String> = body["tags"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let metadata: HashMap<String, String> = body["metadata"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    match manager
        .register_identity(
            name,
            attestation_type,
            spiffe_id,
            public_key,
            key_algorithm,
            ttl_secs,
            tags,
            metadata,
        )
        .await
    {
        Ok(id) => Ok(Json(json!({"id": id, "status": "registered"}))),
        Err(e) => {
            tracing::warn!("NHI operation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            ))
        }
    }
}

/// Get a specific NHI agent identity.
pub async fn get_nhi_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    match manager.get_identity(&id).await {
        Some(agent) => Ok(Json(json!({"agent": agent}))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Agent not found"})),
        )),
    }
}

/// Revoke an NHI agent identity.
pub async fn revoke_nhi_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    match manager.update_status(&id, NhiIdentityStatus::Revoked).await {
        Ok(()) => Ok(Json(json!({"status": "revoked"}))),
        Err(e) => {
            tracing::warn!("NHI operation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            ))
        }
    }
}

/// Activate an NHI agent identity.
pub async fn activate_nhi_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    match manager.activate_identity(&id).await {
        Ok(()) => Ok(Json(json!({"status": "active"}))),
        Err(e) => {
            tracing::warn!("NHI operation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            ))
        }
    }
}

/// Suspend an NHI agent identity.
pub async fn suspend_nhi_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    match manager
        .update_status(&id, NhiIdentityStatus::Suspended)
        .await
    {
        Ok(()) => Ok(Json(json!({"status": "suspended"}))),
        Err(e) => {
            tracing::warn!("NHI operation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            ))
        }
    }
}

/// Get the behavioral baseline for an NHI agent.
pub async fn get_nhi_baseline(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    match manager.get_baseline(&id).await {
        Some(baseline) => Ok(Json(json!({"baseline": baseline}))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No baseline for agent"})),
        )),
    }
}

/// Check behavior against baseline for an NHI agent.
pub async fn check_nhi_behavior(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let tool_call = body["tool_call"].as_str().unwrap_or("unknown");
    let request_interval = body["request_interval_secs"].as_f64();
    let source_ip = body["source_ip"].as_str();

    let result = manager
        .check_behavior(&id, tool_call, request_interval, source_ip)
        .await;
    Ok(Json(json!({"result": result})))
}

/// List NHI delegations.
pub async fn list_nhi_delegations(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let agent_id = params.get("agent_id");
    let delegations = if let Some(agent) = agent_id {
        manager.list_delegations(agent).await
    } else {
        // Return all delegations for the first agent or empty
        Vec::new()
    };

    Ok(Json(json!({"delegations": delegations})))
}

/// Create an NHI delegation.
pub async fn create_nhi_delegation(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let from_agent = body["from_agent"].as_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "from_agent required"})),
        )
    })?;
    let to_agent = body["to_agent"].as_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "to_agent required"})),
        )
    })?;
    let permissions: Vec<String> = body["permissions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let scope_constraints: Vec<String> = body["scope_constraints"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let ttl_secs = body["ttl_secs"].as_u64().unwrap_or(3600);
    let reason = body["reason"].as_str().map(|s| s.to_string());

    match manager
        .create_delegation(
            from_agent,
            to_agent,
            permissions,
            scope_constraints,
            ttl_secs,
            reason,
        )
        .await
    {
        Ok(delegation) => Ok(Json(json!({"delegation": delegation}))),
        Err(e) => {
            tracing::warn!("NHI operation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            ))
        }
    }
}

/// Get a specific NHI delegation.
pub async fn get_nhi_delegation(
    State(state): State<AppState>,
    Path((from, to)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    match manager.get_delegation(&from, &to).await {
        Some(delegation) => Ok(Json(json!({"delegation": delegation}))),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Delegation not found"})),
        )),
    }
}

/// Revoke an NHI delegation.
pub async fn revoke_nhi_delegation(
    State(state): State<AppState>,
    Path((from, to)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    match manager.revoke_delegation(&from, &to).await {
        Ok(()) => Ok(Json(json!({"status": "revoked"}))),
        Err(e) => {
            tracing::warn!("NHI operation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            ))
        }
    }
}

/// Get the full delegation chain for an agent.
pub async fn get_nhi_delegation_chain(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let chain = manager.resolve_delegation_chain(&id).await;
    Ok(Json(json!({"chain": chain})))
}

/// Rotate credentials for an NHI agent.
pub async fn rotate_nhi_credentials(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let new_public_key = body["new_public_key"].as_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "new_public_key required"})),
        )
    })?;
    let new_key_algorithm = body["new_key_algorithm"].as_str();
    let trigger = body["trigger"].as_str().unwrap_or("manual");
    let new_ttl_secs = body["new_ttl_secs"].as_u64();

    match manager
        .rotate_credentials(
            &id,
            new_public_key,
            new_key_algorithm,
            trigger,
            new_ttl_secs,
        )
        .await
    {
        Ok(rotation) => Ok(Json(json!({"rotation": rotation}))),
        Err(e) => {
            tracing::warn!("NHI operation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid request"})),
            ))
        }
    }
}

/// Get identities expiring within the warning window.
pub async fn get_expiring_nhi_identities(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let expiring = manager.get_expiring_identities().await;
    Ok(Json(json!({"expiring": expiring})))
}

/// Generate a DPoP nonce.
pub async fn generate_dpop_nonce(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let nonce = manager.generate_dpop_nonce().await;
    Ok(Json(json!({"nonce": nonce})))
}

/// Get NHI statistics.
pub async fn nhi_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let stats = manager.stats().await;
    Ok(Json(json!({"stats": stats})))
}
