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
use serde_json::json;
use std::collections::HashMap;
use vellaveto_types::{NhiAttestationType, NhiIdentityStatus};

use crate::AppState;

/// Maximum length for string fields (name, spiffe_id, public_key, etc.).
const MAX_FIELD_LEN: usize = 256;
/// Maximum number of entries in array fields (tags, permissions, scope_constraints).
const MAX_ARRAY_LEN: usize = 100;
/// Maximum number of entries in map fields (metadata).
const MAX_MAP_LEN: usize = 50;
/// Maximum TTL in seconds (1 year). Prevents Duration overflow on arithmetic.
const MAX_TTL_SECS: u64 = 86400 * 365;
/// SECURITY (FIND-R66-001): Maximum entries returned by list endpoints.
const MAX_LIST_ENTRIES: usize = 1000;
/// SECURITY (FIND-R67-004-009): Maximum delegation chain entries returned.
const MAX_CHAIN_DISPLAY: usize = 100;

/// SECURITY (FIND-R43-019, FIND-R44-055): Detect control characters AND Unicode format
/// characters (ZWSP, bidi overrides, invisible operators, TAG characters, soft hyphen)
/// that can bypass simple `is_control()` checks.
///
/// NOTE: This is a local copy mirroring the canonical `is_unsafe_char` in
/// `routes/mod.rs`. Kept local to avoid changing the validate_field helper
/// signature chain in this module. Any updates MUST be applied to all copies.
fn is_unsafe_char(c: char) -> bool {
    let cp = c as u32;
    c.is_control()
        || (0x200B..=0x200F).contains(&cp) // ZWSP, ZWNJ, ZWJ, LRM, RLM
        || (0x202A..=0x202E).contains(&cp) // Bidi overrides
        || (0x2060..=0x2064).contains(&cp) // Word joiner, invisible operators
        || (0x2066..=0x2069).contains(&cp) // Bidi isolates
        || cp == 0xFEFF                    // BOM
        || (0xFFF9..=0xFFFB).contains(&cp) // Interlinear annotation
        || (0xE0001..=0xE007F).contains(&cp) // TAG characters
        || cp == 0x00AD // Soft hyphen
}

/// Validate a string field: reject if too long or contains control/format characters.
/// SECURITY (FIND-R41-011, FIND-R43-019): Rejects ALL control characters AND
/// Unicode format characters to prevent log injection and bidi attacks.
fn validate_string_field(
    value: &str,
    field_name: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if value.len() > MAX_FIELD_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("{} exceeds maximum length of {}", field_name, MAX_FIELD_LEN)
            })),
        ));
    }
    if value.chars().any(is_unsafe_char) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("{} contains invalid characters", field_name)
            })),
        ));
    }
    Ok(())
}

/// Validate an array of strings: reject if too many entries or any entry is invalid.
fn validate_string_array(
    values: &[String],
    field_name: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if values.len() > MAX_ARRAY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("{} exceeds maximum of {} entries", field_name, MAX_ARRAY_LEN)
            })),
        ));
    }
    for (i, v) in values.iter().enumerate() {
        validate_string_field(v, &format!("{}[{}]", field_name, i))?;
    }
    Ok(())
}

/// Validate a map of string key-value pairs: reject if too many entries or any
/// key/value is invalid.
fn validate_string_map(
    map: &HashMap<String, String>,
    field_name: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if map.len() > MAX_MAP_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("{} exceeds maximum of {} entries", field_name, MAX_MAP_LEN)
            })),
        ));
    }
    for (k, v) in map {
        validate_string_field(k, &format!("{}.key", field_name))?;
        validate_string_field(v, &format!("{}[{}]", field_name, k))?;
    }
    Ok(())
}

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
    // SECURITY (FIND-R66-001): Cap response to prevent unbounded serialization.
    let total = agents.len();
    let bounded: Vec<_> = agents.into_iter().take(MAX_LIST_ENTRIES).collect();
    Ok(Json(json!({"agents": bounded, "total": total, "truncated": total > MAX_LIST_ENTRIES})))
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
    validate_string_field(name, "name")?;

    let attestation_type = match body["attestation_type"].as_str().unwrap_or("jwt") {
        "jwt" => NhiAttestationType::Jwt,
        "mtls" => NhiAttestationType::Mtls,
        "spiffe" => NhiAttestationType::Spiffe,
        "dpop" => NhiAttestationType::DPoP,
        "api_key" => NhiAttestationType::ApiKey,
        _ => NhiAttestationType::Jwt,
    };
    let spiffe_id = body["spiffe_id"].as_str();
    if let Some(s) = spiffe_id {
        validate_string_field(s, "spiffe_id")?;
    }
    let public_key = body["public_key"].as_str();
    if let Some(s) = public_key {
        validate_string_field(s, "public_key")?;
    }
    let key_algorithm = body["key_algorithm"].as_str();
    if let Some(s) = key_algorithm {
        validate_string_field(s, "key_algorithm")?;
    }
    let ttl_secs = body["ttl_secs"].as_u64();
    if let Some(secs) = ttl_secs {
        if secs > MAX_TTL_SECS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("ttl_secs must be <= {}", MAX_TTL_SECS)})),
            ));
        }
    }
    let tags: Vec<String> = body["tags"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    validate_string_array(&tags, "tags")?;

    let metadata: HashMap<String, String> = body["metadata"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    validate_string_map(&metadata, "metadata")?;

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
    // SECURITY (FIND-R42-016): Validate path parameter length.
    validate_string_field(&id, "id")?;

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
    validate_string_field(&id, "id")?;

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
    validate_string_field(&id, "id")?;

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
    validate_string_field(&id, "id")?;

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
    validate_string_field(&id, "id")?;

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
    validate_string_field(&id, "id")?;

    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let tool_call = body["tool_call"].as_str().unwrap_or("unknown");
    // SECURITY (FIND-R43-021): Validate body fields.
    validate_string_field(tool_call, "tool_call")?;
    let request_interval = body["request_interval_secs"].as_f64();
    let source_ip = body["source_ip"].as_str();
    // SECURITY (FIND-R43-021): Validate source_ip if present.
    if let Some(ip) = source_ip {
        validate_string_field(ip, "source_ip")?;
    }

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
    // SECURITY (FIND-R43-021): Validate agent_id query parameter if present.
    if let Some(aid) = &agent_id {
        validate_string_field(aid, "agent_id")?;
    }
    let delegations = if let Some(agent) = agent_id {
        manager.list_delegations(agent).await
    } else {
        // Return all delegations for the first agent or empty
        Vec::new()
    };

    // SECURITY (FIND-R66-002): Cap response to prevent unbounded serialization.
    let total = delegations.len();
    let bounded: Vec<_> = delegations.into_iter().take(MAX_LIST_ENTRIES).collect();
    Ok(Json(json!({"delegations": bounded, "total": total, "truncated": total > MAX_LIST_ENTRIES})))
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
    validate_string_field(from_agent, "from_agent")?;

    let to_agent = body["to_agent"].as_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "to_agent required"})),
        )
    })?;
    validate_string_field(to_agent, "to_agent")?;

    // SECURITY (FIND-R43-033, FIND-R44-037): Reject self-delegation.
    // Use case-insensitive comparison consistent with deputy route (FIND-R43-024).
    if from_agent.eq_ignore_ascii_case(to_agent) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "from_agent and to_agent must differ"})),
        ));
    }

    let permissions: Vec<String> = body["permissions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    validate_string_array(&permissions, "permissions")?;

    let scope_constraints: Vec<String> = body["scope_constraints"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    validate_string_array(&scope_constraints, "scope_constraints")?;

    let ttl_secs = body["ttl_secs"].as_u64().unwrap_or(3600);
    if ttl_secs > MAX_TTL_SECS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("ttl_secs must be <= {}", MAX_TTL_SECS)})),
        ));
    }
    let reason = body["reason"].as_str().map(|s| s.to_string());
    if let Some(ref r) = reason {
        validate_string_field(r, "reason")?;
    }

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
    validate_string_field(&from, "from")?;
    validate_string_field(&to, "to")?;

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
    validate_string_field(&from, "from")?;
    validate_string_field(&to, "to")?;

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
    validate_string_field(&id, "id")?;

    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "NHI not enabled"})),
        ));
    };

    let delegation = manager.resolve_delegation_chain(&id).await;
    // SECURITY (FIND-R67-004-009): Bound delegation chain response size.
    let total = delegation.chain.len();
    let truncated = total > MAX_CHAIN_DISPLAY;
    let bounded: Vec<_> = delegation.chain.into_iter().take(MAX_CHAIN_DISPLAY).collect();
    Ok(Json(json!({"chain": bounded, "total": total, "truncated": truncated})))
}

/// Rotate credentials for an NHI agent.
pub async fn rotate_nhi_credentials(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_string_field(&id, "id")?;

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
    // SECURITY (FIND-R43-021): Validate body fields.
    validate_string_field(new_public_key, "new_public_key")?;
    let new_key_algorithm = body["new_key_algorithm"].as_str();
    // SECURITY (FIND-R43-021): Validate new_key_algorithm if present.
    if let Some(alg) = new_key_algorithm {
        validate_string_field(alg, "new_key_algorithm")?;
    }
    let trigger = body["trigger"].as_str().unwrap_or("manual");
    // SECURITY (FIND-R43-021): Validate trigger field.
    validate_string_field(trigger, "trigger")?;
    let new_ttl_secs = body["new_ttl_secs"].as_u64();
    if let Some(secs) = new_ttl_secs {
        if secs > MAX_TTL_SECS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("new_ttl_secs must be <= {}", MAX_TTL_SECS)})),
            ));
        }
    }

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
    // SECURITY (FIND-R67-004-008): Cap response to prevent unbounded serialization.
    let total = expiring.len();
    let bounded: Vec<_> = expiring.into_iter().take(MAX_LIST_ENTRIES).collect();
    Ok(Json(json!({"expiring": bounded, "total": total, "truncated": total > MAX_LIST_ENTRIES})))
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

#[cfg(test)]
mod tests {
    use super::*;

    // ═══════════════════════════════════════════════════════
    // FIND-R44-055: is_unsafe_char must detect TAG characters and soft hyphen
    // ═══════════════════════════════════════════════════════

    /// FIND-R44-055: TAG characters (U+E0001..U+E007F) must be detected as unsafe.
    #[test]
    fn test_is_unsafe_char_tag_characters() {
        assert!(
            is_unsafe_char('\u{E0001}'),
            "LANGUAGE TAG must be detected as unsafe"
        );
        assert!(
            is_unsafe_char('\u{E0020}'),
            "TAG SPACE must be detected as unsafe"
        );
        assert!(
            is_unsafe_char('\u{E007F}'),
            "CANCEL TAG must be detected as unsafe"
        );
    }

    /// FIND-R44-055: Soft hyphen (U+00AD) must be detected as unsafe.
    #[test]
    fn test_is_unsafe_char_soft_hyphen() {
        assert!(
            is_unsafe_char('\u{00AD}'),
            "Soft hyphen must be detected as unsafe"
        );
    }

    /// FIND-R44-037: Self-delegation must be case-insensitive.
    #[test]
    fn test_self_delegation_case_insensitive() {
        // Simulating the check that would happen in the route handler
        let from = "AgentAlpha";
        let to = "agentalpha";
        assert!(
            from.eq_ignore_ascii_case(to),
            "Case-insensitive comparison must detect self-delegation"
        );

        let from2 = "AGENT";
        let to2 = "agent";
        assert!(
            from2.eq_ignore_ascii_case(to2),
            "All-caps vs lowercase must match"
        );

        let from3 = "agentA";
        let to3 = "agentB";
        assert!(
            !from3.eq_ignore_ascii_case(to3),
            "Different agents must not match"
        );
    }

    /// Regression: existing unsafe chars still detected.
    #[test]
    fn test_is_unsafe_char_existing_ranges() {
        assert!(is_unsafe_char('\0'));
        assert!(is_unsafe_char('\u{200B}'));
        assert!(is_unsafe_char('\u{202E}'));
        assert!(is_unsafe_char('\u{FEFF}'));
        assert!(!is_unsafe_char('a'));
        assert!(!is_unsafe_char('-'));
    }
}
