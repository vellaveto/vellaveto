// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

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
use serde::Deserialize;
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

// SECURITY (IMP-R106-001): Use canonical is_unsafe_char from routes/mod.rs.
use super::is_unsafe_char;

// ═══════════════════════════════════════════════════════
// SECURITY (FIND-R117-SP-002): Typed query structs for GET handlers.
// ═══════════════════════════════════════════════════════

/// Query parameters for listing NHI agents.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListNhiAgentsQuery {
    pub status: Option<String>,
}

/// Query parameters for listing NHI delegations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListNhiDelegationsQuery {
    pub agent_id: Option<String>,
}

// ═══════════════════════════════════════════════════════
// SECURITY (FIND-R117-SP-001): Typed request structs for POST handlers.
// ═══════════════════════════════════════════════════════

/// Request body for registering a new NHI agent identity.
///
/// SECURITY (FIND-R155-003): Custom Debug redacts `public_key` to prevent
/// cryptographic material from leaking into logs (Trap 6).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterNhiAgentRequest {
    pub name: Option<String>,
    pub attestation_type: Option<String>,
    pub spiffe_id: Option<String>,
    pub public_key: Option<String>,
    pub key_algorithm: Option<String>,
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl std::fmt::Debug for RegisterNhiAgentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterNhiAgentRequest")
            .field("name", &self.name)
            .field("attestation_type", &self.attestation_type)
            .field("spiffe_id", &self.spiffe_id)
            .field(
                "public_key",
                &self.public_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("key_algorithm", &self.key_algorithm)
            .field("ttl_secs", &self.ttl_secs)
            .field("tags", &self.tags)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Request body for checking NHI agent behavior against baseline.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckNhiBehaviorRequest {
    pub tool_call: Option<String>,
    pub request_interval_secs: Option<f64>,
    pub source_ip: Option<String>,
}

/// Request body for creating an NHI delegation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNhiDelegationRequest {
    pub from_agent: String,
    pub to_agent: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub scope_constraints: Vec<String>,
    pub ttl_secs: Option<u64>,
    pub reason: Option<String>,
}

/// Request body for rotating NHI agent credentials.
///
/// SECURITY (FIND-R155-003): Custom Debug redacts `new_public_key` to prevent
/// cryptographic material from leaking into logs (Trap 6).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateNhiCredentialsRequest {
    pub new_public_key: String,
    pub new_key_algorithm: Option<String>,
    pub trigger: Option<String>,
    pub new_ttl_secs: Option<u64>,
}

impl std::fmt::Debug for RotateNhiCredentialsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateNhiCredentialsRequest")
            .field("new_public_key", &"[REDACTED]")
            .field("new_key_algorithm", &self.new_key_algorithm)
            .field("trigger", &self.trigger)
            .field("new_ttl_secs", &self.new_ttl_secs)
            .finish()
    }
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
        validate_string_field(v, &format!("{field_name}[{i}]"))?;
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
        validate_string_field(k, &format!("{field_name}.key"))?;
        validate_string_field(v, &format!("{field_name}[{k}]"))?;
    }
    Ok(())
}

/// Parse optional NHI status filter from query parameter.
/// SECURITY (FIND-R71-SRV-005): Unknown values are rejected (fail-closed).
fn parse_status_filter(
    status: Option<&str>,
) -> Result<Option<NhiIdentityStatus>, (StatusCode, Json<serde_json::Value>)> {
    match status {
        Some("active") => Ok(Some(NhiIdentityStatus::Active)),
        Some("suspended") => Ok(Some(NhiIdentityStatus::Suspended)),
        Some("revoked") => Ok(Some(NhiIdentityStatus::Revoked)),
        Some("expired") => Ok(Some(NhiIdentityStatus::Expired)),
        Some("probationary") => Ok(Some(NhiIdentityStatus::Probationary)),
        // SECURITY (FIND-R108-002): Do not echo raw user input in error responses.
        Some(_other) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid status filter: valid values are active, suspended, revoked, expired, probationary"
            })),
        )),
        None => Ok(None),
    }
}

/// Parse NHI attestation type from request body value.
/// SECURITY (FIND-R71-SRV-003): Unknown values are rejected (fail-closed).
fn parse_attestation_type(
    value: Option<&str>,
) -> Result<NhiAttestationType, (StatusCode, Json<serde_json::Value>)> {
    match value.unwrap_or("jwt") {
        "jwt" => Ok(NhiAttestationType::Jwt),
        "mtls" => Ok(NhiAttestationType::Mtls),
        "spiffe" => Ok(NhiAttestationType::Spiffe),
        "dpop" => Ok(NhiAttestationType::DPoP),
        "api_key" => Ok(NhiAttestationType::ApiKey),
        // SECURITY (FIND-R108-002): Do not echo raw user input in error responses.
        _other => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid attestation_type: valid values are jwt, mtls, spiffe, dpop, api_key"
            })),
        )),
    }
}

/// Validate request interval input for behavior checks.
/// SECURITY (FIND-R71-SRV-004): Reject negative or non-finite values.
fn validate_request_interval(
    interval: Option<f64>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if let Some(interval) = interval {
        if !interval.is_finite() || interval < 0.0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "request_interval_secs must be a non-negative finite number"
                })),
            ));
        }
    }
    Ok(())
}

/// List all NHI agent identities.
pub async fn list_nhi_agents(
    State(state): State<AppState>,
    Query(params): Query<ListNhiAgentsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    let status_filter = parse_status_filter(params.status.as_deref())?;

    let agents = manager.list_identities(status_filter).await;
    // SECURITY (FIND-R66-001): Cap response to prevent unbounded serialization.
    let total = agents.len();
    let bounded: Vec<_> = agents.into_iter().take(MAX_LIST_ENTRIES).collect();
    Ok(Json(
        json!({"agents": bounded, "total": total, "truncated": total > MAX_LIST_ENTRIES}),
    ))
}

/// Register a new NHI agent identity.
pub async fn register_nhi_agent(
    State(state): State<AppState>,
    Json(body): Json<RegisterNhiAgentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    let name = body.name.as_deref().unwrap_or("unnamed");
    validate_string_field(name, "name")?;

    let attestation_type = parse_attestation_type(body.attestation_type.as_deref())?;
    let spiffe_id = body.spiffe_id.as_deref();
    if let Some(s) = spiffe_id {
        validate_string_field(s, "spiffe_id")?;
    }
    let public_key = body.public_key.as_deref();
    if let Some(s) = public_key {
        validate_string_field(s, "public_key")?;
    }
    let key_algorithm = body.key_algorithm.as_deref();
    if let Some(s) = key_algorithm {
        validate_string_field(s, "key_algorithm")?;
    }
    let ttl_secs = body.ttl_secs;
    if let Some(secs) = ttl_secs {
        if secs > MAX_TTL_SECS {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("ttl_secs must be <= {}", MAX_TTL_SECS)})),
            ));
        }
    }
    validate_string_array(&body.tags, "tags")?;
    validate_string_map(&body.metadata, "metadata")?;

    match manager
        .register_identity(
            name,
            attestation_type,
            spiffe_id,
            public_key,
            key_algorithm,
            ttl_secs,
            body.tags,
            body.metadata,
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
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
    Json(body): Json<CheckNhiBehaviorRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_string_field(&id, "id")?;

    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    let tool_call = body.tool_call.as_deref().unwrap_or("unknown");
    // SECURITY (FIND-R43-021): Validate body fields.
    validate_string_field(tool_call, "tool_call")?;
    validate_request_interval(body.request_interval_secs)?;
    // SECURITY (FIND-R43-021): Validate source_ip if present.
    if let Some(ref ip) = body.source_ip {
        validate_string_field(ip, "source_ip")?;
    }

    let result = manager
        .check_behavior(
            &id,
            tool_call,
            body.request_interval_secs,
            body.source_ip.as_deref(),
        )
        .await;
    Ok(Json(json!({"result": result})))
}

/// List NHI delegations.
pub async fn list_nhi_delegations(
    State(state): State<AppState>,
    Query(params): Query<ListNhiDelegationsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    // SECURITY (FIND-R43-021): Validate agent_id query parameter if present.
    if let Some(ref aid) = params.agent_id {
        validate_string_field(aid, "agent_id")?;
    }
    let delegations = if let Some(ref agent) = params.agent_id {
        manager.list_delegations(agent).await
    } else {
        // Return all delegations for the first agent or empty
        Vec::new()
    };

    // SECURITY (FIND-R66-002): Cap response to prevent unbounded serialization.
    let total = delegations.len();
    let bounded: Vec<_> = delegations.into_iter().take(MAX_LIST_ENTRIES).collect();
    Ok(Json(
        json!({"delegations": bounded, "total": total, "truncated": total > MAX_LIST_ENTRIES}),
    ))
}

/// Create an NHI delegation.
pub async fn create_nhi_delegation(
    State(state): State<AppState>,
    Json(body): Json<CreateNhiDelegationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    validate_string_field(&body.from_agent, "from_agent")?;
    validate_string_field(&body.to_agent, "to_agent")?;

    // SECURITY (FIND-R43-033, FIND-R44-037, FIND-R184-001): Reject self-delegation.
    // Use homoglyph-aware comparison — eq_ignore_ascii_case misses Cyrillic confusables.
    // Parity with vellaveto-approval self-approval check (FIND-R58-CFG-001).
    let from_norm = vellaveto_types::unicode::normalize_identity(&body.from_agent);
    let to_norm = vellaveto_types::unicode::normalize_identity(&body.to_agent);
    if from_norm == to_norm {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "from_agent and to_agent must differ"})),
        ));
    }

    validate_string_array(&body.permissions, "permissions")?;
    validate_string_array(&body.scope_constraints, "scope_constraints")?;

    let ttl_secs = body.ttl_secs.unwrap_or(3600);
    if ttl_secs > MAX_TTL_SECS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("ttl_secs must be <= {}", MAX_TTL_SECS)})),
        ));
    }
    if let Some(ref r) = body.reason {
        validate_string_field(r, "reason")?;
    }

    match manager
        .create_delegation(
            &body.from_agent,
            &body.to_agent,
            body.permissions,
            body.scope_constraints,
            ttl_secs,
            body.reason,
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    let delegation = manager.resolve_delegation_chain(&id).await;
    // SECURITY (FIND-R67-004-009): Bound delegation chain response size.
    let total = delegation.chain.len();
    let truncated = total > MAX_CHAIN_DISPLAY;
    let bounded: Vec<_> = delegation
        .chain
        .into_iter()
        .take(MAX_CHAIN_DISPLAY)
        .collect();
    Ok(Json(
        json!({"chain": bounded, "total": total, "truncated": truncated}),
    ))
}

/// Rotate credentials for an NHI agent.
pub async fn rotate_nhi_credentials(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<RotateNhiCredentialsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    validate_string_field(&id, "id")?;

    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    // SECURITY (FIND-R43-021): Validate body fields.
    validate_string_field(&body.new_public_key, "new_public_key")?;
    // SECURITY (FIND-R43-021): Validate new_key_algorithm if present.
    if let Some(ref alg) = body.new_key_algorithm {
        validate_string_field(alg, "new_key_algorithm")?;
    }
    let trigger = body.trigger.as_deref().unwrap_or("manual");
    // SECURITY (FIND-R43-021): Validate trigger field.
    validate_string_field(trigger, "trigger")?;
    if let Some(secs) = body.new_ttl_secs {
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
            &body.new_public_key,
            body.new_key_algorithm.as_deref(),
            trigger,
            body.new_ttl_secs,
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
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    let expiring = manager.get_expiring_identities().await;
    // SECURITY (FIND-R67-004-008): Cap response to prevent unbounded serialization.
    let total = expiring.len();
    let bounded: Vec<_> = expiring.into_iter().take(MAX_LIST_ENTRIES).collect();
    Ok(Json(
        json!({"expiring": bounded, "total": total, "truncated": total > MAX_LIST_ENTRIES}),
    ))
}

/// Generate a DPoP nonce.
pub async fn generate_dpop_nonce(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
        ));
    };

    // SECURITY (R239-SRV-5): Genericize error — do not expose capacity details to clients.
    let nonce = manager.generate_dpop_nonce().await.map_err(|e| {
        tracing::warn!("DPoP nonce generation failed: {}", e);
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "DPoP nonce generation temporarily unavailable"})),
        )
    })?;
    Ok(Json(json!({"nonce": nonce})))
}

/// Get NHI statistics.
pub async fn nhi_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref manager) = state.nhi else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error": "NHI (Non-Human Identity) management is not enabled. Set [nhi] verification.enabled = true in your config file and restart the server."}),
            ),
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

    /// FIND-R44-037, IMP-R184-001: Self-delegation must be homoglyph-aware.
    #[test]
    fn test_self_delegation_homoglyph_aware() {
        use vellaveto_types::unicode::normalize_identity;

        // Case-insensitive via normalize_identity
        assert_eq!(
            normalize_identity("AgentAlpha"),
            normalize_identity("agentalpha"),
            "Case-insensitive comparison must detect self-delegation"
        );

        assert_eq!(
            normalize_identity("AGENT"),
            normalize_identity("agent"),
            "All-caps vs lowercase must match"
        );

        assert_ne!(
            normalize_identity("agentA"),
            normalize_identity("agentB"),
            "Different agents must not match"
        );

        // FIND-R184-001: Cyrillic homoglyph bypass
        // Cyrillic 'а' (U+0430) must be detected as identical to Latin 'a'
        assert_eq!(
            normalize_identity("\u{0430}gent"),
            normalize_identity("agent"),
            "Cyrillic homoglyph must be detected as self-delegation"
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

    #[test]
    fn test_parse_status_filter_rejects_unknown() {
        let err =
            parse_status_filter(Some("unknown")).expect_err("unknown status must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let body = err.1 .0;
        let msg = body["error"]
            .as_str()
            .expect("error field should be a string");
        assert!(msg.contains("invalid status filter"));
    }

    #[test]
    fn test_parse_status_filter_accepts_known_and_none() {
        assert!(matches!(
            parse_status_filter(Some("active")).expect("valid status"),
            Some(NhiIdentityStatus::Active)
        ));
        assert!(parse_status_filter(None)
            .expect("none should be accepted")
            .is_none());
    }

    #[test]
    fn test_parse_attestation_type_rejects_unknown() {
        let err = parse_attestation_type(Some("magic")).expect_err("unknown attestation must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let body = err.1 .0;
        let msg = body["error"]
            .as_str()
            .expect("error field should be a string");
        assert!(msg.contains("invalid attestation_type"));
    }

    #[test]
    fn test_parse_attestation_type_defaults_to_jwt() {
        assert!(matches!(
            parse_attestation_type(None).expect("default should parse"),
            NhiAttestationType::Jwt
        ));
        assert!(matches!(
            parse_attestation_type(Some("dpop")).expect("dpop should parse"),
            NhiAttestationType::DPoP
        ));
    }

    #[test]
    fn test_validate_request_interval_rejects_negative() {
        let err =
            validate_request_interval(Some(-0.1)).expect_err("negative interval must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_request_interval_accepts_non_negative_or_absent() {
        assert!(validate_request_interval(Some(0.0)).is_ok());
        assert!(validate_request_interval(Some(1.5)).is_ok());
        assert!(validate_request_interval(None).is_ok());
    }
}
