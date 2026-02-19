//! ETDI Cryptographic Tool Security route handlers.
//!
//! This module provides REST API endpoints for ETDI (Enhanced Tool Definition
//! Interface) cryptographic security features including tool signatures,
//! attestation chains, and version pinning.
//!
//! Endpoints:
//! - `GET /api/etdi/signatures` - List all tool signatures
//! - `GET /api/etdi/signatures/{tool}` - Get signature for a tool
//! - `POST /api/etdi/signatures/{tool}/verify` - Verify tool signature
//! - `GET /api/etdi/attestations` - List all attestations
//! - `GET /api/etdi/attestations/{tool}` - Get attestation chain for a tool
//! - `GET /api/etdi/attestations/{tool}/verify` - Verify attestation chain
//! - `GET /api/etdi/pins` - List all version pins
//! - `GET /api/etdi/pins/{tool}` - Get version pin for a tool
//! - `POST /api/etdi/pins/{tool}` - Create version pin
//! - `DELETE /api/etdi/pins/{tool}` - Remove version pin

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

/// SECURITY (FIND-R67-004-003): Maximum number of signatures returned by list endpoint.
const MAX_SIGNATURES_LIST: usize = 1000;
/// SECURITY (FIND-R67-004-004): Maximum number of attestations returned by list endpoint.
const MAX_ATTESTATIONS_LIST: usize = 1000;
/// SECURITY (FIND-R67-004-005): Maximum number of version pins returned by list endpoint.
const MAX_PINS_LIST: usize = 1000;

/// List all tool signatures.
pub async fn list_tool_signatures(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref store) = state.etdi_store else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI not enabled"})),
        ));
    };

    let signatures = store.list_signatures().await;
    // SECURITY (FIND-R67-004-003): Cap response to prevent unbounded serialization.
    let total = signatures.len();
    let bounded: Vec<_> = signatures
        .iter()
        .take(MAX_SIGNATURES_LIST)
        .map(|(tool, sig)| {
            json!({
                "tool": tool,
                "signature_id": sig.signature_id,
                "algorithm": sig.algorithm.to_string(),
                "signed_at": sig.signed_at,
                "expires_at": sig.expires_at,
            })
        })
        .collect();
    Ok(Json(json!({
        "count": bounded.len(),
        "total": total,
        "truncated": total > MAX_SIGNATURES_LIST,
        "signatures": bounded,
    })))
}

/// Get signature for a specific tool.
pub async fn get_tool_signature(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param_json(&tool, "tool")?;

    let Some(ref store) = state.etdi_store else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI not enabled"})),
        ));
    };

    match store.get_signature(&tool).await {
        Some(sig) => Ok(Json(json!({
            "tool": tool,
            "signature": sig,
        }))),
        // SECURITY (FIND-R51-011): Generic error — do not echo tool name.
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Tool signature not found"})),
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifySignatureRequest {
    pub schema: serde_json::Value,
}

/// Verify a tool's signature against its schema.
pub async fn verify_tool_signature(
    State(state): State<AppState>,
    Path(tool): Path<String>,
    Json(req): Json<VerifySignatureRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param_json(&tool, "tool")?;

    let Some(ref store) = state.etdi_store else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI not enabled"})),
        ));
    };

    let Some(ref verifier) = state.etdi_verifier else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI verifier not configured"})),
        ));
    };

    // SECURITY (FIND-R51-011): Generic error — do not echo tool name.
    let Some(sig) = store.get_signature(&tool).await else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Tool signature not found"})),
        ));
    };

    let result = verifier.verify_tool_signature(&tool, &req.schema, &sig);
    Ok(Json(json!({
        "tool": tool,
        "verification": result,
    })))
}

/// List all attestations.
pub async fn list_attestations(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref store) = state.etdi_store else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI not enabled"})),
        ));
    };

    let attestations = store.list_attestations().await;
    // SECURITY (FIND-R67-004-004): Cap response to prevent unbounded serialization.
    let total = attestations.len();
    let bounded: Vec<_> = attestations
        .iter()
        .take(MAX_ATTESTATIONS_LIST)
        .map(|(tool, atts)| {
            json!({
                "tool": tool,
                "chain_length": atts.len(),
                "latest": atts.last().map(|a| json!({
                    "attestation_id": a.attestation_id,
                    "type": a.attestation_type,
                    "timestamp": a.timestamp,
                })),
            })
        })
        .collect();
    Ok(Json(json!({
        "count": bounded.len(),
        "total": total,
        "truncated": total > MAX_ATTESTATIONS_LIST,
        "attestations": bounded,
    })))
}

/// Get attestation chain for a tool.
pub async fn get_tool_attestations(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param_json(&tool, "tool")?;

    let Some(ref store) = state.etdi_store else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI not enabled"})),
        ));
    };

    let attestations = store.get_attestations(&tool).await;
    Ok(Json(json!({
        "tool": tool,
        "chain_length": attestations.len(),
        "attestations": attestations,
    })))
}

/// Verify attestation chain for a tool.
pub async fn verify_attestation_chain(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param_json(&tool, "tool")?;

    let Some(ref chain_manager) = state.etdi_attestations else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI attestation tracking not enabled"})),
        ));
    };

    let result = chain_manager.verify_chain(&tool).await;
    Ok(Json(json!({
        "tool": tool,
        "valid": result.valid,
        "chain_length": result.chain_length,
        "issues": result.issues,
    })))
}

/// List all version pins.
pub async fn list_version_pins(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref pin_manager) = state.etdi_version_pins else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI version pinning not enabled"})),
        ));
    };

    let pins = pin_manager.list_pins().await;
    // SECURITY (FIND-R67-004-005): Cap response to prevent unbounded serialization.
    let total = pins.len();
    let bounded: Vec<_> = pins.into_iter().take(MAX_PINS_LIST).collect();
    Ok(Json(json!({
        "count": bounded.len(),
        "total": total,
        "truncated": total > MAX_PINS_LIST,
        "pins": bounded,
        "enforcement": if pin_manager.is_blocking() { "block" } else { "warn" },
    })))
}

/// Get version pin for a tool.
pub async fn get_version_pin(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param_json(&tool, "tool")?;

    let Some(ref pin_manager) = state.etdi_version_pins else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI version pinning not enabled"})),
        ));
    };

    match pin_manager.get_pin(&tool).await {
        Some(pin) => Ok(Json(json!({
            "pin": pin,
        }))),
        // SECURITY (FIND-R51-011): Generic error — do not echo tool name.
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Tool version pin not found"})),
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePinRequest {
    pub version: Option<String>,
    pub constraint: Option<String>,
    pub definition_hash: String,
}

/// Create a version pin for a tool.
pub async fn create_version_pin(
    State(state): State<AppState>,
    Path(tool): Path<String>,
    Json(req): Json<CreatePinRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param_json(&tool, "tool")?;

    // SECURITY: Validate input bounds on request body fields.
    crate::routes::validate_path_param_json(&req.definition_hash, "definition_hash")?;
    if let Some(ref version) = req.version {
        crate::routes::validate_path_param_json(version, "version")?;
    }
    if let Some(ref constraint) = req.constraint {
        crate::routes::validate_path_param_json(constraint, "constraint")?;
    }

    let Some(ref pin_manager) = state.etdi_version_pins else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI version pinning not enabled"})),
        ));
    };

    let result = if let Some(version) = req.version {
        pin_manager
            .pin_version(&tool, &version, &req.definition_hash, "api")
            .await
    } else if let Some(constraint) = req.constraint {
        pin_manager
            .pin_constraint(&tool, &constraint, &req.definition_hash, "api")
            .await
    } else {
        pin_manager
            .pin_hash(&tool, &req.definition_hash, "api")
            .await
    };

    match result {
        Ok(pin) => Ok(Json(json!({
            "success": true,
            "pin": pin,
        }))),
        Err(e) => {
            tracing::warn!(tool = %tool, error = %e, "Failed to create version pin");
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Failed to create version pin"})),
            ))
        }
    }
}

/// Remove a version pin for a tool.
pub async fn remove_version_pin(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // SECURITY (FIND-R51-005): Validate path parameter.
    crate::routes::validate_path_param_json(&tool, "tool")?;

    let Some(ref pin_manager) = state.etdi_version_pins else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI version pinning not enabled"})),
        ));
    };

    match pin_manager.unpin(&tool).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "Tool version pin removed",
        }))),
        // SECURITY (FIND-R51-011): Generic error — do not echo tool name.
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Tool version pin not found"})),
        )),
        Err(e) => {
            tracing::warn!("Failed to remove version pin: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to remove version pin"})),
            ))
        }
    }
}
