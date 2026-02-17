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
    Ok(Json(json!({
        "signatures": signatures.iter()
            .map(|(tool, sig)| json!({
                "tool": tool,
                "signature_id": sig.signature_id,
                "algorithm": sig.algorithm.to_string(),
                "signed_at": sig.signed_at,
                "expires_at": sig.expires_at,
            }))
            .collect::<Vec<_>>()
    })))
}

/// Get signature for a specific tool.
pub async fn get_tool_signature(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("No signature found for tool '{}'", tool)})),
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

    let Some(sig) = store.get_signature(&tool).await else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("No signature found for tool '{}'", tool)})),
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
    Ok(Json(json!({
        "attestations": attestations.iter()
            .map(|(tool, atts)| json!({
                "tool": tool,
                "chain_length": atts.len(),
                "latest": atts.last().map(|a| json!({
                    "attestation_id": a.attestation_id,
                    "type": a.attestation_type,
                    "timestamp": a.timestamp,
                })),
            }))
            .collect::<Vec<_>>()
    })))
}

/// Get attestation chain for a tool.
pub async fn get_tool_attestations(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
    Ok(Json(json!({
        "pins": pins,
        "enforcement": if pin_manager.is_blocking() { "block" } else { "warn" },
    })))
}

/// Get version pin for a tool.
pub async fn get_version_pin(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("No pin found for tool '{}'", tool)})),
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
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )),
    }
}

/// Remove a version pin for a tool.
pub async fn remove_version_pin(
    State(state): State<AppState>,
    Path(tool): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ref pin_manager) = state.etdi_version_pins else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "ETDI version pinning not enabled"})),
        ));
    };

    match pin_manager.unpin(&tool).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": format!("Pin removed for tool '{}'", tool),
        }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("No pin found for tool '{}'", tool)})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}
