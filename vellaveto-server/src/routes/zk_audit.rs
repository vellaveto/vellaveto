// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! ZK Audit route handlers (Phase 37.3).
//!
//! Endpoints:
//! - `GET /api/zk-audit/status` — scheduler status (enabled, pending witnesses, proof count)
//! - `GET /api/zk-audit/proofs` — list all stored batch proofs
//! - `POST /api/zk-audit/verify` — verify a specific batch proof (offline only)
//! - `GET /api/zk-audit/commitments` — list commitments for an entry range

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum batch_id length for verify requests.
const MAX_BATCH_ID_LENGTH: usize = 256;

/// Maximum proofs returned by the list endpoint.
const MAX_PROOFS_LIST: usize = 100;

/// Maximum entry range span for commitments query.
const MAX_ENTRY_RANGE_SPAN: u64 = 10_000;

/// Maximum number of parsed audit entries scanned for range queries.
///
/// Prevents unbounded work and memory pressure when serving commitments from
/// very large audit logs. Operators should rotate/archive audit logs to stay
/// under this limit.
const MAX_LOADED_ENTRIES: usize = 500_000;

/// GET /api/zk-audit/status
///
/// Returns the current ZK audit scheduler status including whether
/// the system is enabled, proof counts, and pending witness counts.
pub async fn zk_audit_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.zk_audit_enabled {
        return Ok(Json(json!({
            "active": false,
            "pending_witnesses": 0,
            "completed_proofs": 0,
            "last_proved_sequence": null,
            "last_proof_at": null,
        })));
    }

    let proofs_store = state.zk_proofs.as_ref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "ZK proof store not initialized".to_string(),
            }),
        )
    })?;

    let guard = proofs_store.lock().map_err(|_e| {
        tracing::error!("SECURITY: ZK proof store mutex poisoned");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;

    let completed_proofs = guard.len();
    let (last_proved_sequence, last_proof_at) = guard.last().map_or((None, None), |p| {
        (Some(p.entry_range.1), Some(p.created_at.clone()))
    });

    Ok(Json(json!({
        "active": state.zk_audit_config.batch_proof_enabled,
        "pending_witnesses": 0,
        "completed_proofs": completed_proofs,
        "last_proved_sequence": last_proved_sequence,
        "last_proof_at": last_proof_at,
    })))
}

/// Query parameters for `GET /api/zk-audit/proofs`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkProofsQuery {
    /// Maximum number of proofs to return (default: 20, max: 100).
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Offset for pagination (default: 0).
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    20
}

/// GET /api/zk-audit/proofs
///
/// List stored ZK batch proofs with pagination.
pub async fn zk_audit_proofs(
    State(state): State<AppState>,
    Query(params): Query<ZkProofsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.zk_audit_enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "ZK audit is not enabled. Set [zk_audit] enabled = true in your config file and restart the server.".to_string(),
            }),
        ));
    }

    let proofs_store = state.zk_proofs.as_ref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "ZK proof store not initialized".to_string(),
            }),
        )
    })?;

    let guard = proofs_store.lock().map_err(|_e| {
        tracing::error!("SECURITY: ZK proof store mutex poisoned");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;

    let limit = params.limit.min(MAX_PROOFS_LIST);
    let total = guard.len();

    // QUALITY (FIND-GAP-010): Validate offset does not exceed total to prevent
    // confusing empty-but-200 responses for wildly out-of-range offsets.
    // SECURITY (FIND-R138-002): Do not disclose exact proof count in error message.
    if params.offset > total {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "offset exceeds total proof count".to_string(),
            }),
        ));
    }

    let proofs: Vec<_> = guard
        .iter()
        .skip(params.offset)
        .take(limit)
        .cloned()
        .collect();

    let proofs_value = serde_json::to_value(&proofs).map_err(|e| {
        tracing::error!("Failed to serialize ZK proofs list: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize proofs list".to_string(),
            }),
        )
    })?;

    Ok(Json(json!({
        "proofs": proofs_value,
        "total": total,
        "offset": params.offset,
        "limit": limit,
    })))
}

/// Request body for `POST /api/zk-audit/verify`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkVerifyRequest {
    /// The batch_id to verify. Must correspond to a stored proof.
    pub batch_id: String,
}

/// POST /api/zk-audit/verify
///
/// Verify a stored batch proof by batch_id. Returns the verification result.
///
/// Note: Full Groth16 verification requires the `zk-audit` feature to be
/// compiled into the audit crate. When running without it, this endpoint
/// performs structural validation only.
pub async fn zk_audit_verify(
    State(state): State<AppState>,
    Json(body): Json<ZkVerifyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.zk_audit_enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "ZK audit is not enabled. Set [zk_audit] enabled = true in your config file and restart the server.".to_string(),
            }),
        ));
    }

    // Validate batch_id
    if body.batch_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "batch_id must not be empty".to_string(),
            }),
        ));
    }
    if body.batch_id.len() > MAX_BATCH_ID_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "batch_id length {} exceeds max {}",
                    body.batch_id.len(),
                    MAX_BATCH_ID_LENGTH
                ),
            }),
        ));
    }
    if body.batch_id.chars().any(crate::routes::is_unsafe_char) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "batch_id contains control characters".to_string(),
            }),
        ));
    }

    let proofs_store = state.zk_proofs.as_ref().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "ZK proof store not initialized".to_string(),
            }),
        )
    })?;

    // Clone proof data inside the lock scope to avoid holding MutexGuard across .await
    let result = {
        let guard = proofs_store.lock().map_err(|_e| {
            tracing::error!("SECURITY: ZK proof store mutex poisoned");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            )
        })?;

        let proof = guard
            .iter()
            .find(|p| p.batch_id == body.batch_id)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Proof not found".to_string(),
                    }),
                )
            })?;

        // Structural validation (full Groth16 verification requires zk-audit feature
        // at the audit crate level — the server returns structural validity here)
        vellaveto_types::ZkVerifyResult {
            valid: !proof.proof.is_empty()
                && !proof.first_prev_hash.is_empty()
                && !proof.final_entry_hash.is_empty()
                && proof.entry_count > 0,
            batch_id: proof.batch_id.clone(),
            entry_range: proof.entry_range,
            verified_at: chrono::Utc::now().to_rfc3339(),
            error: None,
        }
        // guard dropped here
    };

    // Audit log the verification
    if let Err(e) = state
        .audit
        .log_zk_event(
            "proof_verified",
            json!({
                "batch_id": &body.batch_id,
                "valid": result.valid,
                "entry_range": [result.entry_range.0, result.entry_range.1],
            }),
        )
        .await
    {
        tracing::warn!(error = %e, "Failed to audit-log ZK proof verification");
    }

    let value = serde_json::to_value(&result).map_err(|e| {
        tracing::error!("Failed to serialize ZK verify result: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize verification result".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// Query parameters for `GET /api/zk-audit/commitments`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkCommitmentsQuery {
    /// Start of the entry range (sequence number).
    pub from: u64,
    /// End of the entry range (sequence number, inclusive).
    pub to: u64,
}

/// GET /api/zk-audit/commitments
///
/// List Pedersen commitments for audit entries in a given sequence range.
/// Commitments are extracted from the audit log entries.
pub async fn zk_audit_commitments(
    State(state): State<AppState>,
    Query(params): Query<ZkCommitmentsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if !state.zk_audit_enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "ZK audit is not enabled. Set [zk_audit] enabled = true in your config file and restart the server.".to_string(),
            }),
        ));
    }

    // Validate range
    if params.from > params.to {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                // SECURITY (FIND-R153-001): Generic error — don't echo user values
                error: "invalid entry range: from must be <= to".to_string(),
            }),
        ));
    }

    let span = params.to.saturating_sub(params.from);
    if span > MAX_ENTRY_RANGE_SPAN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                // SECURITY (FIND-R153-001): Generic error — don't disclose max bounds
                error: "entry range span exceeds maximum allowed".to_string(),
            }),
        ));
    }

    // Stream-load only entries in the requested sequence range.
    let entries = state
        .audit
        .load_entries_in_sequence_range(params.from, params.to, MAX_LOADED_ENTRIES)
        .await
        .map_err(|e| match e {
            vellaveto_audit::AuditError::Validation(msg)
                if msg.contains("exceeds capacity limit") =>
            {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse { error: msg }),
                )
            }
            _ => {
                // SECURITY (FIND-R65-003): Redact internal error details.
                tracing::warn!(error = %e, "Failed to load audit entries for ZK commitments");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to load audit entries".to_string(),
                    }),
                )
            }
        })?;

    let commitments: Vec<serde_json::Value> = entries
        .into_iter()
        .filter_map(|e| {
            e.commitment.as_ref().map(|c| {
                json!({
                    "sequence": e.sequence,
                    "commitment": c,
                    "timestamp": &e.timestamp,
                })
            })
        })
        .collect();

    Ok(Json(json!({
        "commitments": commitments,
        "total": commitments.len(),
        "range": [params.from, params.to],
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proofs_query_deserialize_defaults() {
        let json = r#"{}"#;
        let query: ZkProofsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit, 20);
        assert_eq!(query.offset, 0);
    }

    #[test]
    fn test_proofs_query_deserialize_full() {
        let json = r#"{"limit": 50, "offset": 10}"#;
        let query: ZkProofsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit, 50);
        assert_eq!(query.offset, 10);
    }

    #[test]
    fn test_verify_request_deserialize() {
        let json = r#"{"batch_id": "abc-123"}"#;
        let req: ZkVerifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.batch_id, "abc-123");
    }

    #[test]
    fn test_commitments_query_deserialize() {
        let json = r#"{"from": 0, "to": 100}"#;
        let query: ZkCommitmentsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.from, 0);
        assert_eq!(query.to, 100);
    }

    #[test]
    fn test_limit_clamped_to_max() {
        let json = r#"{"limit": 500, "offset": 0}"#;
        let query: ZkProofsQuery = serde_json::from_str(json).unwrap();
        // The clamp happens in the handler, but verify parse works
        assert_eq!(query.limit, 500);
    }
}
