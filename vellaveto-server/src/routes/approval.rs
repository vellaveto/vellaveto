//! Approval workflow route handlers.
//!
//! This module provides REST API endpoints for human-in-the-loop
//! approval management.
//!
//! Endpoints:
//! - `GET /api/approvals/pending` - List pending approvals
//! - `GET /api/approvals/{id}` - Get a specific approval
//! - `POST /api/approvals/{id}/approve` - Approve an approval request
//! - `POST /api/approvals/{id}/deny` - Deny an approval request

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use vellaveto_types::{Action, Verdict};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum length for the `resolved_by` field (Finding B1: prevents multi-MB strings).
const MAX_RESOLVED_BY_LEN: usize = 1024;

/// Maximum length for approval ID path parameters.
/// UUIDs are 36 chars; 128 gives ample margin while preventing log bloat.
const MAX_APPROVAL_ID_LEN: usize = 128;

/// Validate an approval ID from a URL path parameter.
/// SECURITY (R16-APPR-1): Reject oversized or malformed IDs to prevent
/// log bloat and provide clean error messages.
fn validate_approval_id(id: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if id.is_empty() || id.len() > MAX_APPROVAL_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Approval ID must be 1-{} characters", MAX_APPROVAL_ID_LEN),
            }),
        ));
    }
    // SECURITY (R16-APPR-2): Reject control characters in approval IDs
    if id.chars().any(|c| c.is_control()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Approval ID contains invalid characters".to_string(),
            }),
        ));
    }
    Ok(())
}

/// Sanitize the resolved_by field: strip control characters.
/// SECURITY (R16-APPR-2): Prevents stored XSS via audit trail if
/// rendered in a web UI, and prevents log injection with newlines/tabs.
fn sanitize_resolved_by(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

/// Derive the resolver identity from the authenticated principal.
///
/// SECURITY (R11-APPR-4): The resolver identity is derived from the Bearer
/// token hash rather than trusting client-supplied values. This creates a
/// cryptographic binding between the authentication and the audit trail.
///
/// The client-supplied `resolved_by` value is preserved as a note but the
/// token hash is the authoritative identity.
pub fn derive_resolver_identity(headers: &HeaderMap, client_value: &str) -> String {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
            let token = &auth[7..];
            if !token.is_empty() {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(token.as_bytes());
                let principal = format!("bearer:{}", hex::encode(&hash[..16]));
                if client_value != "anonymous" {
                    // SECURITY (R34-SRV-7): Strip control characters from client value
                    // to prevent log injection via approval requested_by field.
                    let sanitized: String = client_value
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(256)
                        .collect();
                    return format!("{} (note: {})", principal, sanitized);
                }
                return principal;
            }
        }
    }
    client_value.to_string()
}

/// Request body for resolving an approval.
#[derive(Deserialize)]
pub struct ResolveRequest {
    #[serde(default = "default_resolver")]
    pub resolved_by: String,
}

fn default_resolver() -> String {
    "anonymous".to_string()
}

/// List all pending approvals.
///
/// GET /api/approvals/pending
///
/// Returns a JSON object with:
/// - `count`: number of pending approvals
/// - `approvals`: array of approval objects (parameters redacted)
pub async fn list_pending_approvals(State(state): State<AppState>) -> Json<serde_json::Value> {
    let pending = match state.list_pending_approvals().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to list pending approvals: {:?}", e);
            return Json(json!({"count": 0, "approvals": [], "error": "Backend unavailable"}));
        }
    };
    // SECURITY (R11-APPR-10): Redact sensitive parameters before returning.
    // The approval listing may contain API keys, credentials, or PII in the
    // action parameters. Apply the same redaction used by the audit logger.
    let redacted: Vec<serde_json::Value> = pending
        .iter()
        .map(|a| {
            let mut val = serde_json::to_value(a).unwrap_or_default();
            if let Some(action) = val.get_mut("action") {
                if let Some(params) = action.get("parameters") {
                    let redacted_params = vellaveto_audit::redact_keys_and_patterns(params);
                    action["parameters"] = redacted_params;
                }
            }
            val
        })
        .collect();

    Json(json!({"count": redacted.len(), "approvals": redacted}))
}

/// Get a specific approval by ID.
///
/// GET /api/approvals/{id}
///
/// Returns the approval object with parameters redacted.
pub async fn get_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    let approval = state.get_approval(&id).await.map_err(|e| {
        tracing::debug!("Approval lookup failed for '{}': {:?}", id, e);
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Approval not found".to_string(),
            }),
        )
    })?;

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R11-APPR-10): Redact parameters before returning
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = vellaveto_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
    Ok(Json(value))
}

/// Approve an approval request.
///
/// POST /api/approvals/{id}/approve
///
/// # Security
///
/// - Derives resolver identity from authenticated principal (Bearer token hash)
/// - Validates approval ID for length and control characters
/// - Creates audit trail for the approval decision
/// - Returns 403 Forbidden for self-approval attempts
pub async fn approve_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ResolveRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    // SECURITY (R11-APPR-4): Derive resolver identity from the authenticated
    // principal (Bearer token hash) rather than trusting the client-supplied
    // resolved_by field. The client value is kept as a note but the auth
    // identity is the authoritative record.
    let client_resolved_by = body
        .map(|b| b.resolved_by.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    let resolved_by =
        sanitize_resolved_by(&derive_resolver_identity(&headers, &client_resolved_by));

    if resolved_by.len() > MAX_RESOLVED_BY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "resolved_by exceeds maximum length of {} bytes",
                    MAX_RESOLVED_BY_LEN
                ),
            }),
        ));
    }

    let approval = state
        .approve_approval(&id, &resolved_by)
        .await
        .map_err(|e| {
            let (status, msg) = match &e {
                crate::ApprovalOpError::NotFound(_) => {
                    (StatusCode::NOT_FOUND, "Approval not found")
                }
                crate::ApprovalOpError::AlreadyResolved(_) => {
                    (StatusCode::CONFLICT, "Approval already resolved")
                }
                crate::ApprovalOpError::Expired(_) => (StatusCode::GONE, "Approval expired"),
                crate::ApprovalOpError::Validation(ref msg) => {
                    // SECURITY (R9-2): Self-approval attempts return 403 Forbidden
                    tracing::warn!("Approval validation failed for '{}': {}", id, msg);
                    (StatusCode::FORBIDDEN, "Self-approval denied")
                }
                _ => {
                    tracing::error!("Approval approve error for '{}': {:?}", id, e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                }
            };
            (
                status,
                Json(ErrorResponse {
                    error: msg.to_string(),
                }),
            )
        })?;

    // M7: Audit trail for approval decisions
    {
        let audit_action = Action::new(
            "vellaveto",
            "approval_resolved",
            json!({
                "approval_id": &id,
                "original_tool": &approval.action.tool,
                "original_function": &approval.action.function,
            }),
        );
        if let Err(e) = state
            .audit
            .log_entry(
                &audit_action,
                &Verdict::Allow,
                json!({
                    "source": "api",
                    "event": "approval_approved",
                    "resolved_by": &resolved_by,
                }),
            )
            .await
        {
            tracing::warn!("Failed to audit approval resolution for {}: {}", id, e);
        } else {
            crate::metrics::increment_audit_entries();
        }
    }

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R29-SRV-1): Redact parameters before returning (same as get_approval)
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = vellaveto_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
    Ok(Json(value))
}

/// Deny an approval request.
///
/// POST /api/approvals/{id}/deny
///
/// # Security
///
/// - Derives resolver identity from authenticated principal (Bearer token hash)
/// - Validates approval ID for length and control characters
/// - Creates audit trail for the denial decision
pub async fn deny_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ResolveRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    let client_resolved_by = body
        .map(|b| b.resolved_by.clone())
        .unwrap_or_else(|| "anonymous".to_string());
    let resolved_by =
        sanitize_resolved_by(&derive_resolver_identity(&headers, &client_resolved_by));

    if resolved_by.len() > MAX_RESOLVED_BY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "resolved_by exceeds maximum length of {} bytes",
                    MAX_RESOLVED_BY_LEN
                ),
            }),
        ));
    }

    let approval = state.deny_approval(&id, &resolved_by).await.map_err(|e| {
        let (status, msg) = match &e {
            crate::ApprovalOpError::NotFound(_) => (StatusCode::NOT_FOUND, "Approval not found"),
            crate::ApprovalOpError::AlreadyResolved(_) => {
                (StatusCode::CONFLICT, "Approval already resolved")
            }
            crate::ApprovalOpError::Expired(_) => (StatusCode::GONE, "Approval expired"),
            _ => {
                tracing::error!("Approval deny error for '{}': {:?}", id, e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };
        (
            status,
            Json(ErrorResponse {
                error: msg.to_string(),
            }),
        )
    })?;

    // M7: Audit trail for approval decisions
    {
        let audit_action = Action::new(
            "vellaveto",
            "approval_resolved",
            json!({
                "approval_id": &id,
                "original_tool": &approval.action.tool,
                "original_function": &approval.action.function,
            }),
        );
        if let Err(e) = state
            .audit
            .log_entry(
                &audit_action,
                &Verdict::Deny {
                    reason: "approval_denied".to_string(),
                },
                json!({
                    "source": "api",
                    "event": "approval_denied",
                    "resolved_by": &resolved_by,
                }),
            )
            .await
        {
            tracing::warn!("Failed to audit approval denial for {}: {}", id, e);
        } else {
            crate::metrics::increment_audit_entries();
        }
    }

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R29-SRV-1): Redact parameters before returning (same as get_approval)
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = vellaveto_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
    Ok(Json(value))
}
