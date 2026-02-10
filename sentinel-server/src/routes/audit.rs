//! Audit log route handlers.
//!
//! This module provides REST API endpoints for audit log access,
//! verification, and checkpoint management.
//!
//! Endpoints:
//! - `GET /api/audit` - List audit entries (paginated)
//! - `GET /api/audit/export` - Export audit entries in SIEM formats
//! - `GET /api/audit/report` - Get audit summary report
//! - `GET /api/audit/verify` - Verify audit chain integrity
//! - `GET /api/audit/checkpoints` - List checkpoints
//! - `GET /api/audit/checkpoints/verify` - Verify checkpoint signatures
//! - `POST /api/audit/checkpoints` - Create a new checkpoint

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Default number of audit entries per page.
const DEFAULT_AUDIT_PAGE_SIZE: usize = 100;
/// Maximum number of audit entries per page.
const MAX_AUDIT_PAGE_SIZE: usize = 1000;

/// Query parameters for paginated audit entry listing.
#[derive(Deserialize)]
pub struct AuditEntriesQuery {
    /// Maximum number of entries to return (default 100, max 1000).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Number of entries to skip from the end (most recent first).
    #[serde(default)]
    pub offset: Option<usize>,
}

/// List audit entries with pagination.
///
/// GET /api/audit
#[tracing::instrument(name = "sentinel.audit_entries", skip(state, params))]
pub async fn audit_entries(
    State(state): State<AppState>,
    Query(params): Query<AuditEntriesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let entries = state.audit.load_entries().await.map_err(|e| {
        tracing::error!("Failed to load audit entries: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load audit entries".to_string(),
            }),
        )
    })?;

    let total = entries.len();
    let limit = params
        .limit
        .unwrap_or(DEFAULT_AUDIT_PAGE_SIZE)
        .min(MAX_AUDIT_PAGE_SIZE);
    let offset = params.offset.unwrap_or(0);

    // Return the most recent entries (tail of the list), paginated.
    let page: Vec<_> = entries.into_iter().rev().skip(offset).take(limit).collect();

    Ok(Json(
        json!({"total": total, "count": page.len(), "offset": offset, "limit": limit, "entries": page}),
    ))
}

/// Query parameters for the audit export endpoint.
#[derive(Deserialize)]
pub struct AuditExportQuery {
    /// Export format: "cef" or "jsonl". Default: "jsonl".
    pub format: Option<String>,
    /// Only include entries with timestamp >= this value (ISO 8601 string comparison).
    pub since: Option<String>,
    /// Maximum number of entries to export. Default: 100, max: 1000.
    pub limit: Option<usize>,
}

/// Export audit entries in SIEM-compatible formats (CEF or JSON Lines).
///
/// GET /api/audit/export
///
/// Query parameters:
/// - `format`: "cef" or "jsonl" (default: "jsonl")
/// - `since`: ISO 8601 timestamp filter (entries >= this value)
/// - `limit`: Maximum entries (default: 100, max: 1000)
///
/// Returns `text/plain` for CEF, `application/x-ndjson` for JSON Lines.
pub async fn audit_export(
    State(state): State<AppState>,
    Query(query): Query<AuditExportQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let format = query
        .format
        .as_deref()
        .and_then(sentinel_audit::export::ExportFormat::parse_format)
        .unwrap_or(sentinel_audit::export::ExportFormat::JsonLines);

    let limit = query.limit.unwrap_or(100).min(1000); // Cap at 1000

    let entries = state.audit.load_entries().await.map_err(|e| {
        tracing::error!("Failed to load audit entries for export: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load audit entries".to_string(),
            }),
        )
    })?;

    // Filter by `since` timestamp if provided (lexicographic comparison on ISO 8601)
    let filtered: Vec<_> = if let Some(ref since) = query.since {
        entries
            .into_iter()
            .filter(|e| e.timestamp.as_str() >= since.as_str())
            .take(limit)
            .collect()
    } else {
        entries.into_iter().take(limit).collect()
    };

    let body = sentinel_audit::export::format_entries(&filtered, format);

    let content_type = match format {
        sentinel_audit::export::ExportFormat::Cef => "text/plain",
        sentinel_audit::export::ExportFormat::JsonLines => "application/x-ndjson",
    };

    Ok(([(header::CONTENT_TYPE, content_type)], body))
}

/// Generate an audit summary report.
///
/// GET /api/audit/report
pub async fn audit_report(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let report = state.audit.generate_report().await.map_err(|e| {
        tracing::error!("Failed to generate audit report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate audit report".to_string(),
            }),
        )
    })?;

    // SECURITY (R16-AUDIT-5): Return summary statistics only, not the full
    // entry list. The entries endpoint provides paginated access to individual
    // entries. Embedding all entries in the report response could exhaust
    // server memory with a large audit log.
    Ok(Json(json!({
        "total_entries": report.total_entries,
        "allow_count": report.allow_count,
        "deny_count": report.deny_count,
        "require_approval_count": report.require_approval_count,
    })))
}

/// Verify audit chain integrity.
///
/// GET /api/audit/verify
pub async fn audit_verify(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let verification = state.audit.verify_chain().await.map_err(|e| {
        tracing::error!("Failed to verify audit chain: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to verify audit chain".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(verification).map_err(|e| {
        tracing::error!("Audit verification serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// List all checkpoints.
///
/// GET /api/audit/checkpoints
pub async fn list_checkpoints(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let checkpoints = state.audit.load_checkpoints().await.map_err(|e| {
        tracing::error!("Failed to load checkpoints: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load checkpoints".to_string(),
            }),
        )
    })?;

    Ok(Json(
        json!({"count": checkpoints.len(), "checkpoints": checkpoints}),
    ))
}

/// Verify all checkpoint signatures.
///
/// GET /api/audit/checkpoints/verify
pub async fn verify_checkpoints(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let verification = state.audit.verify_checkpoints().await.map_err(|e| {
        tracing::error!("Failed to verify checkpoints: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to verify checkpoints".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(verification).map_err(|e| {
        tracing::error!("Checkpoint verification serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// Create a new checkpoint.
///
/// POST /api/audit/checkpoints
pub async fn create_checkpoint(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let checkpoint = state.audit.create_checkpoint().await.map_err(|e| {
        tracing::error!("Failed to create checkpoint: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create checkpoint".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(&checkpoint).map_err(|e| {
        tracing::error!("Checkpoint serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}
