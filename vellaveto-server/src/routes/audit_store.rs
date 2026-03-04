// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Audit store route handlers (Phase 43).
//!
//! Endpoints:
//! - `GET /api/audit/search` — search audit entries with structured query params
//! - `GET /api/audit/store/status` — report backend type and enabled flag
//! - `GET /api/audit/entry/:id` — look up a single entry by UUID

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use vellaveto_types::audit_store::{AuditQueryParams, AuditQueryResult, AuditStoreStatus};

use crate::tenant::TenantContext;
use crate::AppState;

use super::{validate_path_param, ErrorResponse};

/// GET /api/audit/search
///
/// Search audit entries matching the given query parameters.
/// Delegates to the configured `AuditQueryService` backend (file or Postgres).
pub async fn audit_search(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Query(mut params): Query<AuditQueryParams>,
) -> Result<Json<AuditQueryResult>, (StatusCode, Json<ErrorResponse>)> {
    // Phase 44: Auto-filter by tenant. Default tenant (admin) can query all tenants.
    // Named tenants can only see their own audit entries.
    if !tenant_ctx.is_default() {
        params.tenant_id = Some(tenant_ctx.tenant_id.clone());
    }

    let query_svc = &state.audit_query;
    match query_svc.search(&params).await {
        Ok(result) => Ok(Json(result)),
        Err(vellaveto_audit::query::QueryError::Validation(msg)) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid query: {msg}"),
            }),
        )),
        Err(e) => {
            tracing::warn!(error = %e, "Audit search failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Audit search failed".to_string(),
                }),
            ))
        }
    }
}

/// GET /api/audit/store/status
///
/// Returns the audit store backend type and enabled state.
///
/// # Security (FIND-R203-005)
///
/// Restricted to the default (admin) tenant. Non-default tenants receive 403
/// because the response discloses global infrastructure details — backend type,
/// sink health, and pending queue depth — that are irrelevant to individual
/// tenants and could assist in denial-of-service or infrastructure mapping.
pub async fn audit_store_status(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
) -> Result<Json<AuditStoreStatus>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R203-005): Only the default (admin) tenant may see global
    // infrastructure status. Return 403 for all other tenants.
    if !tenant_ctx.is_default() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied".to_string(),
            }),
        ));
    }
    Ok(Json(state.audit_store_status.clone()))
}

/// GET /api/audit/entry/:id
///
/// Look up a single audit entry by its UUID.
/// SECURITY (FIND-R202-002): Enforces tenant isolation — non-default tenants
/// can only read entries matching their own tenant_id.
pub async fn audit_entry_by_id(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_path_param(&id, "entry_id")?;

    if id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "entry_id must not be empty".to_string(),
            }),
        ));
    }

    let query_svc = &state.audit_query;
    match query_svc.get_by_id(&id).await {
        Ok(Some(entry)) => {
            // SECURITY (FIND-R202-002): Enforce tenant isolation on single-entry lookup.
            // Non-default tenants must only see their own entries.
            if !tenant_ctx.is_default() {
                let entry_tenant = entry
                    .get("tenant_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if entry_tenant != tenant_ctx.tenant_id {
                    // Return 404 (not 403) to avoid leaking existence of cross-tenant entries.
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: "Audit entry not found".to_string(),
                        }),
                    ));
                }
            }
            Ok(Json(entry))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Audit entry not found".to_string(),
            }),
        )),
        Err(vellaveto_audit::query::QueryError::Validation(msg)) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid entry ID: {msg}"),
            }),
        )),
        Err(e) => {
            tracing::warn!(error = %e, "Audit entry lookup failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Audit entry lookup failed".to_string(),
                }),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use vellaveto_types::audit_store::AuditQueryParams;

    #[test]
    fn test_default_query_params_have_sane_defaults() {
        let params = AuditQueryParams::default();
        assert_eq!(params.limit, 100);
        assert_eq!(params.offset, 0);
        assert!(params.since.is_none());
        assert!(params.until.is_none());
        assert!(params.tool.is_none());
        assert!(params.verdict.is_none());
    }

    #[test]
    fn test_query_params_deserialize_from_json() {
        let json = serde_json::json!({
            "limit": 50,
            "offset": 10,
            "tool": "file_write"
        });
        let params: AuditQueryParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 10);
        assert_eq!(params.tool.as_deref(), Some("file_write"));
    }

    #[test]
    fn test_audit_store_status_serializes() {
        let status = vellaveto_types::audit_store::AuditStoreStatus {
            enabled: true,
            backend: vellaveto_types::audit_store::AuditStoreBackend::File,
            sink_healthy: false,
            pending_count: 0,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["backend"], "file");
    }
}
