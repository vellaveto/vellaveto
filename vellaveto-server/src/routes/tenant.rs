//! Tenant Management route handlers (Phase 3).
//!
//! This module provides REST API endpoints for multi-tenant management
//! including listing, creating, updating, and deleting tenants.
//!
//! Endpoints:
//! - `GET /api/tenants` - List all tenants
//! - `POST /api/tenants` - Create a new tenant
//! - `GET /api/tenants/{id}` - Get a specific tenant
//! - `PUT /api/tenants/{id}` - Update a tenant
//! - `DELETE /api/tenants/{id}` - Delete a tenant

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::routes::ErrorResponse;
use crate::tenant::{self, Tenant, TenantError, TenantQuotas, DEFAULT_TENANT_ID};
use crate::AppState;

/// Response type for tenant operations.
#[derive(Serialize)]
pub struct TenantResponse {
    pub tenant: Tenant,
}

/// Request type for creating/updating a tenant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantRequest {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub quotas: Option<TenantQuotas>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// SECURITY (FIND-R67-002): Maximum entries returned by tenant list.
const MAX_TENANTS_LIST: usize = 1000;

/// List all tenants.
///
/// Returns an empty list if no tenant store is configured.
pub async fn list_tenants(
    State(state): State<AppState>,
) -> Result<Json<Vec<Tenant>>, (StatusCode, Json<ErrorResponse>)> {
    let tenants = match &state.tenant_store {
        Some(store) => store.list_tenants(),
        None => vec![],
    };
    // SECURITY (FIND-R67-002): Cap response to prevent unbounded serialization.
    let bounded: Vec<_> = tenants.into_iter().take(MAX_TENANTS_LIST).collect();
    Ok(Json(bounded))
}

/// Get a specific tenant by ID.
pub async fn get_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TenantResponse>, (StatusCode, Json<ErrorResponse>)> {
    crate::routes::validate_path_param(&id, "id")?;

    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured".to_string(),
            }),
        )
    })?;

    let tenant = store.get_tenant(&id).ok_or_else(|| {
        // SECURITY (FIND-R51-013): Do not leak tenant ID in error response.
        tracing::warn!(tenant_id = %id, "Tenant not found");
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tenant not found".to_string(),
            }),
        )
    })?;

    Ok(Json(TenantResponse { tenant }))
}

/// Create a new tenant.
pub async fn create_tenant(
    State(state): State<AppState>,
    Json(req): Json<TenantRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Validate tenant ID
    if let Err(e) = tenant::validate_tenant_id(&req.id) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        ));
    }

    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured".to_string(),
            }),
        )
    })?;

    let now = chrono::Utc::now().to_rfc3339();
    let tenant = Tenant {
        id: req.id,
        name: req.name,
        enabled: req.enabled,
        quotas: req.quotas.unwrap_or_default(),
        metadata: req.metadata,
        created_at: Some(now.clone()),
        updated_at: Some(now),
    };

    // SECURITY (FIND-R106-001): Validate the full Tenant struct before persisting.
    // validate_tenant_id() only checks the ID field; Tenant::validate() also checks
    // name bounds, metadata bounds, and control/format characters. Without this,
    // any TenantStore implementation that omits internal validate() would accept
    // unbounded/malicious data.
    tenant.validate().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    store.create_tenant(tenant.clone()).map_err(|e| match e {
        TenantError::InvalidTenantId(msg) => {
            (StatusCode::CONFLICT, Json(ErrorResponse { error: msg }))
        }
        _ => {
            tracing::warn!(error = %e, "create_tenant failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create tenant".to_string(),
                }),
            )
        }
    })?;

    Ok((StatusCode::CREATED, Json(TenantResponse { tenant })))
}

/// Update an existing tenant.
pub async fn update_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TenantRequest>,
) -> Result<Json<TenantResponse>, (StatusCode, Json<ErrorResponse>)> {
    crate::routes::validate_path_param(&id, "id")?;

    // Validate that path ID matches body ID
    if id != req.id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Tenant ID in path must match ID in body".to_string(),
            }),
        ));
    }

    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured".to_string(),
            }),
        )
    })?;

    // Get existing tenant to preserve created_at
    let existing = store.get_tenant(&id).ok_or_else(|| {
        // SECURITY (FIND-R51-013): Do not leak tenant ID in error response.
        tracing::warn!(tenant_id = %id, "Tenant not found for update");
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Tenant not found".to_string(),
            }),
        )
    })?;

    let now = chrono::Utc::now().to_rfc3339();
    let tenant = Tenant {
        id: req.id,
        name: req.name,
        enabled: req.enabled,
        quotas: req.quotas.unwrap_or_default(),
        metadata: req.metadata,
        created_at: existing.created_at,
        updated_at: Some(now),
    };

    // SECURITY (FIND-R106-001): Validate the full Tenant struct before persisting.
    tenant.validate().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    store.update_tenant(tenant.clone()).map_err(|e| {
        tracing::warn!(tenant_id = %id, error = %e, "update_tenant failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update tenant".to_string(),
            }),
        )
    })?;

    Ok(Json(TenantResponse { tenant }))
}

/// Delete a tenant.
pub async fn delete_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    crate::routes::validate_path_param(&id, "id")?;

    // Don't allow deleting the default tenant
    if id == DEFAULT_TENANT_ID {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot delete the default tenant".to_string(),
            }),
        ));
    }

    let store = state.tenant_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Tenant store not configured".to_string(),
            }),
        )
    })?;

    store.delete_tenant(&id).map_err(|e| match e {
        TenantError::TenantNotFound(_) => {
            // SECURITY (FIND-R51-013): Do not leak tenant ID in error response.
            tracing::warn!(tenant_id = %id, "Tenant not found for deletion");
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Tenant not found".to_string(),
                }),
            )
        }
        _ => {
            tracing::warn!(tenant_id = %id, error = %e, "delete_tenant failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to delete tenant".to_string(),
                }),
            )
        }
    })?;

    Ok(StatusCode::NO_CONTENT)
}
