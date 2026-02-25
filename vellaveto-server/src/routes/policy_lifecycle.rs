//! Policy lifecycle management route handlers (Phase 47).
//!
//! Endpoints for versioned policy management with approval workflows,
//! staging shadow evaluation, structural diffs, and rollback.
//!
//! All endpoints require `policy_lifecycle.enabled = true` in config.
//! When disabled, all endpoints return 404 "Policy lifecycle not enabled".

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{
    has_dangerous_chars, Action, Policy, PolicyVersionStatus, Verdict, MAX_LIFECYCLE_IDENTITY_LEN,
    MAX_VERSION_COMMENT_LEN,
};

use crate::policy_lifecycle::LifecycleError;
use crate::tenant::TenantContext;
use crate::AppState;

/// SECURITY (FIND-R204-004): Policy lifecycle management is a global
/// administrative operation. Non-default tenants must not be able to
/// create, approve, promote, archive, or rollback policy versions that
/// affect the shared policy engine.
fn require_admin_tenant(
    tenant_ctx: &TenantContext,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if !tenant_ctx.is_default() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Policy lifecycle management requires admin access"})),
        ));
    }
    Ok(())
}

// ─── Request Types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVersionRequest {
    pub policy: Policy,
    pub created_by: String,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveVersionRequest {
    pub approved_by: String,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    pub to_version: u64,
    pub created_by: String,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Get the lifecycle store or return 404.
fn get_store(
    state: &AppState,
) -> Result<
    &Arc<dyn crate::policy_lifecycle::PolicyVersionStore>,
    (StatusCode, Json<serde_json::Value>),
> {
    state.policy_lifecycle_store.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Policy lifecycle not enabled"})),
        )
    })
}

/// Convert LifecycleError to HTTP response.
fn lifecycle_error_response(e: LifecycleError) -> (StatusCode, Json<serde_json::Value>) {
    let (status, msg) = match &e {
        LifecycleError::PolicyNotFound(_) | LifecycleError::VersionNotFound(_, _) => {
            (StatusCode::NOT_FOUND, e.to_string())
        }
        LifecycleError::InvalidTransition(_) => (StatusCode::CONFLICT, e.to_string()),
        LifecycleError::ApprovalRequired(_) => (StatusCode::PRECONDITION_FAILED, e.to_string()),
        LifecycleError::CapacityExceeded(_) => (StatusCode::TOO_MANY_REQUESTS, e.to_string()),
        LifecycleError::Validation(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        LifecycleError::Internal(_) => {
            tracing::error!("Policy lifecycle internal error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error".to_string(),
            )
        }
    };
    (status, Json(json!({"error": msg})))
}

/// Validate a string input field (identity, comment, etc.).
fn validate_input_string(
    field_name: &str,
    value: &str,
    max_len: usize,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if value.is_empty() || value.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{} must be non-empty", field_name)})),
        ));
    }
    if value.len() > max_len {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{} exceeds {} chars", field_name, max_len)})),
        ));
    }
    if has_dangerous_chars(value) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{} contains invalid characters", field_name)})),
        ));
    }
    Ok(())
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// GET /api/policies/{id}/versions
///
/// List all versions for a policy (newest first).
#[tracing::instrument(
    name = "vellaveto.list_policy_versions",
    skip(state),
    fields(policy_id = %id)
)]
pub async fn list_versions(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    super::validate_path_param_json(&id, "policy_id")?;
    let versions = store
        .list_versions(&id)
        .await
        .map_err(lifecycle_error_response)?;
    Ok(Json(json!({ "versions": versions })))
}

/// GET /api/policies/{id}/versions/{v}
///
/// Get a specific version of a policy.
#[tracing::instrument(
    name = "vellaveto.get_policy_version",
    skip(state),
    fields(policy_id = %id, version = %v)
)]
pub async fn get_version(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path((id, v)): Path<(String, u64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    super::validate_path_param_json(&id, "policy_id")?;
    let version = store
        .get_version(&id, v)
        .await
        .map_err(lifecycle_error_response)?;
    // SECURITY (FIND-R204-003): Propagate serialization errors instead of
    // silently returning empty JSON, which would be a fail-open pattern.
    let val = serde_json::to_value(&version).map_err(|e| {
        tracing::error!("Failed to serialize policy version: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Internal serialization error"})),
        )
    })?;
    Ok(Json(val))
}

/// POST /api/policies/{id}/versions
///
/// Create a new draft version for a policy.
#[tracing::instrument(
    name = "vellaveto.create_policy_version",
    skip(state, body),
    fields(policy_id = %id)
)]
pub async fn create_version(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<CreateVersionRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    super::validate_path_param_json(&id, "policy_id")?;
    validate_input_string("created_by", &body.created_by, MAX_LIFECYCLE_IDENTITY_LEN)?;

    // SECURITY (FIND-R204-001): Bind the created_by identity to the
    // authentication principal. The client-asserted value is preserved as
    // a human-readable note, but the authoritative identity is derived
    // from the Bearer token hash. This prevents self-approval bypass
    // where an attacker uses different client-asserted names with the
    // same API key for create and approve operations.
    let bound_created_by = super::approval::derive_resolver_identity(&headers, &body.created_by);
    if let Some(ref c) = body.comment {
        validate_input_string("comment", c, MAX_VERSION_COMMENT_LEN)?;
    }
    // Validate the policy body
    body.policy.validate().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Invalid policy: {}", e)})),
        )
    })?;
    // Ensure the policy ID in the body matches the path parameter
    if body.policy.id != id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy id in body must match path parameter"})),
        ));
    }

    let version = store
        .create_version(&id, body.policy, &bound_created_by, body.comment.as_deref())
        .await
        .map_err(lifecycle_error_response)?;

    // Audit event
    let action = Action::new(
        "vellaveto",
        "policy_lifecycle",
        json!({
            "event": "version_created",
            "policy_id": id,
            "version": version.version,
            // SECURITY (FIND-R206-001): Log the auth-bound identity, not the
            // client-asserted value, to preserve non-repudiation in audit trail.
            "created_by": bound_created_by,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "version_created"}),
        )
        .await
    {
        tracing::warn!("Failed to audit version creation: {}", e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(&version).map_err(|e| {
            tracing::error!("Failed to serialize policy version: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal serialization error"})),
            )
        })?),
    ))
}

/// POST /api/policies/{id}/versions/{v}/approve
///
/// Record an approval for a policy version.
#[tracing::instrument(
    name = "vellaveto.approve_policy_version",
    skip(state, body),
    fields(policy_id = %id, version = %v)
)]
pub async fn approve_version(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    headers: HeaderMap,
    Path((id, v)): Path<(String, u64)>,
    Json(body): Json<ApproveVersionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    super::validate_path_param_json(&id, "policy_id")?;
    validate_input_string("approved_by", &body.approved_by, MAX_LIFECYCLE_IDENTITY_LEN)?;
    if let Some(ref c) = body.comment {
        validate_input_string("comment", c, MAX_VERSION_COMMENT_LEN)?;
    }

    // SECURITY (FIND-R204-001): Bind the approved_by identity to the
    // authentication principal (same as create_version above).
    let bound_approved_by = super::approval::derive_resolver_identity(&headers, &body.approved_by);

    let version = store
        .approve_version(&id, v, &bound_approved_by, body.comment.as_deref())
        .await
        .map_err(lifecycle_error_response)?;

    // Audit event
    let action = Action::new(
        "vellaveto",
        "policy_lifecycle",
        json!({
            "event": "version_approved",
            "policy_id": id,
            "version": v,
            // SECURITY (FIND-R206-001): Log the auth-bound identity, not the
            // client-asserted value, to preserve non-repudiation in audit trail.
            "approved_by": bound_approved_by,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "version_approved"}),
        )
        .await
    {
        tracing::warn!("Failed to audit version approval: {}", e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    Ok(Json(serde_json::to_value(&version).map_err(|e| {
        tracing::error!("Failed to serialize policy version: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Internal serialization error"})),
        )
    })?))
}

/// POST /api/policies/{id}/versions/{v}/promote
///
/// Promote a version: Draft → Staging or Staging → Active.
/// When promoting to Active, compiles the new policy set and atomically swaps it.
#[tracing::instrument(
    name = "vellaveto.promote_policy_version",
    skip(state),
    fields(policy_id = %id, version = %v)
)]
pub async fn promote_version(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path((id, v)): Path<(String, u64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    super::validate_path_param_json(&id, "policy_id")?;

    // SECURITY (FIND-R204-004): Acquire policy_write_lock BEFORE reading version
    // state and performing the promotion. This eliminates the TOCTOU window where
    // the store says Active but the engine hasn't been updated, and ensures the
    // original_status read and the promote+compile+swap are atomic with respect
    // to other policy mutations.
    let _guard = state.policy_write_lock.lock().await;

    // Read the version before promotion to validate and pre-compile
    let before = store
        .get_version(&id, v)
        .await
        .map_err(lifecycle_error_response)?;

    // SECURITY (FIND-R204-003): Pre-compile the candidate policy set BEFORE
    // calling store.promote_version(). This prevents the scenario where the
    // store archives the previously-active version, the new version fails to
    // compile, and revert only restores the promoted version — leaving no
    // active version in the store while the engine still enforces the old one.
    //
    // By compiling first, compilation failures are caught before any store
    // mutation, eliminating the need for revert_promotion on compile failure.
    let snap = state.policy_state.load();
    let mut candidate: Vec<Policy> = snap
        .policies
        .iter()
        .filter(|p| p.id != id)
        .cloned()
        .collect();
    candidate.push(before.policy.clone());
    PolicyEngine::sort_policies(&mut candidate);

    let pre_compiled = match PolicyEngine::with_policies(snap.engine.strict_mode(), &candidate) {
        Ok(engine) => Some(engine),
        Err(errors) => {
            // SECURITY (FIND-R209-001): For both Draft and Staging versions,
            // always treat compilation failure as fatal (fail-safe). The previous
            // heuristic used `!candidate.is_empty()` which was always true since
            // the candidate vec always contains at least the new policy. Catching
            // compilation errors early is correct regardless of whether the draft
            // transitions to Staging or Active — a policy that cannot compile
            // should not enter any promoted state.
            let would_be_active = matches!(before.status, PolicyVersionStatus::Staging)
                || matches!(before.status, PolicyVersionStatus::Draft);

            if would_be_active {
                let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                tracing::error!(
                    "Policy lifecycle: pre-compile failed, blocking promotion: {:?}",
                    msgs
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Policy compilation failed — promotion blocked (no store mutation)",
                        "policy_id": id,
                    })),
                ));
            }
            // Defensive fallback: unreachable for Draft/Staging (both handled
            // above), but kept for forward-compatibility since PolicyVersionStatus
            // is #[non_exhaustive].
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            tracing::warn!(
                "Policy lifecycle: pre-compile failed for unexpected status {:?} (non-fatal): {:?}",
                before.status,
                msgs
            );
            None
        }
    };

    // Now perform the promotion in the store (safe: compilation already validated)
    let promoted = store
        .promote_version(&id, v)
        .await
        .map_err(lifecycle_error_response)?;

    let event_name = match promoted.status {
        PolicyVersionStatus::Staging => "version_promoted_staging",
        PolicyVersionStatus::Active => "version_promoted_active",
        _ => "version_promoted",
    };

    // If promoted to Active, swap the pre-compiled engine
    if matches!(promoted.status, PolicyVersionStatus::Active) {
        if let Some(compiled_engine) = pre_compiled {
            state.policy_state.store(Arc::new(crate::PolicySnapshot {
                engine: compiled_engine,
                policies: candidate,
                compliance_config: snap.compliance_config.clone(),
            }));
            tracing::info!("Policy lifecycle: activated policy {} version {}", id, v);

            // Clear staging snapshot since we just activated
            state.staging_snapshot.store(Arc::new(None));
        } else {
            // This shouldn't happen: pre-compilation should have blocked the
            // promotion to Active. Log and fail-closed.
            tracing::error!(
                "Policy lifecycle: promoted to Active but no pre-compiled engine — \
                 this indicates a logic error"
            );
        }
    } else if matches!(promoted.status, PolicyVersionStatus::Staging) {
        // Use pre-compiled engine for staging snapshot if available
        if let Some(staging_engine) = pre_compiled {
            state
                .staging_snapshot
                .store(Arc::new(Some(crate::StagingSnapshot {
                    engine: staging_engine,
                    policies: candidate,
                })));
            tracing::info!(
                "Policy lifecycle: staging snapshot built for policy {} version {}",
                id,
                v
            );
        }
        // If pre_compiled is None, staging snapshot won't be available (non-fatal)
    }

    // Audit event
    let action = Action::new(
        "vellaveto",
        "policy_lifecycle",
        json!({
            "event": event_name,
            "policy_id": id,
            "version": v,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": event_name}),
        )
        .await
    {
        tracing::warn!("Failed to audit version promotion: {}", e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    Ok(Json(serde_json::to_value(&promoted).map_err(|e| {
        tracing::error!("Failed to serialize promoted version: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Internal serialization error"})),
        )
    })?))
}

/// POST /api/policies/{id}/versions/{v}/archive
///
/// Archive a version (Draft or Staging → Archived).
#[tracing::instrument(
    name = "vellaveto.archive_policy_version",
    skip(state),
    fields(policy_id = %id, version = %v)
)]
pub async fn archive_version(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path((id, v)): Path<(String, u64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    super::validate_path_param_json(&id, "policy_id")?;

    // SECURITY (FIND-R206-002): Acquire policy_write_lock BEFORE reading version
    // status to eliminate TOCTOU gap between the status check and the
    // archive + staging-snapshot-clear operations.
    let _guard = state.policy_write_lock.lock().await;

    // Check if this was a Staging version — if so, clear the staging snapshot
    let before = store
        .get_version(&id, v)
        .await
        .map_err(lifecycle_error_response)?;
    let was_staging = matches!(before.status, PolicyVersionStatus::Staging);

    let version = store
        .archive_version(&id, v)
        .await
        .map_err(lifecycle_error_response)?;

    if was_staging {
        state.staging_snapshot.store(Arc::new(None));
    }

    // Audit event
    let action = Action::new(
        "vellaveto",
        "policy_lifecycle",
        json!({
            "event": "version_archived",
            "policy_id": id,
            "version": v,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "version_archived"}),
        )
        .await
    {
        tracing::warn!("Failed to audit version archival: {}", e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    Ok(Json(serde_json::to_value(&version).map_err(|e| {
        tracing::error!("Failed to serialize policy version: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Internal serialization error"})),
        )
    })?))
}

/// POST /api/policies/{id}/rollback
///
/// Create a new draft from an old version (rollback).
#[tracing::instrument(
    name = "vellaveto.rollback_policy",
    skip(state, body),
    fields(policy_id = %id)
)]
pub async fn rollback_policy(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RollbackRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    super::validate_path_param_json(&id, "policy_id")?;
    validate_input_string("created_by", &body.created_by, MAX_LIFECYCLE_IDENTITY_LEN)?;

    // SECURITY (FIND-R204-001): Bind identity to auth context.
    let bound_created_by = super::approval::derive_resolver_identity(&headers, &body.created_by);

    let version = store
        .rollback(&id, body.to_version, &bound_created_by)
        .await
        .map_err(lifecycle_error_response)?;

    // Audit event
    let action = Action::new(
        "vellaveto",
        "policy_lifecycle",
        json!({
            "event": "policy_rollback",
            "policy_id": id,
            "to_version": body.to_version,
            "new_version": version.version,
            // SECURITY (FIND-R206-001): Log the auth-bound identity, not the
            // client-asserted value, to preserve non-repudiation in audit trail.
            "created_by": bound_created_by,
        }),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "policy_rollback"}),
        )
        .await
    {
        tracing::warn!("Failed to audit policy rollback: {}", e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(&version).map_err(|e| {
            tracing::error!("Failed to serialize policy version: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal serialization error"})),
            )
        })?),
    ))
}

/// GET /api/policies/{id}/versions/{v1}/diff/{v2}
///
/// Compute structural diff between two versions.
#[tracing::instrument(
    name = "vellaveto.diff_policy_versions",
    skip(state),
    fields(policy_id = %id, from = %v1, to = %v2)
)]
pub async fn diff_versions(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Path((id, v1, v2)): Path<(String, u64, u64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    super::validate_path_param_json(&id, "policy_id")?;
    let diff = store
        .diff_versions(&id, v1, v2)
        .await
        .map_err(lifecycle_error_response)?;
    Ok(Json(serde_json::to_value(&diff).map_err(|e| {
        tracing::error!("Failed to serialize policy diff: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Internal serialization error"})),
        )
    })?))
}

/// GET /api/policy-lifecycle/status
///
/// Return lifecycle subsystem status.
#[tracing::instrument(name = "vellaveto.policy_lifecycle_status", skip(state))]
pub async fn lifecycle_status(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_tenant(&tenant_ctx)?;
    let store = get_store(&state)?;
    let status = store.status().await;
    Ok(Json(serde_json::to_value(&status).map_err(|e| {
        tracing::error!("Failed to serialize lifecycle status: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Internal serialization error"})),
        )
    })?))
}
