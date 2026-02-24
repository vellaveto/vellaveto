//! Policy lifecycle management route handlers (Phase 47).
//!
//! Endpoints for versioned policy management with approval workflows,
//! staging shadow evaluation, structural diffs, and rollback.
//!
//! All endpoints require `policy_lifecycle.enabled = true` in config.
//! When disabled, all endpoints return 404 "Policy lifecycle not enabled".

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{
    has_dangerous_chars, Action, Policy, PolicyVersionStatus, Verdict,
    MAX_LIFECYCLE_IDENTITY_LEN, MAX_VERSION_COMMENT_LEN,
};

use crate::policy_lifecycle::LifecycleError;
use crate::AppState;

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
        LifecycleError::ApprovalRequired(_) => {
            (StatusCode::PRECONDITION_FAILED, e.to_string())
        }
        LifecycleError::CapacityExceeded(_) => {
            (StatusCode::TOO_MANY_REQUESTS, e.to_string())
        }
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
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    if let Err(e) = super::validate_path_param_json(&id, "policy_id") {
        return Err(e);
    }
    let versions = store.list_versions(&id).await.map_err(lifecycle_error_response)?;
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
    Path((id, v)): Path<(String, u64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    if let Err(e) = super::validate_path_param_json(&id, "policy_id") {
        return Err(e);
    }
    let version = store.get_version(&id, v).await.map_err(lifecycle_error_response)?;
    Ok(Json(serde_json::to_value(&version).unwrap_or(json!({}))))
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
    Path(id): Path<String>,
    Json(body): Json<CreateVersionRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    if let Err(e) = super::validate_path_param_json(&id, "policy_id") {
        return Err(e);
    }
    validate_input_string("created_by", &body.created_by, MAX_LIFECYCLE_IDENTITY_LEN)?;
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
        .create_version(&id, body.policy, &body.created_by, body.comment.as_deref())
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
            "created_by": body.created_by,
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
        Json(serde_json::to_value(&version).unwrap_or(json!({}))),
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
    Path((id, v)): Path<(String, u64)>,
    Json(body): Json<ApproveVersionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    if let Err(e) = super::validate_path_param_json(&id, "policy_id") {
        return Err(e);
    }
    validate_input_string("approved_by", &body.approved_by, MAX_LIFECYCLE_IDENTITY_LEN)?;
    if let Some(ref c) = body.comment {
        validate_input_string("comment", c, MAX_VERSION_COMMENT_LEN)?;
    }

    let version = store
        .approve_version(&id, v, &body.approved_by, body.comment.as_deref())
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
            "approved_by": body.approved_by,
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

    Ok(Json(serde_json::to_value(&version).unwrap_or(json!({}))))
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
    Path((id, v)): Path<(String, u64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    if let Err(e) = super::validate_path_param_json(&id, "policy_id") {
        return Err(e);
    }

    // Read the version before promotion to know the original status
    let before = store
        .get_version(&id, v)
        .await
        .map_err(lifecycle_error_response)?;
    let original_status = before.status.clone();

    // Perform the promotion in the store
    let promoted = store
        .promote_version(&id, v)
        .await
        .map_err(lifecycle_error_response)?;

    let event_name = match promoted.status {
        PolicyVersionStatus::Staging => "version_promoted_staging",
        PolicyVersionStatus::Active => "version_promoted_active",
        _ => "version_promoted",
    };

    // If promoted to Active, compile and swap the live policy set
    if matches!(promoted.status, PolicyVersionStatus::Active) {
        // Acquire the write lock to serialize with other policy mutations
        let _guard = state.policy_write_lock.lock().await;
        let snap = state.policy_state.load();

        // Build candidate policy list: replace matching policy or append
        let mut candidate: Vec<Policy> = snap
            .policies
            .iter()
            .filter(|p| p.id != id)
            .cloned()
            .collect();
        candidate.push(promoted.policy.clone());
        PolicyEngine::sort_policies(&mut candidate);

        // Compile-first: verify the new policy set compiles before storing
        match PolicyEngine::with_policies(snap.engine.strict_mode(), &candidate) {
            Ok(compiled_engine) => {
                state.policy_state.store(Arc::new(crate::PolicySnapshot {
                    engine: compiled_engine,
                    policies: candidate,
                    compliance_config: snap.compliance_config.clone(),
                }));
                tracing::info!(
                    "Policy lifecycle: activated policy {} version {}",
                    id,
                    v
                );

                // Clear staging snapshot since we just activated
                state
                    .staging_snapshot
                    .store(Arc::new(None));
            }
            Err(errors) => {
                // SECURITY: Revert the promotion in the store on compile failure.
                // This prevents an inconsistency where the store says Active but
                // the live engine doesn't have the policy.
                let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                tracing::error!(
                    "Policy lifecycle: compile failed on promote, reverting: {:?}",
                    msgs
                );
                if let Err(revert_err) = store
                    .revert_promotion(&id, v, original_status)
                    .await
                {
                    tracing::error!(
                        "Policy lifecycle: failed to revert promotion: {}",
                        revert_err
                    );
                }
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Policy compilation failed — promotion reverted",
                        "policy_id": id,
                    })),
                ));
            }
        }
    } else if matches!(promoted.status, PolicyVersionStatus::Staging) {
        // Build staging snapshot for shadow evaluation
        let snap = state.policy_state.load();
        let mut staging_policies: Vec<Policy> = snap
            .policies
            .iter()
            .filter(|p| p.id != id)
            .cloned()
            .collect();
        staging_policies.push(promoted.policy.clone());
        PolicyEngine::sort_policies(&mut staging_policies);

        match PolicyEngine::with_policies(snap.engine.strict_mode(), &staging_policies) {
            Ok(staging_engine) => {
                state.staging_snapshot.store(Arc::new(Some(
                    crate::StagingSnapshot {
                        engine: staging_engine,
                        policies: staging_policies,
                    },
                )));
                tracing::info!(
                    "Policy lifecycle: staging snapshot built for policy {} version {}",
                    id,
                    v
                );
            }
            Err(errors) => {
                let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                tracing::warn!(
                    "Policy lifecycle: staging snapshot compile failed (non-fatal): {:?}",
                    msgs
                );
                // Non-fatal: staging shadow evaluation just won't be available
            }
        }
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

    Ok(Json(serde_json::to_value(&promoted).unwrap_or(json!({}))))
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
    Path((id, v)): Path<(String, u64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    if let Err(e) = super::validate_path_param_json(&id, "policy_id") {
        return Err(e);
    }

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

    Ok(Json(serde_json::to_value(&version).unwrap_or(json!({}))))
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
    Path(id): Path<String>,
    Json(body): Json<RollbackRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    if let Err(e) = super::validate_path_param_json(&id, "policy_id") {
        return Err(e);
    }
    validate_input_string("created_by", &body.created_by, MAX_LIFECYCLE_IDENTITY_LEN)?;

    let version = store
        .rollback(&id, body.to_version, &body.created_by)
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
            "created_by": body.created_by,
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
        Json(serde_json::to_value(&version).unwrap_or(json!({}))),
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
    Path((id, v1, v2)): Path<(String, u64, u64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    if let Err(e) = super::validate_path_param_json(&id, "policy_id") {
        return Err(e);
    }
    let diff = store
        .diff_versions(&id, v1, v2)
        .await
        .map_err(lifecycle_error_response)?;
    Ok(Json(serde_json::to_value(&diff).unwrap_or(json!({}))))
}

/// GET /api/policy-lifecycle/status
///
/// Return lifecycle subsystem status.
#[tracing::instrument(name = "vellaveto.policy_lifecycle_status", skip(state))]
pub async fn lifecycle_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = get_store(&state)?;
    let status = store.status().await;
    Ok(Json(serde_json::to_value(&status).unwrap_or(json!({}))))
}
