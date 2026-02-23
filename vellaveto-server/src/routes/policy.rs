//! Policy management route handlers.
//!
//! This module provides REST API endpoints for policy CRUD operations
//! and hot-reload functionality.
//!
//! Endpoints:
//! - `GET /api/policies` - List all policies
//! - `POST /api/policies` - Add a new policy
//! - `DELETE /api/policies/{id}` - Remove a policy by ID
//! - `POST /api/policies/reload` - Reload policies from config file

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde_json::json;
use std::sync::Arc;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, Verdict};

use crate::routes::ErrorResponse;
use crate::tenant::TenantContext;
use crate::AppState;

/// List all policies.
///
/// GET /api/policies
#[tracing::instrument(name = "vellaveto.list_policies", skip(state))]
pub async fn list_policies(State(state): State<AppState>) -> Json<Vec<Policy>> {
    let snap = state.policy_state.load();
    Json(snap.policies.clone())
}

/// Add a new policy.
///
/// POST /api/policies
///
/// # Security
///
/// - Validates policy id and name (non-empty, max 256 chars, no control chars)
/// - Caps dynamic policy priority at ±1000 to prevent shadowing config-loaded deny rules
/// - Rejects wildcard-only IDs (`*`, `*:*`) to prevent global allow rules via API
/// - Uses compile-first validation to ensure the policy set remains valid
/// - Serializes with other policy mutations via write lock
#[tracing::instrument(
    name = "vellaveto.add_policy",
    skip(state),
    fields(policy_id = %policy.id)
)]
pub async fn add_policy(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    Json(policy): Json<Policy>,
) -> (StatusCode, Json<serde_json::Value>) {
    // SECURITY (R12-SRV-1): Validate policy fields before insertion.
    // Without validation, an attacker could POST a policy with id="*",
    // policy_type=Allow, priority=999999 to override all deny policies.

    // 1. Validate id: non-empty, no control chars, max 256 chars
    if policy.id.is_empty() || policy.id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy id must be non-empty"})),
        );
    }
    if policy.id.len() > 256 || policy.id.chars().any(crate::routes::is_unsafe_char) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy id contains invalid characters or exceeds 256 chars"})),
        );
    }

    // 2. Validate name: non-empty, no control chars, max 256 chars
    if policy.name.is_empty() || policy.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy name must be non-empty"})),
        );
    }
    if policy.name.len() > 256 || policy.name.chars().any(crate::routes::is_unsafe_char) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Policy name contains invalid characters or exceeds 256 chars"})),
        );
    }

    // 3. Validate priority is within a reasonable range.
    // SECURITY (R17-POL-1): Dynamic policies added via API are capped at ±1000
    // to prevent an attacker from shadowing config-loaded deny policies with
    // a max-priority Allow rule.
    if policy.priority < -1_000 || policy.priority > 1_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Dynamic policy priority must be between -1000 and 1000"})),
        );
    }

    // SECURITY (R17-POL-2): Reject wildcard-only IDs that match ALL tools.
    // An attacker with API access could POST id="*", type=Allow, priority=1000
    // to override all deny rules. Require at least a colon-separated scope.
    {
        let id_trimmed = policy.id.trim();
        if id_trimmed == "*" || id_trimmed == "*:*" {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({"error": "Wildcard-only policy IDs ('*', '*:*') are not allowed via API"}),
                ),
            );
        }
    }

    // SECURITY (R15-RACE-*): Hold write lock for the entire read-modify-write
    // sequence. This prevents TOCTOU races (duplicate-ID check, lost updates,
    // stale max-count check) between concurrent add/remove/reload operations.
    // The read path (evaluate) remains lock-free via ArcSwap::load().
    let _guard = state.policy_write_lock.lock().await;

    // 4. Reject duplicate policy IDs
    let existing = state.policy_state.load();
    if existing.policies.iter().any(|p| p.id == policy.id) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": format!("Policy with id '{}' already exists", policy.id)})),
        );
    }

    // 5. Enforce max policy count (prevent resource exhaustion)
    if existing.policies.len() >= 10_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Maximum policy count (10000) reached"})),
        );
    }

    // Phase 44: Enforce per-tenant max_policies quota.
    // Default tenant has unlimited quotas, so this only applies to named tenants.
    if let Some(ref quotas) = tenant_ctx.quotas {
        if quotas.max_policies < u64::MAX {
            let tenant_policy_count = existing
                .policies
                .iter()
                .filter(|p| tenant_ctx.policy_matches(&p.id))
                .count() as u64;
            if tenant_policy_count >= quotas.max_policies {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "error": format!(
                            "Tenant policy quota exceeded ({}/{})",
                            tenant_policy_count, quotas.max_policies
                        )
                    })),
                );
            }
        }
    }

    // Build candidate policy list
    let id = policy.id.clone();
    let mut candidate = existing.policies.clone();
    candidate.push(policy.clone());
    PolicyEngine::sort_policies(&mut candidate);

    // Compile-first: verify the new policy set compiles before storing
    match PolicyEngine::with_policies(false, &candidate) {
        Ok(compiled_engine) => {
            // SECURITY (R15-CFG-2): Single atomic swap of engine + policies.
            state.policy_state.store(Arc::new(crate::PolicySnapshot {
                engine: compiled_engine,
                policies: candidate,
                compliance_config: state.policy_state.load().compliance_config.clone(),
            }));
            tracing::info!("Added policy: {}", id);
        }
        Err(errors) => {
            // SECURITY (R26-SRV-5): Log detailed errors server-side but return
            // generic message to the client. Detailed compiler errors can leak
            // regex patterns and rule structures from existing policies.
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            tracing::warn!("add_policy rejected: compilation failed: {:?}", msgs);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Policy validation failed — policy NOT added",
                    "policy_id": id,
                })),
            );
        }
    }

    // Audit trail for policy mutation
    let action = Action::new("vellaveto", "add_policy", json!({"policy_id": id}));
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "policy_added"}),
        )
        .await
    {
        tracing::warn!("Failed to audit add_policy: {}", e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    (StatusCode::CREATED, Json(json!({"added": id})))
}

/// Remove a policy by ID.
///
/// DELETE /api/policies/{id}
///
/// # Security
///
/// - Validates the policy ID (non-empty, max 256 chars, no control chars)
/// - Uses compile-first validation to ensure the remaining policy set is valid
/// - Serializes with other policy mutations via write lock
#[tracing::instrument(
    name = "vellaveto.remove_policy",
    skip(state),
    fields(policy_id = %id)
)]
pub async fn remove_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // SECURITY (R23-SRV-4): Validate the path param (same rules as add_policy).
    if id.is_empty() || id.len() > 256 || id.chars().any(crate::routes::is_unsafe_char) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid policy id"})),
        );
    }

    // SECURITY (R15-RACE-*): Serialize with other policy mutations.
    let _guard = state.policy_write_lock.lock().await;

    let existing = state.policy_state.load();
    let candidate: Vec<Policy> = existing
        .policies
        .iter()
        .filter(|p| p.id != id)
        .cloned()
        .collect();
    let removed = existing.policies.len().saturating_sub(candidate.len());

    if removed == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("No policy with id '{}'", id)})),
        );
    }

    // Compile-first: verify the remaining set compiles before storing
    match PolicyEngine::with_policies(false, &candidate) {
        Ok(compiled_engine) => {
            // SECURITY (R15-CFG-2): Single atomic swap of engine + policies.
            state.policy_state.store(Arc::new(crate::PolicySnapshot {
                engine: compiled_engine,
                policies: candidate,
                compliance_config: state.policy_state.load().compliance_config.clone(),
            }));
            tracing::info!("Removed {} policy(ies) with id: {}", removed, id);
        }
        Err(errors) => {
            // This is unlikely (removing a policy shouldn't break compilation)
            // but we stay fail-closed.
            let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            tracing::error!("remove_policy rejected: recompilation failed: {:?}", msgs);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Policy recompilation failed after removal — no changes applied",
                })),
            );
        }
    }

    // Audit trail for policy mutation
    let action = Action::new(
        "vellaveto",
        "remove_policy",
        json!({"policy_id": id, "removed_count": removed}),
    );
    if let Err(e) = state
        .audit
        .log_entry(
            &action,
            &Verdict::Allow,
            json!({"source": "api", "event": "policy_removed"}),
        )
        .await
    {
        tracing::warn!("Failed to audit remove_policy: {}", e);
    } else {
        crate::metrics::increment_audit_entries();
    }

    (StatusCode::OK, Json(json!({"removed": removed, "id": id})))
}

/// Reload policies from the configuration file.
///
/// POST /api/policies/reload
///
/// This endpoint triggers a hot-reload of policies from the configured
/// policy file without restarting the server.
#[tracing::instrument(name = "vellaveto.reload_policies", skip(state))]
pub async fn reload_policies(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let count = crate::reload_policies_from_file(&state, "api")
        .await
        .map_err(|e| {
            tracing::error!("{}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to reload policy configuration".to_string(),
                }),
            )
        })?;

    // SECURITY (R10-9): Do not return the full filesystem path in the response.
    // It leaks deployment layout information to any authenticated caller.
    Ok(Json(json!({"reloaded": count, "status": "ok"})))
}
