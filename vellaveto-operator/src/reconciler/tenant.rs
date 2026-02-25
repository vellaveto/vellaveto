//! VellavetoTenant reconciler.
//!
//! Watches `VellavetoTenant` CRDs and syncs tenant definitions to the
//! Vellaveto server via its REST API.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
use kube::ResourceExt;
use serde_json::json;
use tracing::{error, info, warn};

use crate::client::{ApiTenantQuotas, TenantRequest};
use crate::crd::{Condition, VellavetoTenant, VellavetoTenantStatus};
use crate::error::OperatorError;

use super::Context;

/// Finalizer name for tenant cleanup on CRD deletion.
const TENANT_FINALIZER: &str = "vellaveto.io/tenant-cleanup";

/// Requeue interval for drift detection.
const REQUEUE_INTERVAL: Duration = Duration::from_secs(60);

/// Requeue interval after transient failure.
const ERROR_REQUEUE_INTERVAL: Duration = Duration::from_secs(30);

/// Reconcile a VellavetoTenant resource.
pub async fn reconcile_tenant(
    tenant: Arc<VellavetoTenant>,
    ctx: Arc<Context>,
) -> Result<Action, OperatorError> {
    let name = tenant.name_any();
    let namespace = tenant
        .namespace()
        .ok_or_else(|| OperatorError::Config("tenant must be namespaced".into()))?;

    info!(tenant = %name, namespace = %namespace, "reconciling VellavetoTenant");

    // Validate spec
    if let Err(e) = tenant.spec.validate() {
        warn!(tenant = %name, error = %e, "invalid VellavetoTenant spec");
        update_tenant_status(
            &ctx.kube_client,
            &name,
            &namespace,
            false,
            Some(&format!("Validation failed: {e}")),
            tenant.metadata.generation.unwrap_or(0),
        )
        .await?;
        return Ok(Action::await_change());
    }

    let api: Api<VellavetoTenant> = Api::namespaced(ctx.kube_client.clone(), &namespace);

    let ctx_clone = ctx.clone();
    let ns = namespace.clone();

    finalizer(&api, TENANT_FINALIZER, tenant, |event| async {
        match event {
            FinalizerEvent::Apply(tenant) => {
                apply_tenant(&ctx_clone, &tenant, &ns).await
            }
            FinalizerEvent::Cleanup(tenant) => {
                cleanup_tenant(&ctx_clone, &tenant, &ns).await
            }
        }
    })
    .await
    .map_err(|e| OperatorError::Finalizer(format!("finalizer error: {e}")))
}

/// Error policy for VellavetoTenant reconciliation failures.
pub fn error_policy_tenant(
    _tenant: Arc<VellavetoTenant>,
    err: &OperatorError,
    _ctx: Arc<Context>,
) -> Action {
    error!(error = %err, "VellavetoTenant reconciliation error");
    Action::requeue(ERROR_REQUEUE_INTERVAL)
}

/// Apply (create/update) a tenant on the Vellaveto server.
async fn apply_tenant(
    ctx: &Arc<Context>,
    tenant: &VellavetoTenant,
    namespace: &str,
) -> Result<Action, OperatorError> {
    let name = tenant.name_any();
    let cluster_ref = &tenant.spec.cluster_ref;
    let tenant_id = &tenant.spec.tenant_id;

    let client = ctx.get_api_client(cluster_ref, namespace)?;

    // Build request
    let req = spec_to_tenant_request(&tenant.spec);

    // Check if tenant exists
    match client.get_tenant(tenant_id).await {
        Ok(Some(_existing)) => {
            // Update existing tenant
            client
                .update_tenant(tenant_id, &req)
                .await
                .map_err(|e| OperatorError::Api(format!("failed to update tenant: {e}")))?;
            info!(tenant = %name, tenant_id = %tenant_id, "tenant updated on cluster");
        }
        Ok(None) => {
            // Create new tenant
            client
                .create_tenant(&req)
                .await
                .map_err(|e| OperatorError::Api(format!("failed to create tenant: {e}")))?;
            info!(tenant = %name, tenant_id = %tenant_id, "tenant created on cluster");
        }
        Err(e) => {
            warn!(
                tenant = %name,
                error = %e,
                "failed to check tenant existence, attempting create"
            );
            // Try create — it will fail with conflict if exists
            client
                .create_tenant(&req)
                .await
                .map_err(|e| OperatorError::Api(format!("failed to create tenant: {e}")))?;
        }
    }

    // Update status
    update_tenant_status(
        &ctx.kube_client,
        &name,
        namespace,
        true,
        None,
        tenant.metadata.generation.unwrap_or(0),
    )
    .await?;

    Ok(Action::requeue(REQUEUE_INTERVAL))
}

/// Clean up (delete) a tenant from the Vellaveto server when the CRD is deleted.
async fn cleanup_tenant(
    ctx: &Arc<Context>,
    tenant: &VellavetoTenant,
    namespace: &str,
) -> Result<Action, OperatorError> {
    let name = tenant.name_any();
    let cluster_ref = &tenant.spec.cluster_ref;
    let tenant_id = &tenant.spec.tenant_id;

    info!(tenant = %name, tenant_id = %tenant_id, "cleaning up VellavetoTenant");

    match ctx.get_api_client(cluster_ref, namespace) {
        Ok(client) => {
            if let Err(e) = client.delete_tenant(tenant_id).await {
                warn!(
                    tenant = %name,
                    error = %e,
                    "failed to delete tenant during cleanup (cluster may be unavailable)"
                );
            }
        }
        Err(e) => {
            warn!(
                tenant = %name,
                error = %e,
                "failed to build API client during cleanup"
            );
        }
    }

    Ok(Action::await_change())
}

/// Convert CRD TenantSpec to API TenantRequest.
fn spec_to_tenant_request(spec: &crate::crd::VellavetoTenantSpec) -> TenantRequest {
    let quotas = spec.quotas.as_ref().map(|q| ApiTenantQuotas {
        max_evaluations_per_minute: q.max_evaluations_per_minute.unwrap_or(10_000),
        max_policies: q.max_policies.unwrap_or(1_000),
        max_pending_approvals: q.max_pending_approvals.unwrap_or(100),
        max_audit_retention_days: q.max_audit_retention_days.unwrap_or(90),
        max_request_body_bytes: 1_048_576,
    });

    let metadata: HashMap<String, String> = spec
        .metadata
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    TenantRequest {
        id: spec.tenant_id.clone(),
        name: spec.name.clone(),
        enabled: spec.enabled,
        quotas,
        metadata,
    }
}

/// Update the VellavetoTenant status subresource.
async fn update_tenant_status(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    synced: bool,
    error_msg: Option<&str>,
    generation: i64,
) -> Result<(), OperatorError> {
    let api: Api<VellavetoTenant> = Api::namespaced(client.clone(), namespace);

    let now = chrono::Utc::now().to_rfc3339();
    let mut conditions = vec![Condition::new(
        "Synced",
        if synced { "True" } else { "False" },
        Some(now.clone()),
        if synced {
            Some("SyncSuccessful".into())
        } else {
            Some("SyncFailed".into())
        },
        error_msg.map(String::from),
    )];

    if let Some(msg) = error_msg {
        conditions.push(Condition::new(
            "Error",
            "True",
            Some(now.clone()),
            Some("ReconcileError".into()),
            Some(msg.to_string()),
        ));
    }

    let status = VellavetoTenantStatus {
        synced,
        last_sync_time: if synced { Some(now) } else { None },
        last_error: error_msg.map(String::from),
        conditions,
        observed_generation: generation,
    };

    let patch = json!({ "status": status });
    let pp = PatchParams::apply("vellaveto-operator").force();
    api.patch_status(name, &pp, &Patch::Merge(patch)).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{TenantQuotasSpec, VellavetoTenantSpec};
    use std::collections::BTreeMap;

    #[test]
    fn test_spec_to_tenant_request_basic() {
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "acme".into(),
            name: "ACME Corp".into(),
            enabled: true,
            quotas: None,
            metadata: None,
        };
        let req = spec_to_tenant_request(&spec);
        assert_eq!(req.id, "acme");
        assert_eq!(req.name, "ACME Corp");
        assert!(req.enabled);
        assert!(req.quotas.is_none());
    }

    #[test]
    fn test_spec_to_tenant_request_with_quotas() {
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "test".into(),
            name: "Test Tenant".into(),
            enabled: false,
            quotas: Some(TenantQuotasSpec {
                max_evaluations_per_minute: Some(5000),
                max_policies: Some(50),
                max_pending_approvals: None,
                max_audit_retention_days: Some(30),
            }),
            metadata: None,
        };
        let req = spec_to_tenant_request(&spec);
        assert!(!req.enabled);
        let q = req.quotas.unwrap();
        assert_eq!(q.max_evaluations_per_minute, 5000);
        assert_eq!(q.max_policies, 50);
        assert_eq!(q.max_pending_approvals, 100); // default
        assert_eq!(q.max_audit_retention_days, 30);
    }

    #[test]
    fn test_spec_to_tenant_request_with_metadata() {
        let mut md = BTreeMap::new();
        md.insert("env".into(), "production".into());
        md.insert("team".into(), "platform".into());

        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "test".into(),
            name: "Test".into(),
            enabled: true,
            quotas: None,
            metadata: Some(md),
        };
        let req = spec_to_tenant_request(&spec);
        assert_eq!(req.metadata.len(), 2);
        assert_eq!(req.metadata.get("env").unwrap(), "production");
    }
}
