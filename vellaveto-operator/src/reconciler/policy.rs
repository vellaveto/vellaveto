//! VellavetoPolicy reconciler.
//!
//! Watches `VellavetoPolicy` CRDs and syncs policy definitions to the
//! Vellaveto server via its REST API. Supports drift detection by comparing
//! CRD spec against server state on each reconcile.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
use kube::ResourceExt;
use serde_json::json;
use tracing::{error, info, warn};

use crate::client::{ApiIpRules, ApiNetworkRules, ApiPathRules, ApiPolicy};
use crate::crd::{Condition, VellavetoPolicy, VellavetoPolicyStatus};
use crate::error::OperatorError;

use super::Context;

/// Finalizer name for policy cleanup on CRD deletion.
const POLICY_FINALIZER: &str = "vellaveto.io/policy-cleanup";

/// Requeue interval for drift detection.
const REQUEUE_INTERVAL: Duration = Duration::from_secs(60);

/// Requeue interval after transient failure.
const ERROR_REQUEUE_INTERVAL: Duration = Duration::from_secs(30);

/// Reconcile a VellavetoPolicy resource.
pub async fn reconcile_policy(
    policy: Arc<VellavetoPolicy>,
    ctx: Arc<Context>,
) -> Result<Action, OperatorError> {
    let name = policy.name_any();
    let namespace = policy
        .namespace()
        .ok_or_else(|| OperatorError::Config("policy must be namespaced".into()))?;

    info!(policy = %name, namespace = %namespace, "reconciling VellavetoPolicy");

    // Validate spec
    if let Err(e) = policy.spec.validate() {
        warn!(policy = %name, error = %e, "invalid VellavetoPolicy spec");
        update_policy_status(
            &ctx.kube_client,
            &name,
            &namespace,
            false,
            Some(&format!("Validation failed: {e}")),
            policy.metadata.generation.unwrap_or(0),
        )
        .await?;
        return Ok(Action::await_change());
    }

    let api: Api<VellavetoPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);

    // Use finalizer pattern for cleanup on delete
    let ctx_clone = ctx.clone();
    let ns = namespace.clone();

    finalizer(&api, POLICY_FINALIZER, policy, |event| async {
        match event {
            FinalizerEvent::Apply(policy) => {
                apply_policy(&ctx_clone, &policy, &ns).await
            }
            FinalizerEvent::Cleanup(policy) => {
                cleanup_policy(&ctx_clone, &policy, &ns).await
            }
        }
    })
    .await
    .map_err(|e| OperatorError::Finalizer(format!("finalizer error: {e}")))
}

/// Error policy for VellavetoPolicy reconciliation failures.
pub fn error_policy_policy(
    _policy: Arc<VellavetoPolicy>,
    err: &OperatorError,
    _ctx: Arc<Context>,
) -> Action {
    error!(error = %err, "VellavetoPolicy reconciliation error");
    Action::requeue(ERROR_REQUEUE_INTERVAL)
}

/// Apply (create/update) a policy on the Vellaveto server.
async fn apply_policy(
    ctx: &Arc<Context>,
    policy: &VellavetoPolicy,
    namespace: &str,
) -> Result<Action, OperatorError> {
    let name = policy.name_any();
    let cluster_ref = &policy.spec.cluster_ref;

    let client = ctx.get_api_client(cluster_ref, namespace)?;

    // Convert CRD spec to API policy
    let api_policy = spec_to_api_policy(&policy.spec.policy);

    // Upsert via add_policy (server handles upsert semantics).
    // Avoid delete-then-add to prevent availability gaps.
    client.add_policy(&api_policy).await.map_err(|e| {
        OperatorError::Api(format!("failed to sync policy {}: {e}", api_policy.id))
    })?;

    info!(policy = %name, policy_id = %api_policy.id, "policy synced to cluster");

    // Update status
    update_policy_status(
        &ctx.kube_client,
        &name,
        namespace,
        true,
        None,
        policy.metadata.generation.unwrap_or(0),
    )
    .await?;

    Ok(Action::requeue(REQUEUE_INTERVAL))
}

/// Clean up (delete) a policy from the Vellaveto server when the CRD is deleted.
async fn cleanup_policy(
    ctx: &Arc<Context>,
    policy: &VellavetoPolicy,
    namespace: &str,
) -> Result<Action, OperatorError> {
    let name = policy.name_any();
    let cluster_ref = &policy.spec.cluster_ref;
    let policy_id = &policy.spec.policy.id;

    info!(policy = %name, policy_id = %policy_id, "cleaning up VellavetoPolicy");

    match ctx.get_api_client(cluster_ref, namespace) {
        Ok(client) => {
            if let Err(e) = client.delete_policy(policy_id).await {
                // Log but don't block finalizer removal — the cluster may be gone
                warn!(
                    policy = %name,
                    error = %e,
                    "failed to delete policy during cleanup (cluster may be unavailable)"
                );
            }
        }
        Err(e) => {
            warn!(
                policy = %name,
                error = %e,
                "failed to build API client during cleanup"
            );
        }
    }

    Ok(Action::await_change())
}

/// Convert CRD PolicySpec to API PolicySpec for the HTTP client.
fn spec_to_api_policy(spec: &crate::crd::PolicySpec) -> ApiPolicy {
    let path_rules = spec.path_rules.as_ref().map(|pr| ApiPathRules {
        allowed: pr.allowed.clone(),
        blocked: pr.blocked.clone(),
    });

    let network_rules = spec.network_rules.as_ref().map(|nr| ApiNetworkRules {
        allowed_domains: nr.allowed_domains.clone(),
        blocked_domains: nr.blocked_domains.clone(),
        ip_rules: nr.ip_rules.as_ref().map(|ip| ApiIpRules {
            block_private: ip.block_private,
            blocked_cidrs: ip.blocked_cidrs.clone(),
            allowed_cidrs: ip.allowed_cidrs.clone(),
        }),
    });

    ApiPolicy {
        id: spec.id.clone(),
        name: spec.name.clone(),
        policy_type: spec.policy_type.clone(),
        priority: spec.priority,
        path_rules,
        network_rules,
        conditions: spec.conditions.clone(),
    }
}

/// Update the VellavetoPolicy status subresource.
async fn update_policy_status(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    synced: bool,
    error_msg: Option<&str>,
    generation: i64,
) -> Result<(), OperatorError> {
    let api: Api<VellavetoPolicy> = Api::namespaced(client.clone(), namespace);

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

    let status = VellavetoPolicyStatus {
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
    use crate::crd::{NetworkRulesSpec, PathRulesSpec, PolicySpec};

    #[test]
    fn test_spec_to_api_policy_allow() {
        let spec = PolicySpec {
            id: "pol-1".into(),
            name: "Allow reads".into(),
            policy_type: "Allow".into(),
            priority: 10,
            conditions: None,
            path_rules: Some(PathRulesSpec {
                allowed: vec!["/data/**".into()],
                blocked: vec!["/data/secret/**".into()],
            }),
            network_rules: None,
        };
        let api = spec_to_api_policy(&spec);
        assert_eq!(api.id, "pol-1");
        assert_eq!(api.policy_type, "Allow");
        assert!(api.path_rules.is_some());
        assert_eq!(api.path_rules.as_ref().unwrap().allowed.len(), 1);
    }

    #[test]
    fn test_spec_to_api_policy_with_network_rules() {
        let spec = PolicySpec {
            id: "pol-2".into(),
            name: "Network deny".into(),
            policy_type: "Deny".into(),
            priority: 20,
            conditions: None,
            path_rules: None,
            network_rules: Some(NetworkRulesSpec {
                allowed_domains: vec!["example.com".into()],
                blocked_domains: vec!["evil.com".into()],
                ip_rules: Some(crate::crd::IpRulesSpec {
                    block_private: true,
                    blocked_cidrs: vec!["10.0.0.0/8".into()],
                    allowed_cidrs: vec![],
                }),
            }),
        };
        let api = spec_to_api_policy(&spec);
        assert!(api.network_rules.is_some());
        let nr = api.network_rules.unwrap();
        assert!(nr.ip_rules.is_some());
        assert!(nr.ip_rules.unwrap().block_private);
    }

    #[test]
    fn test_spec_to_api_policy_conditional() {
        let spec = PolicySpec {
            id: "pol-3".into(),
            name: "Conditional".into(),
            policy_type: "Conditional".into(),
            priority: 5,
            conditions: Some(serde_json::json!({"time_window": {"after": "09:00", "before": "17:00"}})),
            path_rules: None,
            network_rules: None,
        };
        let api = spec_to_api_policy(&spec);
        assert_eq!(api.policy_type, "Conditional");
        assert!(api.conditions.is_some());
    }
}
