//! VellavetoCluster reconciler.
//!
//! Watches `VellavetoCluster` CRDs and reconciles the desired state by
//! managing Kubernetes child resources (StatefulSet, Service, ConfigMap)
//! via the Kubernetes API.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Service};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use serde_json::json;
use tracing::{error, info, warn};

use crate::crd::{ClusterPhase, Condition, VellavetoCluster, VellavetoClusterStatus};
use crate::error::OperatorError;

use super::Context;

/// Default requeue interval for successful reconciliation.
const REQUEUE_INTERVAL: Duration = Duration::from_secs(60);

/// Requeue interval after transient failure.
const ERROR_REQUEUE_INTERVAL: Duration = Duration::from_secs(30);

/// Label key for operator-managed resources.
const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";

/// Label value for operator-managed resources.
const MANAGED_BY_VALUE: &str = "vellaveto-operator";

/// Label key for cluster name.
const CLUSTER_LABEL: &str = "vellaveto.io/cluster";

/// Reconcile a VellavetoCluster resource.
///
/// Creates or updates child resources (ConfigMap, StatefulSet, Service)
/// to match the desired spec, then updates the CRD status.
pub async fn reconcile_cluster(
    cluster: Arc<VellavetoCluster>,
    ctx: Arc<Context>,
) -> Result<Action, OperatorError> {
    let name = cluster.name_any();
    let namespace = cluster
        .namespace()
        .ok_or_else(|| OperatorError::Config("cluster must be namespaced".into()))?;

    info!(cluster = %name, namespace = %namespace, "reconciling VellavetoCluster");

    // Validate spec
    if let Err(e) = cluster.spec.validate() {
        warn!(cluster = %name, error = %e, "invalid VellavetoCluster spec");
        update_cluster_status(
            &ctx.kube_client,
            &name,
            &namespace,
            ClusterPhase::Failed,
            0,
            0,
            Some(&format!("Validation failed: {e}")),
            cluster.metadata.generation.unwrap_or(0),
        )
        .await?;
        // Do not requeue — permanent error until spec is fixed
        return Ok(Action::await_change());
    }

    // Ensure ConfigMap
    ensure_configmap(&ctx.kube_client, &cluster, &namespace).await?;

    // Ensure StatefulSet
    ensure_statefulset(&ctx.kube_client, &cluster, &namespace).await?;

    // Ensure Service
    ensure_service(&ctx.kube_client, &cluster, &namespace).await?;

    // Check readiness
    let (replicas, ready_replicas) =
        get_statefulset_status(&ctx.kube_client, &name, &namespace).await;

    let phase = if ready_replicas >= cluster.spec.replicas {
        ClusterPhase::Running
    } else {
        ClusterPhase::Pending
    };

    update_cluster_status(
        &ctx.kube_client,
        &name,
        &namespace,
        phase,
        replicas,
        ready_replicas,
        None,
        cluster.metadata.generation.unwrap_or(0),
    )
    .await?;

    info!(
        cluster = %name,
        replicas = replicas,
        ready = ready_replicas,
        "VellavetoCluster reconciliation complete"
    );

    Ok(Action::requeue(REQUEUE_INTERVAL))
}

/// Error policy — determines requeue behavior on reconciliation failure.
pub fn error_policy_cluster(
    _cluster: Arc<VellavetoCluster>,
    err: &OperatorError,
    _ctx: Arc<Context>,
) -> Action {
    error!(error = %err, "VellavetoCluster reconciliation error");
    Action::requeue(ERROR_REQUEUE_INTERVAL)
}

/// Ensure the ConfigMap for the Vellaveto server configuration exists.
async fn ensure_configmap(
    client: &kube::Client,
    cluster: &VellavetoCluster,
    namespace: &str,
) -> Result<(), OperatorError> {
    let name = cluster.name_any();
    let cm_name = format!("{name}-config");
    let api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

    // Generate TOML config from overrides
    let config_toml = generate_config_toml(&cluster.spec.config);

    let cm = ConfigMap {
        metadata: ObjectMeta {
            name: Some(cm_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(managed_labels(&name)),
            owner_references: Some(vec![owner_reference(cluster)]),
            ..Default::default()
        },
        data: Some({
            let mut data = std::collections::BTreeMap::new();
            data.insert("vellaveto.toml".to_string(), config_toml);
            data
        }),
        ..Default::default()
    };

    let patch = Patch::Apply(cm);
    let params = PatchParams::apply(MANAGED_BY_VALUE).force();
    api.patch(&cm_name, &params, &patch).await?;

    Ok(())
}

/// Ensure the StatefulSet for the Vellaveto server pods exists.
async fn ensure_statefulset(
    client: &kube::Client,
    cluster: &VellavetoCluster,
    namespace: &str,
) -> Result<(), OperatorError> {
    let name = cluster.name_any();
    let api: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);

    let resources = build_resource_requirements(&cluster.spec.resources);

    let sts = serde_json::from_value::<StatefulSet>(json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": managed_labels(&name),
            "ownerReferences": [owner_reference_json(cluster)]
        },
        "spec": {
            "replicas": cluster.spec.replicas,
            "serviceName": format!("{name}-headless"),
            "selector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "vellaveto",
                    CLUSTER_LABEL: name
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/name": "vellaveto",
                        MANAGED_BY_LABEL: MANAGED_BY_VALUE,
                        CLUSTER_LABEL: name
                    }
                },
                "spec": {
                    "securityContext": {
                        "runAsNonRoot": true,
                        "runAsUser": 1000,
                        "fsGroup": 1000
                    },
                    "containers": [{
                        "name": "vellaveto",
                        "image": &cluster.spec.image,
                        "ports": [
                            { "name": "http", "containerPort": 3000 }
                        ],
                        "resources": resources,
                        "volumeMounts": [{
                            "name": "config",
                            "mountPath": "/etc/vellaveto",
                            "readOnly": true
                        }, {
                            "name": "data",
                            "mountPath": "/var/lib/vellaveto"
                        }],
                        "livenessProbe": {
                            "httpGet": { "path": "/health", "port": 3000 },
                            "initialDelaySeconds": 10,
                            "periodSeconds": 30
                        },
                        "readinessProbe": {
                            "httpGet": { "path": "/health", "port": 3000 },
                            "initialDelaySeconds": 5,
                            "periodSeconds": 10
                        },
                        "securityContext": {
                            "readOnlyRootFilesystem": true,
                            "allowPrivilegeEscalation": false,
                            "capabilities": { "drop": ["ALL"] }
                        }
                    }],
                    "volumes": [{
                        "name": "config",
                        "configMap": {
                            "name": format!("{name}-config")
                        }
                    }]
                }
            },
            "volumeClaimTemplates": [{
                "metadata": { "name": "data" },
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "resources": {
                        "requests": { "storage": "1Gi" }
                    }
                }
            }]
        }
    }))
    .map_err(|e| OperatorError::Api(format!("failed to build StatefulSet: {e}")))?;

    let patch = Patch::Apply(sts);
    let params = PatchParams::apply(MANAGED_BY_VALUE).force();
    api.patch(&name, &params, &patch).await?;

    Ok(())
}

/// Ensure headless and ClusterIP services exist.
async fn ensure_service(
    client: &kube::Client,
    cluster: &VellavetoCluster,
    namespace: &str,
) -> Result<(), OperatorError> {
    let name = cluster.name_any();

    // Headless service for StatefulSet
    let headless_name = format!("{name}-headless");
    let headless_api: Api<Service> = Api::namespaced(client.clone(), namespace);

    let headless = serde_json::from_value::<Service>(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": headless_name,
            "namespace": namespace,
            "labels": managed_labels(&name),
            "ownerReferences": [owner_reference_json(cluster)]
        },
        "spec": {
            "clusterIP": "None",
            "selector": {
                "app.kubernetes.io/name": "vellaveto",
                CLUSTER_LABEL: name
            },
            "ports": [{
                "name": "http",
                "port": 3000,
                "targetPort": 3000
            }]
        }
    }))
    .map_err(|e| OperatorError::Api(format!("failed to build headless Service: {e}")))?;

    let patch = Patch::Apply(headless);
    let params = PatchParams::apply(MANAGED_BY_VALUE).force();
    headless_api.patch(&headless_name, &params, &patch).await?;

    // ClusterIP service
    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);

    let svc = serde_json::from_value::<Service>(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": managed_labels(&name),
            "ownerReferences": [owner_reference_json(cluster)]
        },
        "spec": {
            "type": "ClusterIP",
            "selector": {
                "app.kubernetes.io/name": "vellaveto",
                CLUSTER_LABEL: name
            },
            "ports": [{
                "name": "http",
                "port": 3000,
                "targetPort": 3000
            }]
        }
    }))
    .map_err(|e| OperatorError::Api(format!("failed to build Service: {e}")))?;

    let patch = Patch::Apply(svc);
    let params = PatchParams::apply(MANAGED_BY_VALUE).force();
    svc_api.patch(&name, &params, &patch).await?;

    Ok(())
}

/// Get the current replica status from the StatefulSet.
async fn get_statefulset_status(
    client: &kube::Client,
    name: &str,
    namespace: &str,
) -> (i32, i32) {
    let api: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
    match api.get(name).await {
        Ok(sts) => {
            let replicas = sts.status.as_ref().map_or(0, |s| s.replicas);
            let ready = sts.status.as_ref().map_or(0, |s| s.ready_replicas.unwrap_or(0));
            (replicas, ready)
        }
        Err(e) => {
            warn!(name = %name, error = %e, "failed to get StatefulSet status");
            (0, 0)
        }
    }
}

/// Update the VellavetoCluster status subresource.
#[allow(clippy::too_many_arguments)]
async fn update_cluster_status(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    phase: ClusterPhase,
    replicas: i32,
    ready_replicas: i32,
    error_msg: Option<&str>,
    generation: i64,
) -> Result<(), OperatorError> {
    let api: Api<VellavetoCluster> = Api::namespaced(client.clone(), namespace);

    let now = chrono::Utc::now().to_rfc3339();
    let mut conditions = vec![Condition {
        condition_type: "Available".into(),
        status: if phase == ClusterPhase::Running {
            "True".into()
        } else {
            "False".into()
        },
        last_transition_time: Some(now.clone()),
        reason: Some(format!("{:?}", phase)),
        message: error_msg.map(String::from),
    }];

    if let Some(msg) = error_msg {
        conditions.push(Condition {
            condition_type: "Error".into(),
            status: "True".into(),
            last_transition_time: Some(now),
            reason: Some("ValidationFailed".into()),
            message: Some(msg.to_string()),
        });
    }

    let status = VellavetoClusterStatus {
        phase,
        replicas,
        ready_replicas,
        conditions,
        observed_generation: generation,
    };

    let patch = json!({ "status": status });
    let pp = PatchParams::apply(MANAGED_BY_VALUE).force();
    api.patch_status(name, &pp, &Patch::Merge(patch)).await?;

    Ok(())
}

/// Generate TOML config from CRD overrides.
fn generate_config_toml(
    overrides: &Option<crate::crd::VellavetoConfigOverrides>,
) -> String {
    let mut lines = vec![
        "# Generated by vellaveto-operator".to_string(),
        "# Do not edit manually — changes will be overwritten".to_string(),
        String::new(),
    ];

    if let Some(ref config) = overrides {
        if let Some(ref mode) = config.security_mode {
            lines.push(format!("security_mode = \"{mode}\""));
        }
        if let Some(rps) = config.rate_limit_rps {
            lines.push("[rate_limiting]".to_string());
            lines.push(format!("requests_per_second = {rps}"));
        }

        // Compliance flags
        let mut compliance_lines = Vec::new();
        if let Some(enabled) = config.eu_ai_act_enabled {
            compliance_lines.push("[eu_ai_act]".to_string());
            compliance_lines.push(format!("enabled = {enabled}"));
        }
        if let Some(enabled) = config.dora_enabled {
            compliance_lines.push("[dora]".to_string());
            compliance_lines.push(format!("enabled = {enabled}"));
        }
        if let Some(enabled) = config.nis2_enabled {
            compliance_lines.push("[nis2]".to_string());
            compliance_lines.push(format!("enabled = {enabled}"));
        }
        if let Some(enabled) = config.audit_enabled {
            compliance_lines.push("[audit]".to_string());
            compliance_lines.push(format!("enabled = {enabled}"));
        }
        lines.extend(compliance_lines);
    }

    lines.join("\n")
}

/// Build standard labels for managed resources.
fn managed_labels(cluster_name: &str) -> std::collections::BTreeMap<String, String> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("app.kubernetes.io/name".into(), "vellaveto".into());
    labels.insert(MANAGED_BY_LABEL.into(), MANAGED_BY_VALUE.into());
    labels.insert(CLUSTER_LABEL.into(), cluster_name.into());
    labels
}

/// Build a Kubernetes OwnerReference for garbage collection.
fn owner_reference(
    cluster: &VellavetoCluster,
) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
    k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
        api_version: "vellaveto.io/v1alpha1".into(),
        kind: "VellavetoCluster".into(),
        name: cluster.name_any(),
        uid: cluster.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Build an OwnerReference as a JSON value for serde_json::json! macros.
fn owner_reference_json(cluster: &VellavetoCluster) -> serde_json::Value {
    json!({
        "apiVersion": "vellaveto.io/v1alpha1",
        "kind": "VellavetoCluster",
        "name": cluster.name_any(),
        "uid": cluster.metadata.uid.clone().unwrap_or_default(),
        "controller": true,
        "blockOwnerDeletion": true
    })
}

/// Build Kubernetes resource requirements from CRD spec.
fn build_resource_requirements(
    res: &Option<crate::crd::ResourceRequirements>,
) -> serde_json::Value {
    match res {
        Some(r) => {
            let mut requests = serde_json::Map::new();
            let mut limits = serde_json::Map::new();

            if let Some(ref cpu) = r.cpu_request {
                requests.insert("cpu".into(), json!(cpu));
            }
            if let Some(ref mem) = r.memory_request {
                requests.insert("memory".into(), json!(mem));
            }
            if let Some(ref cpu) = r.cpu_limit {
                limits.insert("cpu".into(), json!(cpu));
            }
            if let Some(ref mem) = r.memory_limit {
                limits.insert("memory".into(), json!(mem));
            }

            json!({
                "requests": requests,
                "limits": limits
            })
        }
        None => json!({
            "requests": {
                "cpu": "100m",
                "memory": "128Mi"
            },
            "limits": {
                "cpu": "1",
                "memory": "512Mi"
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_config_toml_empty() {
        let toml = generate_config_toml(&None);
        assert!(toml.contains("Generated by vellaveto-operator"));
    }

    #[test]
    fn test_generate_config_toml_with_overrides() {
        let config = crate::crd::VellavetoConfigOverrides {
            security_mode: Some("strict".into()),
            eu_ai_act_enabled: Some(true),
            dora_enabled: Some(false),
            nis2_enabled: None,
            audit_enabled: Some(true),
            rate_limit_rps: Some(100),
        };
        let toml = generate_config_toml(&Some(config));
        assert!(toml.contains("security_mode = \"strict\""));
        assert!(toml.contains("requests_per_second = 100"));
        assert!(toml.contains("[eu_ai_act]"));
        assert!(toml.contains("enabled = true"));
    }

    #[test]
    fn test_managed_labels() {
        let labels = managed_labels("my-cluster");
        assert_eq!(labels.get(MANAGED_BY_LABEL).unwrap(), MANAGED_BY_VALUE);
        assert_eq!(labels.get(CLUSTER_LABEL).unwrap(), "my-cluster");
    }

    #[test]
    fn test_build_resource_requirements_default() {
        let res = build_resource_requirements(&None);
        assert_eq!(res["requests"]["cpu"], "100m");
        assert_eq!(res["limits"]["memory"], "512Mi");
    }

    #[test]
    fn test_build_resource_requirements_custom() {
        let req = crate::crd::ResourceRequirements {
            cpu_request: Some("250m".into()),
            memory_request: Some("256Mi".into()),
            cpu_limit: Some("2".into()),
            memory_limit: Some("1Gi".into()),
        };
        let res = build_resource_requirements(&Some(req));
        assert_eq!(res["requests"]["cpu"], "250m");
        assert_eq!(res["limits"]["memory"], "1Gi");
    }

    #[test]
    fn test_build_server_url() {
        let url = super::super::Context::build_server_url("vellaveto", "production");
        assert_eq!(url, "http://vellaveto.production.svc.cluster.local:3000");
    }
}
