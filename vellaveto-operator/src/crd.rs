//! Custom Resource Definitions for the Vellaveto Kubernetes operator.
//!
//! Three CRDs are defined:
//! - `VellavetoCluster` — manages a Vellaveto server deployment
//! - `VellavetoPolicy` — declarative policy management
//! - `VellavetoTenant` — declarative tenant management

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════

/// Maximum cluster replicas.
const MAX_CLUSTER_REPLICAS: i32 = 10;

/// Maximum container image string length.
const MAX_IMAGE_LEN: usize = 512;

/// Maximum version tag length.
const MAX_VERSION_LEN: usize = 128;

/// Maximum cluster_ref name length.
const MAX_CLUSTER_REF_LEN: usize = 253;

/// Maximum tenant ID length (mirrors server validation).
const MAX_TENANT_ID_LEN: usize = 64;

/// Maximum tenant name length.
const MAX_TENANT_NAME_LEN: usize = 256;

/// Maximum metadata entries per tenant.
const MAX_TENANT_METADATA: usize = 100;

/// Maximum metadata key length.
const MAX_METADATA_KEY_LEN: usize = 128;

/// Maximum metadata value length.
const MAX_METADATA_VALUE_LEN: usize = 1024;

/// Maximum policy ID length (mirrors vellaveto-types).
const MAX_POLICY_ID_LEN: usize = 256;

/// Maximum policy name length (mirrors vellaveto-types).
const MAX_POLICY_NAME_LEN: usize = 512;

/// Maximum path rules entries.
const MAX_PATH_RULES: usize = 1_000;

/// Maximum domain rules entries.
const MAX_DOMAIN_RULES: usize = 1_000;

/// Maximum CIDR rules entries.
const MAX_CIDR_RULES: usize = 500;

/// Maximum conditions JSON size in bytes.
const MAX_CONDITIONS_SIZE: usize = 65_536;

/// Maximum staging period in seconds (30 days).
const MAX_STAGING_PERIOD_SECS: u64 = 2_592_000;

/// Maximum config override string length.
const MAX_CONFIG_OVERRIDE_LEN: usize = 4096;

// ═══════════════════════════════════════════════════
// VellavetoCluster CRD
// ═══════════════════════════════════════════════════

/// Manages a Vellaveto server deployment on Kubernetes.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "vellaveto.io",
    version = "v1alpha1",
    kind = "VellavetoCluster",
    namespaced
)]
#[kube(status = "VellavetoClusterStatus")]
#[kube(
    printcolumn = r#"{"name":"Replicas","type":"integer","jsonPath":".spec.replicas"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Ready","type":"integer","jsonPath":".status.readyReplicas"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VellavetoClusterSpec {
    /// Number of Vellaveto server replicas (1-10).
    pub replicas: i32,
    /// Container image (e.g. "ghcr.io/paolovella/vellaveto:4.0.0").
    pub image: String,
    /// Application version tag override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Configuration overrides applied to the generated ConfigMap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<VellavetoConfigOverrides>,
    /// Kubernetes resource requirements for the Vellaveto pods.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
}

/// Subset of Vellaveto configuration fields overridable via the CRD.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct VellavetoConfigOverrides {
    /// Security enforcement mode (e.g. "strict", "permissive", "audit").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_mode: Option<String>,
    /// Enable EU AI Act compliance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eu_ai_act_enabled: Option<bool>,
    /// Enable DORA compliance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dora_enabled: Option<bool>,
    /// Enable NIS2 compliance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nis2_enabled: Option<bool>,
    /// Enable audit logging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_enabled: Option<bool>,
    /// Global rate limit (evaluations per second).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_rps: Option<u32>,
}

/// Kubernetes resource requirements (simplified for CRD schema).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct ResourceRequirements {
    /// CPU request (e.g. "100m").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_request: Option<String>,
    /// Memory request (e.g. "128Mi").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_request: Option<String>,
    /// CPU limit (e.g. "500m").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<String>,
    /// Memory limit (e.g. "512Mi").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit: Option<String>,
}

/// Status subresource for VellavetoCluster.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct VellavetoClusterStatus {
    /// Current phase: Pending, Running, or Failed.
    #[serde(default)]
    pub phase: ClusterPhase,
    /// Desired replica count.
    #[serde(default)]
    pub replicas: i32,
    /// Number of ready replicas.
    #[serde(default, rename = "readyReplicas")]
    pub ready_replicas: i32,
    /// Standard Kubernetes conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// Last observed generation of the spec.
    #[serde(default, rename = "observedGeneration")]
    pub observed_generation: i64,
}

/// Phase of a VellavetoCluster.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub enum ClusterPhase {
    #[default]
    Pending,
    Running,
    Failed,
}

// ═══════════════════════════════════════════════════
// VellavetoPolicy CRD
// ═══════════════════════════════════════════════════

/// Declarative policy management — syncs policies to a Vellaveto cluster.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "vellaveto.io",
    version = "v1alpha1",
    kind = "VellavetoPolicy",
    namespaced
)]
#[kube(status = "VellavetoPolicyStatus")]
#[kube(
    printcolumn = r#"{"name":"Cluster","type":"string","jsonPath":".spec.clusterRef"}"#,
    printcolumn = r#"{"name":"PolicyID","type":"string","jsonPath":".spec.policy.id"}"#,
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.policy.policyType"}"#,
    printcolumn = r#"{"name":"Synced","type":"boolean","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VellavetoPolicySpec {
    /// Name of the target VellavetoCluster in the same namespace.
    #[serde(rename = "clusterRef")]
    pub cluster_ref: String,
    /// Policy specification (mirrors vellaveto-types Policy fields).
    pub policy: PolicySpec,
    /// Optional lifecycle management configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<PolicyLifecycleSpec>,
}

/// Policy specification mirroring vellaveto-types::Policy for JSON Schema generation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicySpec {
    /// Unique policy identifier.
    pub id: String,
    /// Human-readable policy name.
    pub name: String,
    /// Policy type: "Allow", "Deny", or "Conditional".
    #[serde(rename = "policyType")]
    pub policy_type: String,
    /// Evaluation priority (higher = evaluated first, >= 0).
    #[serde(default)]
    pub priority: i32,
    /// Conditional policy conditions (JSON object, only for policyType="Conditional").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
    /// Path-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "pathRules")]
    pub path_rules: Option<PathRulesSpec>,
    /// Network-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "networkRules")]
    pub network_rules: Option<NetworkRulesSpec>,
}

/// Path rules specification for CRD (mirrors vellaveto-types::PathRules).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct PathRulesSpec {
    /// Glob patterns for allowed paths.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Glob patterns for blocked paths.
    #[serde(default)]
    pub blocked: Vec<String>,
}

/// Network rules specification for CRD (mirrors vellaveto-types::NetworkRules).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct NetworkRulesSpec {
    /// Domain patterns for allowed destinations.
    #[serde(default, rename = "allowedDomains")]
    pub allowed_domains: Vec<String>,
    /// Domain patterns for blocked destinations.
    #[serde(default, rename = "blockedDomains")]
    pub blocked_domains: Vec<String>,
    /// IP-level access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipRules")]
    pub ip_rules: Option<IpRulesSpec>,
}

/// IP rules specification for CRD (mirrors vellaveto-types::IpRules).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct IpRulesSpec {
    /// Block connections to private/reserved IPs.
    #[serde(default, rename = "blockPrivate")]
    pub block_private: bool,
    /// CIDR ranges to block.
    #[serde(default, rename = "blockedCidrs")]
    pub blocked_cidrs: Vec<String>,
    /// CIDR ranges to allow (allowlist).
    #[serde(default, rename = "allowedCidrs")]
    pub allowed_cidrs: Vec<String>,
}

/// Policy lifecycle management configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct PolicyLifecycleSpec {
    /// Automatically promote through Draft -> Staging -> Active.
    #[serde(default, rename = "autoPromote")]
    pub auto_promote: bool,
    /// Minimum staging period before promotion to Active (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "stagingPeriodSecs")]
    pub staging_period_secs: Option<u64>,
}

/// Status subresource for VellavetoPolicy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct VellavetoPolicyStatus {
    /// Whether the policy is synchronized with the target cluster.
    #[serde(default)]
    pub synced: bool,
    /// Last successful sync time (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastSyncTime")]
    pub last_sync_time: Option<String>,
    /// Last error message, if any.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastError")]
    pub last_error: Option<String>,
    /// Standard Kubernetes conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// Last observed generation of the spec.
    #[serde(default, rename = "observedGeneration")]
    pub observed_generation: i64,
}

// ═══════════════════════════════════════════════════
// VellavetoTenant CRD
// ═══════════════════════════════════════════════════

/// Declarative tenant management — syncs tenants to a Vellaveto cluster.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "vellaveto.io",
    version = "v1alpha1",
    kind = "VellavetoTenant",
    namespaced
)]
#[kube(status = "VellavetoTenantStatus")]
#[kube(
    printcolumn = r#"{"name":"Cluster","type":"string","jsonPath":".spec.clusterRef"}"#,
    printcolumn = r#"{"name":"TenantID","type":"string","jsonPath":".spec.tenantId"}"#,
    printcolumn = r#"{"name":"Enabled","type":"boolean","jsonPath":".spec.enabled"}"#,
    printcolumn = r#"{"name":"Synced","type":"boolean","jsonPath":".status.synced"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VellavetoTenantSpec {
    /// Name of the target VellavetoCluster in the same namespace.
    #[serde(rename = "clusterRef")]
    pub cluster_ref: String,
    /// Unique tenant identifier (1-64 chars, [a-zA-Z0-9_-]).
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Human-readable tenant name.
    pub name: String,
    /// Whether the tenant is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Tenant-specific quota overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<TenantQuotasSpec>,
    /// Tenant metadata (custom key-value pairs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

fn default_true() -> bool {
    true
}

/// Tenant quotas specification for CRD.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct TenantQuotasSpec {
    /// Maximum policy evaluations per minute.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxEvaluationsPerMinute"
    )]
    pub max_evaluations_per_minute: Option<u64>,
    /// Maximum number of policies this tenant can create.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxPolicies"
    )]
    pub max_policies: Option<u64>,
    /// Maximum pending approvals at any time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxPendingApprovals"
    )]
    pub max_pending_approvals: Option<u64>,
    /// Maximum audit log retention in days.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxAuditRetentionDays"
    )]
    pub max_audit_retention_days: Option<u64>,
}

/// Status subresource for VellavetoTenant.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct VellavetoTenantStatus {
    /// Whether the tenant is synchronized with the target cluster.
    #[serde(default)]
    pub synced: bool,
    /// Last successful sync time (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastSyncTime")]
    pub last_sync_time: Option<String>,
    /// Last error message, if any.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastError")]
    pub last_error: Option<String>,
    /// Standard Kubernetes conditions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// Last observed generation of the spec.
    #[serde(default, rename = "observedGeneration")]
    pub observed_generation: i64,
}

// ═══════════════════════════════════════════════════
// Shared Types
// ═══════════════════════════════════════════════════

/// Standard Kubernetes-style condition.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Condition {
    /// Type of condition (e.g. "Ready", "Synced", "Available").
    #[serde(rename = "type")]
    pub condition_type: String,
    /// Status: "True", "False", or "Unknown".
    pub status: String,
    /// Last time the condition transitioned.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "lastTransitionTime")]
    pub last_transition_time: Option<String>,
    /// Human-readable reason for the condition's last transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable message with details about the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ═══════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════

/// Check for control characters or Unicode format characters in a string.
///
/// Mirrors `vellaveto_types::has_dangerous_chars()` without depending on
/// the types crate (operator is a standalone binary).
fn has_dangerous_chars(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() || is_unicode_format_char(c))
}

/// Check for Unicode format characters (zero-width, bidi, BOM, etc.).
fn is_unicode_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2069}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0001}'..='\u{E007F}'
    )
}

/// Validate a tenant ID: 1-64 chars, [a-zA-Z0-9_-] only.
fn validate_tenant_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("tenant_id must not be empty".into());
    }
    if id.len() > MAX_TENANT_ID_LEN {
        return Err(format!(
            "tenant_id exceeds max length of {}",
            MAX_TENANT_ID_LEN
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("tenant_id must contain only [a-zA-Z0-9_-]".into());
    }
    Ok(())
}

/// Validate a Kubernetes resource name (DNS subdomain: lowercase alnum + '-', max 253).
fn validate_k8s_name(name: &str, field: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if name.len() > MAX_CLUSTER_REF_LEN {
        return Err(format!("{field} exceeds max length of {MAX_CLUSTER_REF_LEN}"));
    }
    if has_dangerous_chars(name) {
        return Err(format!("{field} contains dangerous characters"));
    }
    Ok(())
}

impl VellavetoClusterSpec {
    /// Validate the cluster spec.
    pub fn validate(&self) -> Result<(), String> {
        if self.replicas < 1 || self.replicas > MAX_CLUSTER_REPLICAS {
            return Err(format!(
                "replicas must be between 1 and {}",
                MAX_CLUSTER_REPLICAS
            ));
        }
        if self.image.is_empty() {
            return Err("image must not be empty".into());
        }
        if self.image.len() > MAX_IMAGE_LEN {
            return Err(format!("image exceeds max length of {MAX_IMAGE_LEN}"));
        }
        if has_dangerous_chars(&self.image) {
            return Err("image contains dangerous characters".into());
        }
        if let Some(ref version) = self.version {
            if version.len() > MAX_VERSION_LEN {
                return Err(format!(
                    "version exceeds max length of {MAX_VERSION_LEN}"
                ));
            }
            if has_dangerous_chars(version) {
                return Err("version contains dangerous characters".into());
            }
        }
        if let Some(ref config) = self.config {
            config.validate()?;
        }
        Ok(())
    }
}

impl VellavetoConfigOverrides {
    /// Validate config overrides.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref mode) = self.security_mode {
            if mode.len() > MAX_CONFIG_OVERRIDE_LEN {
                return Err("security_mode too long".into());
            }
            if has_dangerous_chars(mode) {
                return Err("security_mode contains dangerous characters".into());
            }
            let valid_modes = ["strict", "permissive", "audit"];
            if !valid_modes.contains(&mode.as_str()) {
                return Err(format!(
                    "security_mode must be one of: {}",
                    valid_modes.join(", ")
                ));
            }
        }
        if let Some(rps) = self.rate_limit_rps {
            if rps == 0 {
                return Err("rate_limit_rps must be > 0".into());
            }
        }
        Ok(())
    }
}

impl VellavetoPolicySpec {
    /// Validate the policy spec.
    pub fn validate(&self) -> Result<(), String> {
        validate_k8s_name(&self.cluster_ref, "clusterRef")?;
        self.policy.validate()?;
        if let Some(ref lifecycle) = self.lifecycle {
            lifecycle.validate()?;
        }
        Ok(())
    }
}

impl PolicySpec {
    /// Validate the policy specification.
    pub fn validate(&self) -> Result<(), String> {
        // ID
        if self.id.is_empty() {
            return Err("policy.id must not be empty".into());
        }
        if self.id.len() > MAX_POLICY_ID_LEN {
            return Err(format!(
                "policy.id exceeds max length of {MAX_POLICY_ID_LEN}"
            ));
        }
        if has_dangerous_chars(&self.id) {
            return Err("policy.id contains dangerous characters".into());
        }
        // Name
        if self.name.is_empty() {
            return Err("policy.name must not be empty".into());
        }
        if self.name.len() > MAX_POLICY_NAME_LEN {
            return Err(format!(
                "policy.name exceeds max length of {MAX_POLICY_NAME_LEN}"
            ));
        }
        if has_dangerous_chars(&self.name) {
            return Err("policy.name contains dangerous characters".into());
        }
        // Policy type
        let valid_types = ["Allow", "Deny", "Conditional"];
        if !valid_types.contains(&self.policy_type.as_str()) {
            return Err(format!(
                "policy.policyType must be one of: {}",
                valid_types.join(", ")
            ));
        }
        // Conditions required for Conditional, forbidden otherwise
        if self.policy_type == "Conditional" {
            if self.conditions.is_none() {
                return Err("conditions required when policyType is Conditional".into());
            }
            if let Some(ref cond) = self.conditions {
                let size = serde_json::to_string(cond)
                    .map(|s| s.len())
                    .unwrap_or(0);
                if size > MAX_CONDITIONS_SIZE {
                    return Err(format!(
                        "conditions exceed max size of {MAX_CONDITIONS_SIZE} bytes"
                    ));
                }
            }
        } else if self.conditions.is_some() {
            return Err("conditions must be absent for non-Conditional policy type".into());
        }
        // Priority
        if self.priority < 0 {
            return Err("policy.priority must be >= 0".into());
        }
        // Path rules
        if let Some(ref pr) = self.path_rules {
            if pr.allowed.len() > MAX_PATH_RULES {
                return Err(format!(
                    "pathRules.allowed exceeds max of {MAX_PATH_RULES}"
                ));
            }
            if pr.blocked.len() > MAX_PATH_RULES {
                return Err(format!(
                    "pathRules.blocked exceeds max of {MAX_PATH_RULES}"
                ));
            }
        }
        // Network rules
        if let Some(ref nr) = self.network_rules {
            if nr.allowed_domains.len() > MAX_DOMAIN_RULES {
                return Err(format!(
                    "networkRules.allowedDomains exceeds max of {MAX_DOMAIN_RULES}"
                ));
            }
            if nr.blocked_domains.len() > MAX_DOMAIN_RULES {
                return Err(format!(
                    "networkRules.blockedDomains exceeds max of {MAX_DOMAIN_RULES}"
                ));
            }
            if let Some(ref ip) = nr.ip_rules {
                if ip.blocked_cidrs.len() > MAX_CIDR_RULES {
                    return Err(format!(
                        "ipRules.blockedCidrs exceeds max of {MAX_CIDR_RULES}"
                    ));
                }
                if ip.allowed_cidrs.len() > MAX_CIDR_RULES {
                    return Err(format!(
                        "ipRules.allowedCidrs exceeds max of {MAX_CIDR_RULES}"
                    ));
                }
            }
        }
        Ok(())
    }
}

impl PolicyLifecycleSpec {
    /// Validate lifecycle settings.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(secs) = self.staging_period_secs {
            if secs > MAX_STAGING_PERIOD_SECS {
                return Err(format!(
                    "stagingPeriodSecs exceeds max of {MAX_STAGING_PERIOD_SECS}"
                ));
            }
        }
        Ok(())
    }
}

impl VellavetoTenantSpec {
    /// Validate the tenant spec.
    pub fn validate(&self) -> Result<(), String> {
        validate_k8s_name(&self.cluster_ref, "clusterRef")?;
        validate_tenant_id(&self.tenant_id)?;
        // Name
        if self.name.is_empty() {
            return Err("name must not be empty".into());
        }
        if self.name.len() > MAX_TENANT_NAME_LEN {
            return Err(format!("name exceeds max length of {MAX_TENANT_NAME_LEN}"));
        }
        if has_dangerous_chars(&self.name) {
            return Err("name contains dangerous characters".into());
        }
        // Metadata
        if let Some(ref md) = self.metadata {
            if md.len() > MAX_TENANT_METADATA {
                return Err(format!(
                    "metadata exceeds max of {MAX_TENANT_METADATA} entries"
                ));
            }
            for (k, v) in md {
                if k.len() > MAX_METADATA_KEY_LEN {
                    return Err(format!(
                        "metadata key exceeds max length of {MAX_METADATA_KEY_LEN}"
                    ));
                }
                if v.len() > MAX_METADATA_VALUE_LEN {
                    return Err(format!(
                        "metadata value exceeds max length of {MAX_METADATA_VALUE_LEN}"
                    ));
                }
                if has_dangerous_chars(k) || has_dangerous_chars(v) {
                    return Err("metadata contains dangerous characters".into());
                }
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn test_cluster_crd_generation() {
        let crd = VellavetoCluster::crd();
        assert_eq!(crd.metadata.name.as_deref(), Some("vellavetoclusters.vellaveto.io"));
    }

    #[test]
    fn test_policy_crd_generation() {
        let crd = VellavetoPolicy::crd();
        assert_eq!(crd.metadata.name.as_deref(), Some("vellavetopolicies.vellaveto.io"));
    }

    #[test]
    fn test_tenant_crd_generation() {
        let crd = VellavetoTenant::crd();
        assert_eq!(crd.metadata.name.as_deref(), Some("vellavetotenants.vellaveto.io"));
    }

    #[test]
    fn test_cluster_spec_validate_valid() {
        let spec = VellavetoClusterSpec {
            replicas: 3,
            image: "ghcr.io/paolovella/vellaveto:4.0.0".into(),
            version: Some("4.0.0".into()),
            config: None,
            resources: None,
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_cluster_spec_validate_invalid_replicas() {
        let spec = VellavetoClusterSpec {
            replicas: 0,
            image: "test:latest".into(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec.validate().unwrap_err().contains("replicas"));

        let spec2 = VellavetoClusterSpec {
            replicas: 11,
            image: "test:latest".into(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec2.validate().unwrap_err().contains("replicas"));
    }

    #[test]
    fn test_cluster_spec_validate_empty_image() {
        let spec = VellavetoClusterSpec {
            replicas: 1,
            image: String::new(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec.validate().unwrap_err().contains("image"));
    }

    #[test]
    fn test_cluster_spec_validate_dangerous_chars() {
        let spec = VellavetoClusterSpec {
            replicas: 1,
            image: "test\x00:latest".into(),
            version: None,
            config: None,
            resources: None,
        };
        assert!(spec.validate().unwrap_err().contains("dangerous"));
    }

    #[test]
    fn test_policy_spec_validate_valid_allow() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "pol-1".into(),
                name: "Allow reads".into(),
                policy_type: "Allow".into(),
                priority: 10,
                conditions: None,
                path_rules: Some(PathRulesSpec {
                    allowed: vec!["/data/**".into()],
                    blocked: vec![],
                }),
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_policy_spec_validate_invalid_type() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "pol-1".into(),
                name: "Bad type".into(),
                policy_type: "Invalid".into(),
                priority: 0,
                conditions: None,
                path_rules: None,
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec.validate().unwrap_err().contains("policyType"));
    }

    #[test]
    fn test_policy_spec_validate_conditional_needs_conditions() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "pol-1".into(),
                name: "Conditional".into(),
                policy_type: "Conditional".into(),
                priority: 0,
                conditions: None,
                path_rules: None,
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec.validate().unwrap_err().contains("conditions required"));
    }

    #[test]
    fn test_policy_spec_validate_negative_priority() {
        let spec = VellavetoPolicySpec {
            cluster_ref: "my-cluster".into(),
            policy: PolicySpec {
                id: "pol-1".into(),
                name: "Neg priority".into(),
                policy_type: "Allow".into(),
                priority: -1,
                conditions: None,
                path_rules: None,
                network_rules: None,
            },
            lifecycle: None,
        };
        assert!(spec.validate().unwrap_err().contains("priority"));
    }

    #[test]
    fn test_tenant_spec_validate_valid() {
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "acme-corp".into(),
            name: "ACME Corporation".into(),
            enabled: true,
            quotas: Some(TenantQuotasSpec {
                max_evaluations_per_minute: Some(5000),
                max_policies: Some(100),
                max_pending_approvals: None,
                max_audit_retention_days: None,
            }),
            metadata: None,
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_tenant_spec_validate_invalid_id() {
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "invalid id!".into(),
            name: "Test".into(),
            enabled: true,
            quotas: None,
            metadata: None,
        };
        assert!(spec.validate().unwrap_err().contains("tenant_id"));
    }

    #[test]
    fn test_tenant_spec_validate_metadata_bounds() {
        let mut md = BTreeMap::new();
        for i in 0..=MAX_TENANT_METADATA {
            md.insert(format!("key-{i}"), "value".into());
        }
        let spec = VellavetoTenantSpec {
            cluster_ref: "my-cluster".into(),
            tenant_id: "test".into(),
            name: "Test".into(),
            enabled: true,
            quotas: None,
            metadata: Some(md),
        };
        assert!(spec.validate().unwrap_err().contains("metadata"));
    }

    #[test]
    fn test_config_overrides_validate_valid() {
        let config = VellavetoConfigOverrides {
            security_mode: Some("strict".into()),
            eu_ai_act_enabled: Some(true),
            dora_enabled: None,
            nis2_enabled: None,
            audit_enabled: Some(true),
            rate_limit_rps: Some(100),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_overrides_validate_invalid_mode() {
        let config = VellavetoConfigOverrides {
            security_mode: Some("unknown".into()),
            ..Default::default()
        };
        assert!(config.validate().unwrap_err().contains("security_mode"));
    }

    #[test]
    fn test_cluster_spec_serde_roundtrip() {
        let spec = VellavetoClusterSpec {
            replicas: 3,
            image: "test:latest".into(),
            version: Some("4.0.0".into()),
            config: None,
            resources: Some(ResourceRequirements {
                cpu_request: Some("100m".into()),
                memory_request: Some("128Mi".into()),
                cpu_limit: None,
                memory_limit: None,
            }),
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let parsed: VellavetoClusterSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.replicas, 3);
        assert_eq!(parsed.image, "test:latest");
    }

    #[test]
    fn test_policy_spec_serde_roundtrip() {
        let spec = PolicySpec {
            id: "p1".into(),
            name: "Test Policy".into(),
            policy_type: "Allow".into(),
            priority: 5,
            conditions: None,
            path_rules: Some(PathRulesSpec {
                allowed: vec!["/tmp/**".into()],
                blocked: vec![],
            }),
            network_rules: Some(NetworkRulesSpec {
                allowed_domains: vec!["example.com".into()],
                blocked_domains: vec![],
                ip_rules: None,
            }),
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let parsed: PolicySpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, "p1");
        assert_eq!(parsed.policy_type, "Allow");
    }
}
