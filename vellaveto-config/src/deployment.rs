//! Kubernetes-native deployment configuration (Phase 27).
//!
//! Configures deployment mode, leader election, and service discovery.
//! All fields have sensible defaults so that `DeploymentConfig::default()`
//! produces a valid standalone configuration requiring zero extra config.

use serde::{Deserialize, Serialize};

/// Deployment mode for the Vellaveto instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// Single instance, no coordination (default).
    #[default]
    Standalone,
    /// Multiple instances with shared state (e.g., Redis cluster backend).
    Clustered,
    /// Running in Kubernetes with leader election and service discovery.
    Kubernetes,
}

/// Configuration for leader election.
///
/// When enabled, one instance in the cluster acquires the leader lease.
/// The leader performs coordination tasks (e.g., audit log rotation,
/// stale approval expiry) while followers defer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderElectionConfig {
    /// Enable leader election. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Duration in seconds before a lease expires if not renewed.
    /// Range: [5, 300]. Default: 15.
    #[serde(default = "default_lease_duration_secs")]
    pub lease_duration_secs: u64,

    /// Interval in seconds between lease renewal attempts.
    /// Must be less than `lease_duration_secs`. Default: 10.
    #[serde(default = "default_renew_interval_secs")]
    pub renew_interval_secs: u64,

    /// Retry period in seconds after a failed acquisition attempt.
    /// Range: [1, 60]. Default: 5.
    #[serde(default = "default_retry_period_secs")]
    pub retry_period_secs: u64,
}

fn default_lease_duration_secs() -> u64 {
    15
}
fn default_renew_interval_secs() -> u64 {
    10
}
fn default_retry_period_secs() -> u64 {
    5
}

impl Default for LeaderElectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lease_duration_secs: default_lease_duration_secs(),
            renew_interval_secs: default_renew_interval_secs(),
            retry_period_secs: default_retry_period_secs(),
        }
    }
}

impl LeaderElectionConfig {
    /// Validate leader election configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.lease_duration_secs < 5 || self.lease_duration_secs > 300 {
            return Err(format!(
                "deployment.leader_election.lease_duration_secs must be in [5, 300], got {}",
                self.lease_duration_secs
            ));
        }
        if self.renew_interval_secs >= self.lease_duration_secs {
            return Err(format!(
                "deployment.leader_election.renew_interval_secs ({}) must be < lease_duration_secs ({})",
                self.renew_interval_secs, self.lease_duration_secs
            ));
        }
        if self.retry_period_secs < 1 || self.retry_period_secs > 60 {
            return Err(format!(
                "deployment.leader_election.retry_period_secs must be in [1, 60], got {}",
                self.retry_period_secs
            ));
        }
        Ok(())
    }
}

/// Service discovery mode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceDiscoveryMode {
    /// Fixed list of endpoints from gateway config (default).
    #[default]
    Static,
    /// DNS-based discovery (e.g., headless Service A/AAAA records).
    Dns,
    /// Kubernetes API-based discovery (future, feature-gated).
    Kubernetes,
}

/// Configuration for service discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    /// Discovery mode. Default: Static.
    #[serde(default)]
    pub mode: ServiceDiscoveryMode,

    /// DNS name to resolve for endpoint discovery.
    /// Required when mode is `Dns`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,

    /// Interval in seconds between discovery refreshes.
    /// Range: [5, 300]. Default: 30.
    #[serde(default = "default_refresh_interval_secs")]
    pub refresh_interval_secs: u64,

    /// Kubernetes label selector for endpoint filtering (future use).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_selector: Option<String>,
}

fn default_refresh_interval_secs() -> u64 {
    30
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: ServiceDiscoveryMode::default(),
            dns_name: None,
            refresh_interval_secs: default_refresh_interval_secs(),
            label_selector: None,
        }
    }
}

impl ServiceDiscoveryConfig {
    /// Validate service discovery configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.refresh_interval_secs < 5 || self.refresh_interval_secs > 300 {
            return Err(format!(
                "deployment.service_discovery.refresh_interval_secs must be in [5, 300], got {}",
                self.refresh_interval_secs
            ));
        }
        if self.mode == ServiceDiscoveryMode::Dns && self.dns_name.is_none() {
            return Err(
                "deployment.service_discovery.dns_name is required when mode is 'dns'".to_string(),
            );
        }
        // Validate dns_name is not empty if provided
        if let Some(ref name) = self.dns_name {
            if name.trim().is_empty() {
                return Err(
                    "deployment.service_discovery.dns_name must not be empty".to_string()
                );
            }
            // SECURITY (FIND-P27-005): Reject SSRF-prone DNS names.
            // Extract host part before the port (required by tokio::net::lookup_host).
            // Handle bracketed IPv6 addresses like [::1]:80.
            let host = if name.starts_with('[') {
                // IPv6 bracketed notation: [::1]:80
                name.split(']')
                    .next()
                    .unwrap_or(name)
                    .trim_start_matches('[')
                    .to_lowercase()
            } else {
                name.rsplit_once(':')
                    .map(|(h, _)| h)
                    .unwrap_or(name)
                    .to_lowercase()
            };
            // Block loopback addresses
            if host == "localhost"
                || host == "127.0.0.1"
                || host == "::1"
                || host == "0.0.0.0"
                || host.starts_with("127.")
            {
                return Err(format!(
                    "deployment.service_discovery.dns_name must not resolve to loopback (got '{}')",
                    host
                ));
            }
            // Block cloud metadata endpoints
            if host == "169.254.169.254"
                || host == "metadata.google.internal"
                || host == "169.254.165.254"
                || host.ends_with(".internal")
            {
                return Err(format!(
                    "deployment.service_discovery.dns_name must not target cloud metadata endpoints (got '{}')",
                    host
                ));
            }
            // Block link-local range
            if host.starts_with("169.254.") {
                return Err(format!(
                    "deployment.service_discovery.dns_name must not target link-local addresses (got '{}')",
                    host
                ));
            }
        }
        Ok(())
    }
}

/// Maximum length for instance_id (DNS label safe).
pub const MAX_INSTANCE_ID_LEN: usize = 253;

/// Top-level deployment configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Deployment mode. Default: Standalone.
    #[serde(default)]
    pub mode: DeploymentMode,

    /// Leader election configuration.
    #[serde(default)]
    pub leader_election: LeaderElectionConfig,

    /// Service discovery configuration.
    #[serde(default)]
    pub service_discovery: ServiceDiscoveryConfig,

    /// Instance ID override. When None, derived from HOSTNAME env var.
    /// Must be DNS-safe (max 253 chars, lowercase alphanumeric + hyphens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

// DeploymentConfig Default: all fields have their own Default impls,
// and instance_id defaults to None via Option.

impl DeploymentConfig {
    /// Validate the entire deployment configuration.
    pub fn validate(&self) -> Result<(), String> {
        self.leader_election.validate()?;
        self.service_discovery.validate()?;

        // Validate instance_id if provided
        if let Some(ref id) = self.instance_id {
            if id.len() > MAX_INSTANCE_ID_LEN {
                return Err(format!(
                    "deployment.instance_id must be at most {} characters, got {}",
                    MAX_INSTANCE_ID_LEN,
                    id.len()
                ));
            }
            if id.is_empty() {
                return Err("deployment.instance_id must not be empty".to_string());
            }
            // DNS-safe: lowercase alphanumeric + hyphens, no leading/trailing hyphen
            if !id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
            {
                return Err(format!(
                    "deployment.instance_id must be DNS-safe (lowercase alphanumeric, hyphens, dots), got '{}'",
                    id
                ));
            }
            if id.starts_with('-') || id.ends_with('-') {
                return Err(format!(
                    "deployment.instance_id must not start or end with a hyphen, got '{}'",
                    id
                ));
            }
            // SECURITY (FIND-P27-007): Reject leading/trailing dots and consecutive dots.
            if id.starts_with('.') || id.ends_with('.') {
                return Err(format!(
                    "deployment.instance_id must not start or end with a dot, got '{}'",
                    id
                ));
            }
            if id.contains("..") {
                return Err(format!(
                    "deployment.instance_id must not contain consecutive dots, got '{}'",
                    id
                ));
            }
        }

        // Kubernetes mode requires leader election
        if self.mode == DeploymentMode::Kubernetes && !self.leader_election.enabled {
            // Not an error — just informational. Leader election is optional even in K8s mode.
        }

        Ok(())
    }

    /// Resolve the effective instance ID.
    ///
    /// Order of precedence:
    /// 1. Configured `instance_id`
    /// 2. `HOSTNAME` environment variable (K8s sets this to pod name)
    /// 3. `"vellaveto-unknown"`
    pub fn effective_instance_id(&self) -> String {
        if let Some(ref id) = self.instance_id {
            return id.clone();
        }
        std::env::var("HOSTNAME").unwrap_or_else(|_| "vellaveto-unknown".to_string())
    }
}
