//! Kubernetes-native deployment types (Phase 27).
//!
//! Leaf types for leader election status, service discovery endpoints,
//! and deployment info. No internal dependencies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Leader election status for a Vellaveto instance.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LeaderStatus {
    /// This instance currently holds the leader lease.
    Leader {
        /// ISO 8601 timestamp when leadership was acquired.
        since: String,
    },
    /// This instance is a follower.
    Follower {
        /// Instance ID of the current leader, if known.
        #[serde(skip_serializing_if = "Option::is_none")]
        leader_id: Option<String>,
    },
    /// Leadership status is unknown (e.g., during startup or partition).
    #[default]
    Unknown,
}

/// A discovered service endpoint in the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    /// Unique identifier for this endpoint (e.g., pod name).
    pub id: String,
    /// URL to reach this endpoint (e.g., `http://vellaveto-0.vellaveto:3000`).
    pub url: String,
    /// Labels/metadata associated with this endpoint.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    /// Whether this endpoint is currently healthy.
    pub healthy: bool,
}

/// Events emitted by service discovery watchers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DiscoveryEvent {
    /// A new endpoint was discovered.
    Added(ServiceEndpoint),
    /// An endpoint was removed.
    Removed {
        /// ID of the removed endpoint.
        id: String,
    },
    /// An existing endpoint was updated (e.g., health status changed).
    Updated(ServiceEndpoint),
}

/// Summary of deployment status for the `/api/deployment/info` endpoint.
///
/// SECURITY (FIND-R44-015): In anonymous mode (no api_key configured), sensitive
/// topology fields (`instance_id`, `leader_status`, `discovered_endpoints`) are
/// set to `None` and omitted from the JSON response. Only `mode` and `uptime_secs`
/// are included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentInfo {
    /// Instance ID of this Vellaveto node (e.g., pod name).
    /// None when redacted in anonymous mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// Current leader election status.
    /// None when redacted in anonymous mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leader_status: Option<LeaderStatus>,
    /// Number of discovered service endpoints.
    /// None when redacted in anonymous mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_endpoints: Option<usize>,
    /// Uptime in seconds since process start.
    pub uptime_secs: u64,
    /// Deployment mode (standalone, clustered, kubernetes).
    pub mode: String,
}
