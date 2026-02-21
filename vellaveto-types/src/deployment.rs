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
#[serde(deny_unknown_fields)]
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

impl ServiceEndpoint {
    /// Maximum length for endpoint `id`.
    const MAX_ID_LEN: usize = 256;
    /// Maximum length for endpoint `url`.
    const MAX_URL_LEN: usize = 2048;
    /// Maximum number of labels per endpoint.
    const MAX_LABELS: usize = 100;
    /// Maximum length for a label key.
    ///
    /// SECURITY (FIND-R113-011): Bound individual label key lengths.
    const MAX_LABEL_KEY_LEN: usize = 256;
    /// Maximum length for a label value.
    ///
    /// SECURITY (FIND-R113-011): Bound individual label value lengths.
    const MAX_LABEL_VALUE_LEN: usize = 1024;

    /// Validate structural bounds on deserialized data.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.len() > Self::MAX_ID_LEN {
            return Err(format!(
                "ServiceEndpoint id length {} exceeds max {}",
                self.id.len(),
                Self::MAX_ID_LEN,
            ));
        }
        // SECURITY (FIND-R113-011): Validate control/format chars on id.
        if self
            .id
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "ServiceEndpoint id contains control or format characters".to_string(),
            );
        }
        if self.url.len() > Self::MAX_URL_LEN {
            return Err(format!(
                "ServiceEndpoint '{}' url length {} exceeds max {}",
                self.id,
                self.url.len(),
                Self::MAX_URL_LEN,
            ));
        }
        // SECURITY (FIND-R113-011): Validate control/format chars on url.
        if self
            .url
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "ServiceEndpoint url contains control or format characters".to_string(),
            );
        }
        if self.labels.len() > Self::MAX_LABELS {
            return Err(format!(
                "ServiceEndpoint '{}' labels count {} exceeds max {}",
                self.id,
                self.labels.len(),
                Self::MAX_LABELS,
            ));
        }
        // SECURITY (FIND-R113-011): Validate label key/value lengths and control chars.
        for (key, value) in &self.labels {
            if key.len() > Self::MAX_LABEL_KEY_LEN {
                return Err(format!(
                    "ServiceEndpoint '{}' label key length {} exceeds max {}",
                    self.id,
                    key.len(),
                    Self::MAX_LABEL_KEY_LEN,
                ));
            }
            if value.len() > Self::MAX_LABEL_VALUE_LEN {
                return Err(format!(
                    "ServiceEndpoint '{}' label value length {} exceeds max {}",
                    self.id,
                    value.len(),
                    Self::MAX_LABEL_VALUE_LEN,
                ));
            }
            if key
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "ServiceEndpoint '{}' label key contains control or format characters",
                    self.id,
                ));
            }
            if value
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "ServiceEndpoint '{}' label value contains control or format characters",
                    self.id,
                ));
            }
        }
        Ok(())
    }
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

impl DeploymentInfo {
    /// Maximum length for `instance_id`.
    const MAX_INSTANCE_ID_LEN: usize = 256;
    /// Maximum length for `mode`.
    const MAX_MODE_LEN: usize = 64;

    /// Validate structural bounds on deserialized data.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref id) = self.instance_id {
            if id.len() > Self::MAX_INSTANCE_ID_LEN {
                return Err(format!(
                    "DeploymentInfo instance_id length {} exceeds max {}",
                    id.len(),
                    Self::MAX_INSTANCE_ID_LEN,
                ));
            }
        }
        if self.mode.len() > Self::MAX_MODE_LEN {
            return Err(format!(
                "DeploymentInfo mode length {} exceeds max {}",
                self.mode.len(),
                Self::MAX_MODE_LEN,
            ));
        }
        Ok(())
    }
}
