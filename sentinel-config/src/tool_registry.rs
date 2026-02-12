//! Tool registry configuration — trust scoring and persistence settings.

use serde::{Deserialize, Serialize};

/// Tool registry with trust scoring configuration (P2.1).
///
/// Controls the tool registry that tracks tool definitions, their hashes,
/// and computes trust scores. Tools below the threshold require human approval.
///
/// # TOML Example
///
/// ```toml
/// [tool_registry]
/// enabled = true
/// trust_threshold = 0.3
/// persistence_path = "/var/lib/sentinel/tool_registry.jsonl"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolRegistryConfig {
    /// Enable tool registry tracking. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Trust threshold below which tools require approval. Default: 0.3.
    /// Tools with trust_score < threshold get RequireApproval verdict.
    #[serde(default = "default_trust_threshold")]
    pub trust_threshold: f32,
    /// Path to the registry persistence file. Default: "tool_registry.jsonl".
    #[serde(default = "default_registry_path")]
    pub persistence_path: String,
}

fn default_trust_threshold() -> f32 {
    0.3
}

fn default_registry_path() -> String {
    "tool_registry.jsonl".to_string()
}

impl Default for ToolRegistryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            trust_threshold: default_trust_threshold(),
            persistence_path: default_registry_path(),
        }
    }
}
