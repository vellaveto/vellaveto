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
/// persistence_path = "/var/lib/vellaveto/tool_registry.jsonl"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

impl ToolRegistryConfig {
    /// Validate tool registry configuration (FIND-R58-CFG-022).
    ///
    /// Ensures trust_threshold is finite and in `[0.0, 1.0]`.
    /// Also validates persistence_path for control characters and length
    /// (FIND-R112-017).
    pub fn validate(&self) -> Result<(), String> {
        if !self.trust_threshold.is_finite()
            || self.trust_threshold < 0.0
            || self.trust_threshold > 1.0
        {
            return Err(format!(
                "tool_registry.trust_threshold must be in [0.0, 1.0], got {}",
                self.trust_threshold
            ));
        }
        // SECURITY (FIND-R112-017): Reject control characters in persistence_path
        // to prevent filesystem confusion and log injection.
        if vellaveto_types::has_dangerous_chars(&self.persistence_path) {
            return Err(
                "tool_registry.persistence_path contains control or format characters".to_string(),
            );
        }
        // SECURITY (FIND-R112-017): Cap path length to prevent OS-level path
        // length limit bypasses and memory abuse from excessively long paths.
        const MAX_PERSISTENCE_PATH_LEN: usize = 4096;
        if self.persistence_path.len() > MAX_PERSISTENCE_PATH_LEN {
            return Err(format!(
                "tool_registry.persistence_path exceeds max length ({} > {})",
                self.persistence_path.len(),
                MAX_PERSISTENCE_PATH_LEN,
            ));
        }
        Ok(())
    }
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
