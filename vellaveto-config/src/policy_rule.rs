//! Policy rule types — PolicyRule struct and default_priority helper.

use vellaveto_types::{NetworkRules, PathRules, PolicyType};
use serde::{Deserialize, Serialize};

/// Default priority for policies when not explicitly specified.
/// SECURITY (R19-CFG-1): Default to 0 (lowest priority) so that policies
/// without explicit priority match last. This prevents accidentally creating
/// high-priority broad Allow rules that gut deny rules.
fn default_priority() -> Option<i32> {
    Some(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub tool_pattern: String,
    pub function_pattern: String,
    pub policy_type: PolicyType,
    #[serde(default = "default_priority")]
    pub priority: Option<i32>,
    #[serde(default)]
    pub id: Option<String>,
    /// Optional path-based access control rules (file system operations).
    /// SECURITY (R12-CFG-1): Previously missing — path_rules from config were
    /// silently discarded in to_policies(), making path constraints inoperable
    /// for config-defined policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_rules: Option<PathRules>,
    /// Optional network-based access control rules (domain blocking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rules: Option<NetworkRules>,
}

impl PolicyRule {
    /// Effective priority (defaults to 0 — lowest priority).
    pub fn effective_priority(&self) -> i32 {
        self.priority.unwrap_or(0)
    }

    /// Effective ID (defaults to "tool_pattern:function_pattern").
    pub fn effective_id(&self) -> String {
        self.id
            .clone()
            .unwrap_or_else(|| format!("{}:{}", self.tool_pattern, self.function_pattern))
    }
}
