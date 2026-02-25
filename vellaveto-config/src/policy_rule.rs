//! Policy rule types — PolicyRule struct and default_priority helper.

use serde::{Deserialize, Serialize};
use vellaveto_types::{NetworkRules, PathRules, PolicyType};

/// Default priority for policies when not explicitly specified.
/// SECURITY (R19-CFG-1): Default to 0 (lowest priority) so that policies
/// without explicit priority match last. This prevents accidentally creating
/// high-priority broad Allow rules that gut deny rules.
fn default_priority() -> Option<i32> {
    Some(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

/// Maximum length for PolicyRule string fields.
const MAX_POLICY_RULE_FIELD_LEN: usize = 512;

/// Maximum length for a PolicyRule name.
const MAX_POLICY_RULE_NAME_LEN: usize = 256;

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

    /// Validate policy rule fields.
    ///
    /// SECURITY (FIND-R100-012): Validates name, patterns, and optional id
    /// for length bounds and control character rejection.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("policy_rule.name must not be empty".to_string());
        }
        if self.name.len() > MAX_POLICY_RULE_NAME_LEN {
            return Err(format!(
                "policy_rule.name length {} exceeds maximum {}",
                self.name.len(),
                MAX_POLICY_RULE_NAME_LEN
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.name) {
            return Err("policy_rule.name contains control or format characters".to_string());
        }
        if self.tool_pattern.is_empty() {
            return Err("policy_rule.tool_pattern must not be empty".to_string());
        }
        if self.tool_pattern.len() > MAX_POLICY_RULE_FIELD_LEN {
            return Err(format!(
                "policy_rule.tool_pattern length {} exceeds maximum {}",
                self.tool_pattern.len(),
                MAX_POLICY_RULE_FIELD_LEN
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.tool_pattern) {
            return Err(
                "policy_rule.tool_pattern contains control or format characters".to_string(),
            );
        }
        if self.function_pattern.is_empty() {
            return Err("policy_rule.function_pattern must not be empty".to_string());
        }
        if self.function_pattern.len() > MAX_POLICY_RULE_FIELD_LEN {
            return Err(format!(
                "policy_rule.function_pattern length {} exceeds maximum {}",
                self.function_pattern.len(),
                MAX_POLICY_RULE_FIELD_LEN
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.function_pattern) {
            return Err(
                "policy_rule.function_pattern contains control or format characters".to_string(),
            );
        }
        if let Some(ref id) = self.id {
            if id.is_empty() {
                return Err("policy_rule.id must not be empty when provided".to_string());
            }
            if id.len() > MAX_POLICY_RULE_FIELD_LEN {
                return Err(format!(
                    "policy_rule.id length {} exceeds maximum {}",
                    id.len(),
                    MAX_POLICY_RULE_FIELD_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(id) {
                return Err("policy_rule.id contains control or format characters".to_string());
            }
        }
        Ok(())
    }
}
