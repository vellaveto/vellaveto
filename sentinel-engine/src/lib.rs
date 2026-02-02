use sentinel_types::{Action, Policy, PolicyType, Verdict};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("No policies defined")]
    NoPolicies,
    #[error("Evaluation error: {0}")]
    EvaluationError(String),
    #[error("Invalid condition in policy '{policy_id}': {reason}")]
    InvalidCondition { policy_id: String, reason: String },
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// The core policy evaluation engine.
///
/// Evaluates [`Action`]s against a set of [`Policy`] rules to produce a [`Verdict`].
///
/// # Security Model
///
/// - **Fail-closed**: An empty policy set produces `Verdict::Deny`.
/// - **Priority ordering**: Higher-priority policies are evaluated first.
/// - **Pattern matching**: Policy IDs use `"tool:function"` convention with wildcard support.
pub struct PolicyEngine {
    strict_mode: bool,
}

impl PolicyEngine {
    /// Create a new policy engine.
    ///
    /// When `strict_mode` is true, the engine applies stricter validation
    /// on conditions and parameters.
    pub fn new(strict_mode: bool) -> Self {
        Self { strict_mode }
    }

    /// Evaluate an action against a set of policies.
    ///
    /// Policies are sorted by priority (highest first). The first matching policy
    /// determines the verdict. If no policy matches, the default is Deny (fail-closed).
    pub fn evaluate_action(&self, action: &Action, policies: &[Policy]) -> Result<Verdict, EngineError> {
        if policies.is_empty() {
            return Ok(Verdict::Deny {
                reason: "No policies defined".to_string(),
            });
        }

        let mut sorted: Vec<&Policy> = policies.iter().collect();
        sorted.sort_by(|a, b| {
            // Primary: higher priority first
            let pri = b.priority.cmp(&a.priority);
            if pri != std::cmp::Ordering::Equal {
                return pri;
            }
            // Secondary: at equal priority, Deny before Allow (deny-overrides)
            let a_deny = matches!(a.policy_type, PolicyType::Deny);
            let b_deny = matches!(b.policy_type, PolicyType::Deny);
            b_deny.cmp(&a_deny)
        });

        for policy in &sorted {
            if self.matches_action(action, policy) {
                return self.apply_policy(action, policy);
            }
        }

        Ok(Verdict::Deny {
            reason: "No matching policy".to_string(),
        })
    }

    /// Check if a policy matches an action.
    ///
    /// Policy ID convention: `"tool:function"`, `"tool:*"`, `"*:function"`, or `"*"`.
    fn matches_action(&self, action: &Action, policy: &Policy) -> bool {
        let id = &policy.id;

        if id == "*" {
            return true;
        }

        if let Some((tool_pat, func_pat)) = id.split_once(':') {
            self.match_pattern(tool_pat, &action.tool)
                && self.match_pattern(func_pat, &action.function)
        } else {
            self.match_pattern(id, &action.tool)
        }
    }

    /// Match a pattern against a value. Supports `"*"` (match all),
    /// prefix wildcards (`"*suffix"`), suffix wildcards (`"prefix*"`), and exact match.
    fn match_pattern(&self, pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix('*') {
            return value.ends_with(suffix);
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return value.starts_with(prefix);
        }
        pattern == value
    }

    /// Apply a matched policy to produce a verdict.
    fn apply_policy(&self, action: &Action, policy: &Policy) -> Result<Verdict, EngineError> {
        match &policy.policy_type {
            PolicyType::Allow => Ok(Verdict::Allow),
            PolicyType::Deny => Ok(Verdict::Deny {
                reason: format!("Denied by policy '{}'", policy.name),
            }),
            PolicyType::Conditional { conditions } => {
                self.evaluate_conditions(action, policy, conditions)
            }
        }
    }

    /// Evaluate conditional policy rules.
    ///
    /// Supported condition keys:
    /// - `forbidden_parameters`: array of parameter keys that must not be present
    /// - `required_parameters`: array of parameter keys that must be present
    /// - `require_approval`: if true, returns RequireApproval verdict
    fn evaluate_conditions(
        &self,
        action: &Action,
        policy: &Policy,
        conditions: &serde_json::Value,
    ) -> Result<Verdict, EngineError> {
        // JSON depth protection
        if Self::json_depth(conditions) > 10 {
            return Err(EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "Condition JSON exceeds maximum nesting depth of 10".to_string(),
            });
        }

        // Size protection
        let size = conditions.to_string().len();
        if size > 100_000 {
            return Err(EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: format!("Condition JSON too large: {} bytes (max 100000)", size),
            });
        }

        // Check require_approval first
        if let Some(require_approval) = conditions.get("require_approval") {
            if require_approval.as_bool().unwrap_or(false) {
                return Ok(Verdict::RequireApproval {
                    reason: format!("Approval required by policy '{}'", policy.name),
                });
            }
        }

        // Check forbidden parameters
        if let Some(forbidden) = conditions.get("forbidden_parameters") {
            if let Some(forbidden_arr) = forbidden.as_array() {
                for param in forbidden_arr {
                    if let Some(param_str) = param.as_str() {
                        if action.parameters.get(param_str).is_some() {
                            return Ok(Verdict::Deny {
                                reason: format!(
                                    "Parameter '{}' is forbidden by policy '{}'",
                                    param_str, policy.name
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Check required parameters
        if let Some(required) = conditions.get("required_parameters") {
            if let Some(required_arr) = required.as_array() {
                for param in required_arr {
                    if let Some(param_str) = param.as_str() {
                        if action.parameters.get(param_str).is_none() {
                            return Ok(Verdict::Deny {
                                reason: format!(
                                    "Required parameter '{}' missing (policy '{}')",
                                    param_str, policy.name
                                ),
                            });
                        }
                    }
                }
            }
        }

        // If no conditions triggered denial, allow
        Ok(Verdict::Allow)
    }

    /// Calculate the nesting depth of a JSON value.
    fn json_depth(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Array(arr) => {
                1 + arr.iter().map(Self::json_depth).max().unwrap_or(0)
            }
            serde_json::Value::Object(obj) => {
                1 + obj.values().map(Self::json_depth).max().unwrap_or(0)
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_policies_deny() {
        let engine = PolicyEngine::new(false);
        let action = Action {
            tool: "bash".to_string(),
            function: "execute".to_string(),
            parameters: json!({}),
        };
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_deny_policy_match() {
        let engine = PolicyEngine::new(false);
        let action = Action {
            tool: "bash".to_string(),
            function: "execute".to_string(),
            parameters: json!({}),
        };
        let policies = vec![Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
        }];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_allow_policy_match() {
        let engine = PolicyEngine::new(false);
        let action = Action {
            tool: "file_system".to_string(),
            function: "read_file".to_string(),
            parameters: json!({}),
        };
        let policies = vec![Policy {
            id: "file_system:read_file".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
        }];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_priority_ordering() {
        let engine = PolicyEngine::new(false);
        let action = Action {
            tool: "bash".to_string(),
            function: "execute".to_string(),
            parameters: json!({}),
        };
        let policies = vec![
            Policy {
                id: "*".to_string(),
                name: "Allow all (low priority)".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Deny bash (high priority)".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
            },
        ];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_conditional_require_approval() {
        let engine = PolicyEngine::new(false);
        let action = Action {
            tool: "network".to_string(),
            function: "connect".to_string(),
            parameters: json!({}),
        };
        let policies = vec![Policy {
            id: "network:*".to_string(),
            name: "Network requires approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "require_approval": true
                }),
            },
            priority: 100,
        }];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    }
}
