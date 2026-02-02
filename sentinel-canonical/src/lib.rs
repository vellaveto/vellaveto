use sentinel_types::{Policy, PolicyType};
use serde_json::json;

pub struct CanonicalPolicies;

impl CanonicalPolicies {
    pub fn deny_all() -> Policy {
        Policy {
            id: "*".to_string(),
            name: "Deny All Actions".to_string(),
            policy_type: PolicyType::Deny,
            priority: 1000,
        }
    }

    pub fn allow_all() -> Policy {
        Policy {
            id: "*".to_string(),
            name: "Allow All Actions".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
        }
    }

    pub fn block_dangerous_tools() -> Vec<Policy> {
        vec![
            Policy {
                id: "bash_block".to_string(),
                name: "Block Bash Commands".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "tool_pattern": "bash",
                        "require_approval": true
                    }),
                },
                priority: 900,
            },
            Policy {
                id: "system_block".to_string(),
                name: "Block System Commands".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "tool_pattern": "system",
                        "forbidden_parameters": ["rm", "delete", "format"]
                    }),
                },
                priority: 900,
            },
            Policy {
                id: "file_protection".to_string(),
                name: "File Operation Protection".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "tool_pattern": "file",
                        "function_pattern": "delete",
                        "require_approval": true
                    }),
                },
                priority: 800,
            },
        ]
    }

    pub fn network_security() -> Vec<Policy> {
        vec![
            Policy {
                id: "external_network".to_string(),
                name: "External Network Access".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "tool_pattern": "network",
                        "require_approval": true
                    }),
                },
                priority: 700,
            },
            Policy {
                id: "data_exfiltration".to_string(),
                name: "Prevent Data Exfiltration".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "tool_pattern": "*",
                        "function_pattern": "*upload*",
                        "forbidden_parameters": ["personal_data", "credentials", "tokens"]
                    }),
                },
                priority: 950,
            },
        ]
    }

    pub fn development_environment() -> Vec<Policy> {
        vec![
            Policy {
                id: "safe_dev_tools".to_string(),
                name: "Allow Safe Development Tools".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "tool_pattern": "*",
                        "function_pattern": "*",
                        "allowed_tools": ["git", "npm", "cargo", "python", "node"]
                    }),
                },
                priority: 100,
            },
            Policy {
                id: "test_environment".to_string(),
                name: "Test Environment Access".to_string(),
                policy_type: PolicyType::Allow,
                priority: 50,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_policy_creation() {
        let deny_all = CanonicalPolicies::deny_all();
        assert_eq!(deny_all.priority, 1000);
        assert!(matches!(deny_all.policy_type, PolicyType::Deny));

        let dangerous_tools = CanonicalPolicies::block_dangerous_tools();
        assert_eq!(dangerous_tools.len(), 3);
        assert!(dangerous_tools.iter().all(|p| p.priority >= 800));
    }

    #[test]
    fn test_network_security_policies() {
        let policies = CanonicalPolicies::network_security();
        assert!(!policies.is_empty());
        assert!(policies.iter().any(|p| p.name.contains("Network")));
    }

    #[test]
    fn test_development_environment_policies() {
        let policies = CanonicalPolicies::development_environment();
        assert!(!policies.is_empty());
        assert!(policies.iter().any(|p| p.priority == 50));
    }
}