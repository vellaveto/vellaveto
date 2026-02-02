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
                id: "bash:*".to_string(),
                name: "Block Bash Commands".to_string(),
                policy_type: PolicyType::Deny,
                priority: 900,
            },
            Policy {
                id: "shell:*".to_string(),
                name: "Block Shell Commands".to_string(),
                policy_type: PolicyType::Deny,
                priority: 900,
            },
            Policy {
                id: "exec:*".to_string(),
                name: "Block Exec Commands".to_string(),
                policy_type: PolicyType::Deny,
                priority: 900,
            },
        ]
    }

    pub fn network_security() -> Vec<Policy> {
        vec![
            Policy {
                id: "http_request:*".to_string(),
                name: "HTTP Domain Allowlist".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [
                            {
                                "param": "url",
                                "op": "domain_not_in",
                                "patterns": ["localhost", "127.0.0.1"],
                                "on_match": "deny"
                            }
                        ]
                    }),
                },
                priority: 700,
            },
            Policy {
                id: "*:*upload*".to_string(),
                name: "Prevent Data Exfiltration".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
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
                id: "file_system:*".to_string(),
                name: "Restrict File Access to Project Directory".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [
                            {
                                "param": "path",
                                "op": "not_glob",
                                "patterns": ["/home/*/projects/**", "/tmp/**"],
                                "on_match": "deny",
                                "on_missing": "skip"
                            }
                        ]
                    }),
                },
                priority: 100,
            },
            Policy {
                id: "test:*".to_string(),
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

        // All dangerous tool policies should be plain Deny with proper IDs
        for p in &dangerous_tools {
            assert!(matches!(p.policy_type, PolicyType::Deny));
            assert!(
                p.id.contains(':'),
                "ID '{}' should use tool:function format",
                p.id
            );
        }
    }

    #[test]
    fn test_network_security_policies() {
        let policies = CanonicalPolicies::network_security();
        assert!(!policies.is_empty());

        // First policy should use parameter_constraints for domain allowlisting
        let http_policy = &policies[0];
        assert_eq!(http_policy.id, "http_request:*");
        if let PolicyType::Conditional { conditions } = &http_policy.policy_type {
            assert!(conditions.get("parameter_constraints").is_some());
        } else {
            panic!("HTTP policy should be Conditional with parameter_constraints");
        }
    }

    #[test]
    fn test_development_environment_policies() {
        let policies = CanonicalPolicies::development_environment();
        assert!(!policies.is_empty());
        assert!(policies.iter().any(|p| p.priority == 50));

        // File system policy should use not_glob constraint
        let fs_policy = &policies[0];
        assert_eq!(fs_policy.id, "file_system:*");
        if let PolicyType::Conditional { conditions } = &fs_policy.policy_type {
            let constraints = conditions.get("parameter_constraints").unwrap();
            let first = &constraints.as_array().unwrap()[0];
            assert_eq!(first["op"], "not_glob");
        } else {
            panic!("File system policy should be Conditional with parameter_constraints");
        }
    }

    #[test]
    fn test_block_dangerous_tools_match_engine() {
        // Verify that the IDs actually match the tools they're supposed to block
        let policies = CanonicalPolicies::block_dangerous_tools();
        let ids: Vec<&str> = policies.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"bash:*"));
        assert!(ids.contains(&"shell:*"));
        assert!(ids.contains(&"exec:*"));
    }

    #[test]
    fn test_deny_all_allow_all_are_simple() {
        let deny = CanonicalPolicies::deny_all();
        assert!(matches!(deny.policy_type, PolicyType::Deny));
        assert_eq!(deny.id, "*");

        let allow = CanonicalPolicies::allow_all();
        assert!(matches!(allow.policy_type, PolicyType::Allow));
        assert_eq!(allow.id, "*");
    }
}
