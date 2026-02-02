use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Action {
    pub tool: String,
    pub function: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyType {
    Allow,
    Deny,
    Conditional { conditions: serde_json::Value },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub policy_type: PolicyType,
    pub priority: i32,
}

// ═══════════════════════════════════════════════════
// EVALUATION TRACE TYPES (Phase 10.4)
// ═══════════════════════════════════════════════════

/// Full evaluation trace for a single action evaluation.
///
/// Returned by `PolicyEngine::evaluate_action_traced()` when callers need
/// OPA-style decision explanations (e.g. `?trace=true` on the HTTP proxy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationTrace {
    pub action_summary: ActionSummary,
    pub policies_checked: usize,
    pub policies_matched: usize,
    pub matches: Vec<PolicyMatch>,
    pub verdict: Verdict,
    pub duration_us: u64,
}

/// Summary of the action being evaluated (no raw parameter values for security).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSummary {
    pub tool: String,
    pub function: String,
    pub param_count: usize,
    pub param_keys: Vec<String>,
}

/// Per-policy evaluation result within a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMatch {
    pub policy_id: String,
    pub policy_name: String,
    pub policy_type: String,
    pub priority: i32,
    pub tool_matched: bool,
    pub constraint_results: Vec<ConstraintResult>,
    pub verdict_contribution: Option<Verdict>,
}

/// Individual constraint evaluation result within a policy match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintResult {
    pub constraint_type: String,
    pub param: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_action_serialization_roundtrip() {
        let action = Action {
            tool: "file_system".to_string(),
            function: "read_file".to_string(),
            parameters: json!({"path": "/tmp/test.txt"}),
        };
        let json_str = serde_json::to_string(&action).unwrap();
        let deserialized: Action = serde_json::from_str(&json_str).unwrap();
        assert_eq!(action, deserialized);
    }

    #[test]
    fn test_verdict_all_variants() {
        let variants = vec![
            Verdict::Allow,
            Verdict::Deny {
                reason: "blocked".to_string(),
            },
            Verdict::RequireApproval {
                reason: "needs review".to_string(),
            },
        ];
        for v in variants {
            let json_str = serde_json::to_string(&v).unwrap();
            let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
            assert_eq!(v, deserialized);
        }
    }

    #[test]
    fn test_policy_type_conditional_with_value() {
        let pt = PolicyType::Conditional {
            conditions: json!({"tool_pattern": "bash", "forbidden_parameters": ["force"]}),
        };
        let json_str = serde_json::to_string(&pt).unwrap();
        let deserialized: PolicyType = serde_json::from_str(&json_str).unwrap();
        assert_eq!(pt, deserialized);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
        };
        let json_str = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.id, "bash:*");
        assert_eq!(deserialized.priority, 100);
    }
}
