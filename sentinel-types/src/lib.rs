use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Maximum length for tool and function names (bytes).
const MAX_NAME_LEN: usize = 256;

/// Maximum length for individual path or domain strings (bytes).
const MAX_TARGET_LEN: usize = 4096;

/// Maximum number of combined target_paths + target_domains entries.
const MAX_TARGETS: usize = 256;

/// Validation errors for Action fields.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    /// Tool or function name is empty.
    EmptyField { field: &'static str },
    /// Tool or function name contains a null byte.
    NullByte { field: &'static str },
    /// Tool or function name exceeds the maximum length.
    TooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    /// Too many target_paths + target_domains entries.
    TooManyTargets { count: usize, max: usize },
    /// A target path or domain string is too long.
    TargetTooLong {
        field: &'static str,
        index: usize,
        len: usize,
        max: usize,
    },
    /// A target path or domain contains a null byte.
    TargetNullByte {
        field: &'static str,
        index: usize,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::EmptyField { field } => {
                write!(f, "Action {} must not be empty", field)
            }
            ValidationError::NullByte { field } => {
                write!(f, "Action {} contains null byte", field)
            }
            ValidationError::TooLong { field, len, max } => {
                write!(f, "Action {} too long: {} bytes (max {})", field, len, max)
            }
            ValidationError::TooManyTargets { count, max } => {
                write!(f, "Too many targets: {} (max {})", count, max)
            }
            ValidationError::TargetTooLong {
                field,
                index,
                len,
                max,
            } => {
                write!(
                    f,
                    "Target {}[{}] too long: {} bytes (max {})",
                    field, index, len, max
                )
            }
            ValidationError::TargetNullByte { field, index } => {
                write!(f, "Target {}[{}] contains null byte", field, index)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Action {
    pub tool: String,
    pub function: String,
    pub parameters: serde_json::Value,
    /// File paths targeted by this action (e.g. from `file://` URIs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_paths: Vec<String>,
    /// Domains targeted by this action (e.g. from `https://` URIs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_domains: Vec<String>,
}

/// Validate a single name field (tool or function).
fn validate_name(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyField { field });
    }
    if value.contains('\0') {
        return Err(ValidationError::NullByte { field });
    }
    if value.len() > MAX_NAME_LEN {
        return Err(ValidationError::TooLong {
            field,
            len: value.len(),
            max: MAX_NAME_LEN,
        });
    }
    Ok(())
}

impl Action {
    /// Create an Action with only tool, function, and parameters.
    /// `target_paths` and `target_domains` default to empty.
    ///
    /// Does NOT validate inputs — use [`Action::validated`] or [`Action::validate`]
    /// at trust boundaries (MCP extractor, HTTP proxy).
    pub fn new(
        tool: impl Into<String>,
        function: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            tool: tool.into(),
            function: function.into(),
            parameters,
            target_paths: Vec::new(),
            target_domains: Vec::new(),
        }
    }

    /// Create an Action with validation on tool and function names.
    ///
    /// Rejects empty names, null bytes, and names exceeding 256 bytes.
    /// Use this at trust boundaries where inputs come from external sources.
    pub fn validated(
        tool: impl Into<String>,
        function: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Result<Self, ValidationError> {
        let tool = tool.into();
        let function = function.into();
        validate_name(&tool, "tool")?;
        validate_name(&function, "function")?;
        Ok(Self {
            tool,
            function,
            parameters,
            target_paths: Vec::new(),
            target_domains: Vec::new(),
        })
    }

    /// Validate an existing Action's fields.
    ///
    /// Checks tool/function names, and target_paths/target_domains for
    /// null bytes, excessive length, and total count.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_name(&self.tool, "tool")?;
        validate_name(&self.function, "function")?;

        // Check combined target count
        let total_targets = self.target_paths.len() + self.target_domains.len();
        if total_targets > MAX_TARGETS {
            return Err(ValidationError::TooManyTargets {
                count: total_targets,
                max: MAX_TARGETS,
            });
        }

        // Validate individual target_paths
        for (i, path) in self.target_paths.iter().enumerate() {
            if path.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "target_paths",
                    index: i,
                });
            }
            if path.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "target_paths",
                    index: i,
                    len: path.len(),
                    max: MAX_TARGET_LEN,
                });
            }
        }

        // Validate individual target_domains
        for (i, domain) in self.target_domains.iter().enumerate() {
            if domain.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "target_domains",
                    index: i,
                });
            }
            if domain.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "target_domains",
                    index: i,
                    len: domain.len(),
                    max: MAX_TARGET_LEN,
                });
            }
        }

        Ok(())
    }
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

/// Path-based access control rules for file system operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PathRules {
    /// Glob patterns for allowed paths. If non-empty, only matching paths are allowed.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Glob patterns for blocked paths. Any match results in denial.
    #[serde(default)]
    pub blocked: Vec<String>,
}

/// Network-based access control rules for outbound connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NetworkRules {
    /// Domain patterns for allowed destinations. If non-empty, only matching domains are allowed.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Domain patterns for blocked destinations. Any match results in denial.
    #[serde(default)]
    pub blocked_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub policy_type: PolicyType,
    pub priority: i32,
    /// Optional path-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_rules: Option<PathRules>,
    /// Optional network-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rules: Option<NetworkRules>,
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

/// Session-level context for policy evaluation.
///
/// Separate from [`Action`] because Action = "what to do" (from the agent),
/// while Context = "session state" (from the proxy). This security boundary
/// ensures agents don't control context fields like call counts or timestamps.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvaluationContext {
    /// ISO 8601 timestamp for the evaluation. When `None`, the engine uses
    /// the current wall-clock time. Providing an explicit timestamp enables
    /// deterministic testing of time-window policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Identity of the agent making the request (e.g., OAuth subject, API key hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Per-tool call counts for the current session (tool_name → count).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub call_counts: HashMap<String, u64>,
    /// History of tool names called in this session (most recent last).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_actions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn test_action_serialization_roundtrip() {
        let action = Action::new("file_system", "read_file", json!({"path": "/tmp/test.txt"}));
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
            path_rules: None,
            network_rules: None,
        };
        let json_str = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.id, "bash:*");
        assert_eq!(deserialized.priority, 100);
    }

    // --- Action validation tests (M2) ---

    #[test]
    fn test_validated_accepts_valid_input() {
        let action = Action::validated("read_file", "execute", json!({}));
        assert!(action.is_ok());
        let action = action.unwrap();
        assert_eq!(action.tool, "read_file");
        assert_eq!(action.function, "execute");
    }

    #[test]
    fn test_validated_rejects_empty_tool() {
        let result = Action::validated("", "execute", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::EmptyField { field: "tool" })
        ));
    }

    #[test]
    fn test_validated_rejects_empty_function() {
        let result = Action::validated("read_file", "", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::EmptyField { field: "function" })
        ));
    }

    #[test]
    fn test_validated_rejects_null_bytes_in_tool() {
        let result = Action::validated("read\0file", "execute", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::NullByte { field: "tool" })
        ));
    }

    #[test]
    fn test_validated_rejects_null_bytes_in_function() {
        let result = Action::validated("read_file", "exec\0ute", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::NullByte { field: "function" })
        ));
    }

    #[test]
    fn test_validated_rejects_too_long_tool() {
        let long_name = "a".repeat(257);
        let result = Action::validated(long_name, "execute", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::TooLong { field: "tool", .. })
        ));
    }

    #[test]
    fn test_validated_accepts_max_length_tool() {
        let name = "a".repeat(256);
        let result = Action::validated(name, "execute", json!({}));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_existing_action() {
        let action = Action::new("read_file", "execute", json!({}));
        assert!(action.validate().is_ok());

        let bad = Action::new("", "execute", json!({}));
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_new_still_works_without_validation() {
        // Backward compatibility: new() doesn't validate
        let action = Action::new("", "", json!({}));
        assert_eq!(action.tool, "");
        assert_eq!(action.function, "");
    }

    #[test]
    fn test_validation_error_display() {
        let e = ValidationError::EmptyField { field: "tool" };
        assert!(e.to_string().contains("tool"));
        assert!(e.to_string().contains("empty"));
    }

    // --- Target validation tests ---

    #[test]
    fn test_validate_rejects_null_byte_in_target_path() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["/tmp/foo\0bar".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte { field: "target_paths", index: 0 })
        ));
    }

    #[test]
    fn test_validate_rejects_null_byte_in_target_domain() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_domains = vec!["evil\0.com".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte { field: "target_domains", index: 0 })
        ));
    }

    #[test]
    fn test_validate_rejects_too_long_target_path() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["a".repeat(4097)];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetTooLong { field: "target_paths", index: 0, .. })
        ));
    }

    #[test]
    fn test_validate_accepts_max_length_target_path() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["a".repeat(4096)];
        assert!(action.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_too_many_targets() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = (0..200).map(|i| format!("/path/{}", i)).collect();
        action.target_domains = (0..100).map(|i| format!("d{}.com", i)).collect();
        // 200 + 100 = 300 > 256
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TooManyTargets { count: 300, max: 256 })
        ));
    }

    #[test]
    fn test_validate_accepts_max_targets() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = (0..128).map(|i| format!("/path/{}", i)).collect();
        action.target_domains = (0..128).map(|i| format!("d{}.com", i)).collect();
        // 128 + 128 = 256 == MAX_TARGETS
        assert!(action.validate().is_ok());
    }

    #[test]
    fn test_validate_null_byte_second_target() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["/ok".to_string(), "/bad\0path".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte { field: "target_paths", index: 1 })
        ));
    }

    #[test]
    fn test_target_validation_error_display() {
        let e = ValidationError::TooManyTargets { count: 500, max: 256 };
        assert!(e.to_string().contains("500"));
        assert!(e.to_string().contains("256"));

        let e = ValidationError::TargetNullByte { field: "target_paths", index: 3 };
        assert!(e.to_string().contains("target_paths[3]"));
        assert!(e.to_string().contains("null byte"));

        let e = ValidationError::TargetTooLong { field: "target_domains", index: 0, len: 5000, max: 4096 };
        assert!(e.to_string().contains("5000"));
        assert!(e.to_string().contains("4096"));
    }

    // ═══════════════════════════════════════════════════
    // PROPERTY-BASED TESTS: Action Validation
    // ═══════════════════════════════════════════════════

    proptest! {
        // PROPERTY: validated() succeeds iff validate() succeeds on the same inputs
        #[test]
        fn validated_ok_iff_validate_ok(
            tool in "[a-z_]{0,260}",
            function in "[a-z_]{0,260}",
        ) {
            let validated_result = Action::validated(&tool, &function, json!({}));
            let new_action = Action::new(&tool, &function, json!({}));
            let validate_result = new_action.validate();

            prop_assert_eq!(
                validated_result.is_ok(),
                validate_result.is_ok(),
                "validated() and validate() must agree for tool={:?} function={:?}\n\
                 validated: {:?}\n\
                 validate:  {:?}",
                tool, function, validated_result, validate_result
            );
        }

        // PROPERTY: Any name containing a null byte is always rejected
        #[test]
        fn null_byte_always_rejected(
            prefix in "[a-z]{1,10}",
            suffix in "[a-z]{1,10}",
        ) {
            let tool_with_null = format!("{}\0{}", prefix, suffix);

            // Null in tool
            let result = Action::validated(&tool_with_null, "func", json!({}));
            prop_assert!(
                matches!(result, Err(ValidationError::NullByte { field: "tool" })),
                "Null byte in tool must be rejected. Got: {:?}", result
            );

            // Null in function
            let result = Action::validated("tool", &tool_with_null, json!({}));
            prop_assert!(
                matches!(result, Err(ValidationError::NullByte { field: "function" })),
                "Null byte in function must be rejected. Got: {:?}", result
            );
        }

        // PROPERTY: Empty tool or function name is always rejected
        #[test]
        fn empty_name_always_rejected(
            other in "[a-z]{1,10}",
        ) {
            let result = Action::validated("", &other, json!({}));
            prop_assert!(
                matches!(result, Err(ValidationError::EmptyField { field: "tool" })),
                "Empty tool must be rejected. Got: {:?}", result
            );

            let result = Action::validated(&other, "", json!({}));
            prop_assert!(
                matches!(result, Err(ValidationError::EmptyField { field: "function" })),
                "Empty function must be rejected. Got: {:?}", result
            );
        }

        // PROPERTY: 256-byte name is accepted, 257-byte name is rejected
        #[test]
        fn max_length_boundary(
            ch in "[a-z]",
        ) {
            let at_max = ch.repeat(256);
            let over_max = ch.repeat(257);

            let ok_result = Action::validated(&at_max, "func", json!({}));
            prop_assert!(ok_result.is_ok(),
                "256-byte name must be accepted. Got: {:?}", ok_result);

            let err_result = Action::validated(&over_max, "func", json!({}));
            prop_assert!(
                matches!(err_result, Err(ValidationError::TooLong { field: "tool", .. })),
                "257-byte name must be rejected. Got: {:?}", err_result
            );
        }

        // PROPERTY: Valid actions roundtrip through serde unchanged
        #[test]
        fn valid_names_roundtrip_serde(
            tool in "[a-z_]{1,20}",
            function in "[a-z_]{1,20}",
        ) {
            let action = Action::validated(&tool, &function, json!({"key": "value"})).unwrap();
            let serialized = serde_json::to_string(&action).unwrap();
            let deserialized: Action = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(&action, &deserialized,
                "Valid action must roundtrip through serde unchanged");
        }
    }
}
