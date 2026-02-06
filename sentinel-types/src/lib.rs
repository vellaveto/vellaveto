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
    /// Tool or function name contains a control character (tab, newline, etc.).
    ControlCharacter { field: &'static str },
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
    TargetNullByte { field: &'static str, index: usize },
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
            ValidationError::ControlCharacter { field } => {
                write!(f, "Action {} contains control character", field)
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
    /// IP addresses resolved from target_domains (populated by proxy layer).
    /// Used by the engine for DNS rebinding protection when `IpRules` are configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_ips: Vec<String>,
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
    // SECURITY (R12-TYPES-1): Reject names with control characters or
    // that are whitespace-only. Prevents homoglyph/invisible-char bypass
    // and log confusion.
    if value.trim().is_empty() {
        return Err(ValidationError::EmptyField { field });
    }
    // SECURITY (R16-TYPES-1): Use distinct variant for control characters
    // so error messages accurately describe the issue.
    if value.chars().any(|c| c.is_control() && c != '\0') {
        return Err(ValidationError::ControlCharacter { field });
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
            resolved_ips: Vec::new(),
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
            resolved_ips: Vec::new(),
        })
    }

    /// Validate an existing Action's fields.
    ///
    /// Checks tool/function names, and target_paths/target_domains for
    /// null bytes, excessive length, and total count.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_name(&self.tool, "tool")?;
        validate_name(&self.function, "function")?;

        // Check combined target count (R39-ENG-4: include resolved_ips)
        let total_targets = self.target_paths.len() + self.target_domains.len() + self.resolved_ips.len();
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

        // SECURITY (R42-TYPES-1): Validate resolved_ips contents (null bytes, length).
        // Previously only counted toward MAX_TARGETS but contents were not checked,
        // unlike target_paths and target_domains which validate null bytes and length.
        for (i, ip) in self.resolved_ips.iter().enumerate() {
            if ip.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "resolved_ips",
                    index: i,
                });
            }
            if ip.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "resolved_ips",
                    index: i,
                    len: ip.len(),
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
    /// IP-level access control for DNS rebinding protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_rules: Option<IpRules>,
}

/// IP-level access control rules (DNS rebinding protection).
///
/// When configured, the proxy layer resolves target domains to IP addresses
/// and the engine checks them against these rules. This prevents attacks
/// where an allowed domain's DNS record changes to point at a private IP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct IpRules {
    /// Block connections to private/reserved IPs (RFC 1918, loopback, link-local).
    #[serde(default)]
    pub block_private: bool,
    /// CIDR ranges to block (e.g. "10.0.0.0/8").
    #[serde(default)]
    pub blocked_cidrs: Vec<String>,
    /// CIDR ranges to allow. If non-empty, only matching IPs are allowed.
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
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

/// Cryptographically attested agent identity from a signed JWT.
///
/// This type represents a validated identity extracted from the `X-Agent-Identity`
/// header. Unlike the simple `agent_id` string, this provides cryptographic
/// attestation of the agent's identity via JWT signature verification.
///
/// # Security (OWASP ASI07 - Agent Identity Attestation)
///
/// - All claims are extracted from a signature-verified JWT
/// - The proxy validates the JWT before populating this struct
/// - Policies can match on issuer, subject, and custom claims
/// - This provides stronger identity guarantees than the legacy `agent_id` field
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AgentIdentity {
    /// JWT issuer (`iss` claim). Identifies the identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// JWT subject (`sub` claim). Identifies the specific agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// JWT audience (`aud` claim). May be a single string or array.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    /// Additional custom claims from the JWT payload.
    /// Common claims: `role`, `team`, `environment`, `permissions`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub claims: HashMap<String, serde_json::Value>,
}

impl AgentIdentity {
    /// Returns true if this identity has any populated fields.
    pub fn is_populated(&self) -> bool {
        self.issuer.is_some()
            || self.subject.is_some()
            || !self.audience.is_empty()
            || !self.claims.is_empty()
    }

    /// Get a claim value as a string, if present and is a string.
    pub fn claim_str(&self, key: &str) -> Option<&str> {
        self.claims.get(key).and_then(|v| v.as_str())
    }

    /// Get a claim value as an array of strings, if present and is an array.
    pub fn claim_str_array(&self, key: &str) -> Option<Vec<&str>> {
        self.claims.get(key).and_then(|v| {
            v.as_array().map(|arr| {
                arr.iter().filter_map(|item| item.as_str()).collect()
            })
        })
    }
}

/// An entry in a multi-agent call chain, tracking the path of a request
/// through multiple agents in a multi-hop MCP scenario.
///
/// OWASP ASI08: Multi-agent communication monitoring requires tracking
/// the full chain of tool calls to detect privilege escalation patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallChainEntry {
    /// The agent that made this call (from X-Upstream-Agent header or OAuth subject).
    pub agent_id: String,
    /// The tool being called.
    pub tool: String,
    /// The function being called.
    pub function: String,
    /// ISO 8601 timestamp when the call was made.
    pub timestamp: String,
    /// HMAC-SHA256 signature over the entry content (FIND-015).
    /// Present when the entry was signed by a Sentinel instance with a configured HMAC key.
    /// Hex-encoded. Omitted from serialization when `None` for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
    /// Whether the HMAC on this entry has been verified (FIND-015).
    /// `None` = not checked (no key configured or entry has no HMAC).
    /// `Some(true)` = HMAC verified successfully.
    /// `Some(false)` = HMAC verification failed (entry marked as unverified).
    /// Excluded from serialization — this is local verification state only.
    #[serde(skip)]
    pub verified: Option<bool>,
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
    /// This is the legacy identity field — prefer `agent_identity` for stronger guarantees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Cryptographically attested agent identity from a signed JWT (OWASP ASI07).
    ///
    /// When present, this provides stronger identity guarantees than `agent_id`.
    /// Populated from the `X-Agent-Identity` header after JWT signature verification.
    /// Policies can use `agent_identity` context conditions to match on claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentity>,
    /// Per-tool call counts for the current session (tool_name → count).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub call_counts: HashMap<String, u64>,
    /// History of tool names called in this session (most recent last).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_actions: Vec<String>,
    /// OWASP ASI08: Call chain for multi-agent communication monitoring.
    /// Records the path of the current request through multiple agents.
    /// The first entry is the originating agent, subsequent entries are
    /// intermediary agents in multi-hop scenarios.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_chain: Vec<CallChainEntry>,
}

impl EvaluationContext {
    /// Returns true if any context field is populated with meaningful data.
    /// Used by the engine to decide whether falling back to the legacy path
    /// (which cannot evaluate context conditions) is safe.
    // SECURITY (R16-TYPES-2): Include timestamp so time-window policies
    // fail-closed when compiled policies are unavailable, rather than
    // silently falling back to the legacy path that ignores time constraints.
    pub fn has_any_meaningful_fields(&self) -> bool {
        self.timestamp.is_some()
            || self.agent_id.is_some()
            || self.agent_identity.as_ref().is_some_and(|id| id.is_populated())
            || !self.call_counts.is_empty()
            || !self.previous_actions.is_empty()
            || !self.call_chain.is_empty()
    }

    /// Returns the depth of the current call chain (number of agents in the chain).
    /// A depth of 0 means no multi-hop scenario (direct call).
    /// A depth of 1 means there is one upstream agent.
    pub fn call_chain_depth(&self) -> usize {
        self.call_chain.len()
    }

    /// Returns the originating agent ID if this is a multi-hop request.
    /// This is the first agent in the call chain (the one that initiated the request).
    pub fn originating_agent(&self) -> Option<&str> {
        self.call_chain.first().map(|e| e.agent_id.as_str())
    }
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

    #[test]
    fn test_validated_rejects_control_chars_with_correct_variant() {
        // Tab character should produce ControlCharacter, not NullByte
        let result = Action::validated("read\tfile", "execute", json!({}));
        assert!(
            matches!(
                result,
                Err(ValidationError::ControlCharacter { field: "tool" })
            ),
            "Tab should produce ControlCharacter variant, got: {:?}",
            result
        );

        // Newline in function
        let result = Action::validated("tool", "exec\nute", json!({}));
        assert!(
            matches!(
                result,
                Err(ValidationError::ControlCharacter { field: "function" })
            ),
            "Newline should produce ControlCharacter variant, got: {:?}",
            result
        );
    }

    #[test]
    fn test_control_character_error_display() {
        let e = ValidationError::ControlCharacter { field: "tool" };
        let msg = e.to_string();
        assert!(
            msg.contains("control character"),
            "Error message should say 'control character', got: {}",
            msg
        );
        assert!(!msg.contains("null byte"), "Should NOT mention null byte");
    }

    // --- Target validation tests ---

    #[test]
    fn test_validate_rejects_null_byte_in_target_path() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["/tmp/foo\0bar".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "target_paths",
                index: 0
            })
        ));
    }

    #[test]
    fn test_validate_rejects_null_byte_in_target_domain() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_domains = vec!["evil\0.com".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "target_domains",
                index: 0
            })
        ));
    }

    #[test]
    fn test_validate_rejects_too_long_target_path() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["a".repeat(4097)];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetTooLong {
                field: "target_paths",
                index: 0,
                ..
            })
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
            Err(ValidationError::TooManyTargets {
                count: 300,
                max: 256
            })
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
    fn test_validate_rejects_too_many_resolved_ips_r39_eng_4() {
        // R39-ENG-4: resolved_ips must be counted in total_targets.
        // 300 resolved_ips alone should exceed MAX_TARGETS=256.
        let mut action = Action::new("tool", "func", json!({}));
        action.resolved_ips = (0..300).map(|i| format!("10.0.{}.{}", i / 256, i % 256)).collect();
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TooManyTargets {
                count: 300,
                max: 256
            })
        ));
    }

    #[test]
    fn test_validate_resolved_ips_combined_with_paths_domains_r39_eng_4() {
        // R39-ENG-4: Combination of paths + domains + IPs exceeding MAX_TARGETS
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = (0..100).map(|i| format!("/path/{}", i)).collect();
        action.target_domains = (0..100).map(|i| format!("d{}.com", i)).collect();
        action.resolved_ips = (0..57).map(|i| format!("10.0.0.{}", i)).collect();
        // 100 + 100 + 57 = 257 > 256
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TooManyTargets {
                count: 257,
                max: 256
            })
        ));
    }

    #[test]
    fn test_validate_resolved_ips_at_boundary_r39_eng_4() {
        // R39-ENG-4: paths + domains + IPs exactly at MAX_TARGETS should pass
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = (0..85).map(|i| format!("/path/{}", i)).collect();
        action.target_domains = (0..85).map(|i| format!("d{}.com", i)).collect();
        action.resolved_ips = (0..86).map(|i| format!("10.0.0.{}", i)).collect();
        // 85 + 85 + 86 = 256 == MAX_TARGETS
        assert!(action.validate().is_ok());
    }

    // --- R42-TYPES-1: resolved_ips content validation tests ---

    #[test]
    fn test_r42_types_1_resolved_ips_null_byte_rejected() {
        // R42-TYPES-1: resolved_ips with null byte must be rejected
        let mut action = Action::new("tool", "func", json!({}));
        action.resolved_ips = vec!["10.0.0.1".to_string(), "10.0.\0.2".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "resolved_ips",
                index: 1
            })
        ));
    }

    #[test]
    fn test_r42_types_1_resolved_ips_oversized_rejected() {
        // R42-TYPES-1: resolved_ips with oversized string must be rejected
        let mut action = Action::new("tool", "func", json!({}));
        let oversized = "A".repeat(4097); // MAX_TARGET_LEN is 4096
        action.resolved_ips = vec![oversized];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetTooLong {
                field: "resolved_ips",
                index: 0,
                len: 4097,
                max: 4096
            })
        ));
    }

    #[test]
    fn test_r42_types_1_resolved_ips_valid_entries_pass() {
        // R42-TYPES-1: Valid resolved_ips should pass validation
        let mut action = Action::new("tool", "func", json!({}));
        action.resolved_ips = vec![
            "10.0.0.1".to_string(),
            "192.168.1.1".to_string(),
            "::1".to_string(),
        ];
        assert!(action.validate().is_ok());
    }

    #[test]
    fn test_r42_types_1_resolved_ips_null_byte_first_entry() {
        // R42-TYPES-1: null byte at index 0
        let mut action = Action::new("tool", "func", json!({}));
        action.resolved_ips = vec!["\0".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "resolved_ips",
                index: 0
            })
        ));
    }

    #[test]
    fn test_validate_null_byte_second_target() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["/ok".to_string(), "/bad\0path".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "target_paths",
                index: 1
            })
        ));
    }

    #[test]
    fn test_target_validation_error_display() {
        let e = ValidationError::TooManyTargets {
            count: 500,
            max: 256,
        };
        assert!(e.to_string().contains("500"));
        assert!(e.to_string().contains("256"));

        let e = ValidationError::TargetNullByte {
            field: "target_paths",
            index: 3,
        };
        assert!(e.to_string().contains("target_paths[3]"));
        assert!(e.to_string().contains("null byte"));

        let e = ValidationError::TargetTooLong {
            field: "target_domains",
            index: 0,
            len: 5000,
            max: 4096,
        };
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

    // SECURITY (R16-TYPES-2): EvaluationContext.has_any_meaningful_fields()
    // must include timestamp so time-window policies fail-closed.
    #[test]
    fn test_context_timestamp_only_is_meaningful() {
        let ctx = EvaluationContext {
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(
            ctx.has_any_meaningful_fields(),
            "Context with only timestamp should be meaningful"
        );
    }

    #[test]
    fn test_context_empty_is_not_meaningful() {
        let ctx = EvaluationContext::default();
        assert!(
            !ctx.has_any_meaningful_fields(),
            "Default context should not be meaningful"
        );
    }

    // --- Call chain tests (OWASP ASI08) ---

    #[test]
    fn test_call_chain_entry_serialization() {
        let entry = CallChainEntry {
            agent_id: "agent-a".to_string(),
            tool: "read_file".to_string(),
            function: "execute".to_string(),
            timestamp: "2026-01-01T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        };
        let json_str = serde_json::to_string(&entry).unwrap();
        let deserialized: CallChainEntry = serde_json::from_str(&json_str).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_context_call_chain_is_meaningful() {
        let ctx = EvaluationContext {
            call_chain: vec![CallChainEntry {
                agent_id: "agent-a".to_string(),
                tool: "read_file".to_string(),
                function: "execute".to_string(),
                timestamp: "2026-01-01T12:00:00Z".to_string(),
                hmac: None,
                verified: None,
            }],
            ..Default::default()
        };
        assert!(
            ctx.has_any_meaningful_fields(),
            "Context with call_chain should be meaningful"
        );
    }

    #[test]
    fn test_call_chain_depth() {
        let empty_ctx = EvaluationContext::default();
        assert_eq!(empty_ctx.call_chain_depth(), 0);

        let single_hop_ctx = EvaluationContext {
            call_chain: vec![CallChainEntry {
                agent_id: "agent-a".to_string(),
                tool: "tool1".to_string(),
                function: "func1".to_string(),
                timestamp: "2026-01-01T12:00:00Z".to_string(),
                hmac: None,
                verified: None,
            }],
            ..Default::default()
        };
        assert_eq!(single_hop_ctx.call_chain_depth(), 1);

        let multi_hop_ctx = EvaluationContext {
            call_chain: vec![
                CallChainEntry {
                    agent_id: "agent-a".to_string(),
                    tool: "tool1".to_string(),
                    function: "func1".to_string(),
                    timestamp: "2026-01-01T12:00:00Z".to_string(),
                    hmac: None,
                    verified: None,
                },
                CallChainEntry {
                    agent_id: "agent-b".to_string(),
                    tool: "tool2".to_string(),
                    function: "func2".to_string(),
                    timestamp: "2026-01-01T12:00:01Z".to_string(),
                    hmac: None,
                    verified: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(multi_hop_ctx.call_chain_depth(), 2);
    }

    #[test]
    fn test_originating_agent() {
        let empty_ctx = EvaluationContext::default();
        assert!(empty_ctx.originating_agent().is_none());

        let ctx = EvaluationContext {
            call_chain: vec![
                CallChainEntry {
                    agent_id: "origin-agent".to_string(),
                    tool: "tool1".to_string(),
                    function: "func1".to_string(),
                    timestamp: "2026-01-01T12:00:00Z".to_string(),
                    hmac: None,
                    verified: None,
                },
                CallChainEntry {
                    agent_id: "proxy-agent".to_string(),
                    tool: "tool2".to_string(),
                    function: "func2".to_string(),
                    timestamp: "2026-01-01T12:00:01Z".to_string(),
                    hmac: None,
                    verified: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(ctx.originating_agent(), Some("origin-agent"));
    }

    // --- AgentIdentity tests (OWASP ASI07) ---

    #[test]
    fn test_agent_identity_serialization_roundtrip() {
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), json!("admin"));
        claims.insert("permissions".to_string(), json!(["read", "write"]));

        let identity = AgentIdentity {
            issuer: Some("https://auth.example.com".to_string()),
            subject: Some("agent-123".to_string()),
            audience: vec!["mcp-server".to_string()],
            claims,
        };

        let json_str = serde_json::to_string(&identity).unwrap();
        let deserialized: AgentIdentity = serde_json::from_str(&json_str).unwrap();
        assert_eq!(identity, deserialized);
    }

    #[test]
    fn test_agent_identity_is_populated() {
        let empty = AgentIdentity::default();
        assert!(!empty.is_populated());

        let with_issuer = AgentIdentity {
            issuer: Some("https://auth.example.com".to_string()),
            ..Default::default()
        };
        assert!(with_issuer.is_populated());

        let with_subject = AgentIdentity {
            subject: Some("agent-123".to_string()),
            ..Default::default()
        };
        assert!(with_subject.is_populated());

        let with_audience = AgentIdentity {
            audience: vec!["server".to_string()],
            ..Default::default()
        };
        assert!(with_audience.is_populated());

        let mut claims = HashMap::new();
        claims.insert("role".to_string(), json!("admin"));
        let with_claims = AgentIdentity {
            claims,
            ..Default::default()
        };
        assert!(with_claims.is_populated());
    }

    #[test]
    fn test_agent_identity_claim_str() {
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), json!("admin"));
        claims.insert("count".to_string(), json!(42));

        let identity = AgentIdentity {
            claims,
            ..Default::default()
        };

        assert_eq!(identity.claim_str("role"), Some("admin"));
        assert_eq!(identity.claim_str("count"), None); // Not a string
        assert_eq!(identity.claim_str("missing"), None);
    }

    #[test]
    fn test_agent_identity_claim_str_array() {
        let mut claims = HashMap::new();
        claims.insert("permissions".to_string(), json!(["read", "write"]));
        claims.insert("role".to_string(), json!("admin")); // Not an array
        claims.insert("mixed".to_string(), json!(["str", 42])); // Mixed types

        let identity = AgentIdentity {
            claims,
            ..Default::default()
        };

        assert_eq!(
            identity.claim_str_array("permissions"),
            Some(vec!["read", "write"])
        );
        assert_eq!(identity.claim_str_array("role"), None); // Not an array
        // Mixed array should only contain strings
        assert_eq!(identity.claim_str_array("mixed"), Some(vec!["str"]));
        assert_eq!(identity.claim_str_array("missing"), None);
    }

    #[test]
    fn test_context_with_agent_identity_is_meaningful() {
        let identity = AgentIdentity {
            subject: Some("agent-123".to_string()),
            ..Default::default()
        };
        let ctx = EvaluationContext {
            agent_identity: Some(identity),
            ..Default::default()
        };
        assert!(
            ctx.has_any_meaningful_fields(),
            "Context with agent_identity should be meaningful"
        );
    }

    #[test]
    fn test_context_with_empty_agent_identity_is_not_meaningful() {
        let ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity::default()),
            ..Default::default()
        };
        assert!(
            !ctx.has_any_meaningful_fields(),
            "Context with empty agent_identity should not be meaningful"
        );
    }
}
