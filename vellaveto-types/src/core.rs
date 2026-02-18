//! Core policy types — Action, Verdict, PolicyType, PathRules, NetworkRules,
//! IpRules, Policy, evaluation trace types, and validation.

use crate::threat::ValidationError;
use serde::{Deserialize, Serialize};

/// Maximum length for tool and function names (bytes).
const MAX_NAME_LEN: usize = 256;

/// Maximum length for individual path or domain strings (bytes).
const MAX_TARGET_LEN: usize = 4096;

/// Maximum number of combined `target_paths` + `target_domains` entries.
const MAX_TARGETS: usize = 256;

/// Maximum serialized size of `parameters` in bytes (1 MiB).
///
/// SECURITY (FIND-P3-016): Prevents memory exhaustion from oversized
/// parameter payloads. 1 MiB is generous for tool call parameters
/// while still bounding memory usage per-action.
const MAX_PARAMETERS_SIZE: usize = 1_048_576;

/// Returns true if the character is a Unicode format character (category Cf)
/// that could cause identity confusion or log injection.
///
/// SECURITY (FIND-R55-CORE-001, FIND-R56-CORE-001): Covers zero-width chars,
/// bidi overrides, and BOM. Canonical implementation — identity.rs and threat.rs
/// call this via `crate::core::is_unicode_format_char()`.
pub(crate) fn is_unicode_format_char(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}' |  // zero-width space, ZWNJ, ZWJ, LRM, RLM
        '\u{202A}'..='\u{202E}' |  // bidi overrides (LRE, RLE, PDF, LRO, RLO)
        '\u{2060}'..='\u{2069}' |  // word joiner, invisible separators, bidi isolates
        '\u{FEFF}'                  // BOM / zero-width no-break space
    )
}

/// Validate a single name field (tool or function).
///
/// This is `pub(crate)` intentionally — external callers should use
/// [`Action::validated`] or [`Action::validate`] which call this internally.
/// Keeping it crate-private avoids exposing an internal validation primitive
/// in the public API surface.
pub(crate) fn validate_name(value: &str, field: &'static str) -> Result<(), ValidationError> {
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
    // SECURITY (R16-TYPES-1, FIND-R55-CORE-001): Reject control characters
    // and Unicode format characters (zero-width, bidi overrides, BOM) that
    // could cause identity confusion or bypass pattern matching.
    // Note: '\0' is excluded from the control char check here because null
    // bytes are caught above with the specific NullByte error variant (FIND-R56-CORE-005).
    if value
        .chars()
        .any(|c| (c.is_control() && c != '\0') || is_unicode_format_char(c))
    {
        return Err(ValidationError::ControlCharacter { field });
    }
    Ok(())
}

/// A tool-call action submitted for policy evaluation.
///
/// Represents a single invocation of a tool function with its parameters
/// and optional target paths/domains. This is the primary input to the
/// policy engine's `evaluate()` method.
///
/// Use [`Action::validated`] or [`Action::validate`] at trust boundaries
/// (MCP extractor, HTTP proxy) to enforce structural invariants before
/// evaluation.
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
    /// IP addresses resolved from `target_domains` (populated by proxy layer).
    /// Used by the engine for DNS rebinding protection when [`IpRules`] are configured.
    ///
    /// # Security
    ///
    /// This field MUST only be set by the proxy layer after performing DNS resolution.
    /// If set by an untrusted client, an attacker could provide fake resolved IPs to
    /// bypass IP-based access controls (e.g., claiming a private IP is a public one).
    /// The proxy layer should always overwrite any client-supplied `resolved_ips`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_ips: Vec<String>,
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
    /// Checks tool/function names, parameters size, and
    /// `target_paths`/`target_domains` for null bytes, excessive length,
    /// and total count.
    ///
    /// # Error type
    ///
    /// Returns [`ValidationError`] (a structured enum) rather than `String`
    /// so callers can programmatically match on specific failure kinds
    /// (e.g., `NullByte`, `TooLong`, `ParametersTooLarge`). Other `validate()`
    /// methods in this crate return `Result<(), String>` because they were
    /// added later and their errors are purely diagnostic.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_name(&self.tool, "tool")?;
        validate_name(&self.function, "function")?;

        // SECURITY (FIND-P3-016): Bound parameters size to prevent memory exhaustion.
        // SECURITY (FIND-R48-001): Fail-closed when serialization fails — reject rather
        // than silently skipping the size check.
        match serde_json::to_string(&self.parameters) {
            Ok(serialized) => {
                if serialized.len() > MAX_PARAMETERS_SIZE {
                    return Err(ValidationError::ParametersTooLarge {
                        size: serialized.len(),
                        max: MAX_PARAMETERS_SIZE,
                    });
                }
            }
            Err(_) => {
                return Err(ValidationError::ParametersTooLarge {
                    size: 0,
                    max: MAX_PARAMETERS_SIZE,
                });
            }
        }

        // Check combined target count (R39-ENG-4: include resolved_ips)
        let total_targets =
            self.target_paths.len() + self.target_domains.len() + self.resolved_ips.len();
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

/// Result of policy evaluation for an [`Action`].
///
/// - `Allow` — the action is permitted.
/// - `Deny` — the action is blocked, with a human-readable reason.
/// - `RequireApproval` — the action needs explicit operator approval before proceeding.
///
/// Marked `#[non_exhaustive]` to allow future variants without breaking downstream matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum Verdict {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String },
}

/// The disposition of a [`Policy`] — whether it allows, denies, or conditionally
/// gates actions.
///
/// - `Allow` — matching actions are permitted.
/// - `Deny` — matching actions are blocked.
/// - `Conditional` — matching actions are evaluated against a JSON condition tree
///   (see context-aware policy evaluation in the engine).
///
/// Marked `#[non_exhaustive]` to allow future variants without breaking downstream matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum PolicyType {
    Allow,
    Deny,
    Conditional { conditions: serde_json::Value },
}

/// Path-based access control rules for file system operations.
/// SECURITY (FIND-R46-015): deny_unknown_fields prevents misconfiguration
/// where a typo (e.g. "allow" instead of "allowed") would silently produce
/// an empty allowlist, which is a fail-open condition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct PathRules {
    /// Glob patterns for allowed paths. If non-empty, only matching paths are allowed.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Glob patterns for blocked paths. Any match results in denial.
    #[serde(default)]
    pub blocked: Vec<String>,
}

/// Network-based access control rules for outbound connections.
/// SECURITY (FIND-R46-015): deny_unknown_fields prevents misconfiguration
/// where a typo (e.g. "allowed_domain" instead of "allowed_domains") would
/// silently produce an empty allowlist, which is a fail-open condition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
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
/// SECURITY (FIND-R46-015): deny_unknown_fields prevents misconfiguration
/// where a typo (e.g. "blocked_cidr" instead of "blocked_cidrs") would
/// silently skip IP blocking rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
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

/// A security policy that governs whether an [`Action`] is allowed, denied,
/// or requires approval.
///
/// Policies are matched against actions by the engine in priority order
/// (higher `priority` value = evaluated first). Each policy may include
/// optional [`PathRules`] and [`NetworkRules`] for fine-grained access control.
///
/// # Validation
///
/// Call [`Policy::validate()`] after deserialization to enforce structural
/// invariants (non-empty id/name, non-negative priority, bounded conditions).
// SECURITY (FIND-R48-011): deny_unknown_fields catches typos like "network_rule"
// that would silently result in missing security rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Maximum length for policy id (bytes).
/// SECURITY (FIND-R55-CORE-012): Bounds policy identifier length.
const MAX_POLICY_ID_LEN: usize = 256;
/// Maximum length for policy name (bytes).
/// SECURITY (FIND-R55-CORE-012): Bounds policy display name length.
const MAX_POLICY_NAME_LEN: usize = 512;

/// Maximum serialized size of `Conditional` conditions in bytes (64 KiB).
///
/// SECURITY (FIND-R49-003, FIND-R56-CORE-003): Prevents memory exhaustion
/// via deeply nested or excessively large JSON condition values.
const MAX_CONDITIONS_SIZE: usize = 65_536;

impl Policy {
    /// Validate structural invariants of a `Policy`.
    ///
    /// Checks:
    /// - `id` is not empty, max 256 bytes, no control/format chars
    /// - `name` is not empty, max 512 bytes, no control/format chars
    /// - `priority` is non-negative (>= 0)
    ///
    /// SECURITY (FIND-P2-008): Policies with empty IDs could collide in
    /// lookups; empty names hamper audit legibility; negative priorities
    /// could invert evaluation ordering expectations.
    /// SECURITY (FIND-R55-CORE-012): Validate id and name for control characters,
    /// Unicode format characters, and length bounds to prevent log injection
    /// and memory abuse via oversized policy identifiers.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("Policy id must not be empty".to_string());
        }
        if self.id.len() > MAX_POLICY_ID_LEN {
            return Err(format!(
                "Policy id length {} exceeds max {}",
                self.id.len(),
                MAX_POLICY_ID_LEN
            ));
        }
        if self
            .id
            .chars()
            .any(|c| c.is_control() || is_unicode_format_char(c))
        {
            return Err("Policy id contains control or format characters".to_string());
        }
        if self.name.is_empty() {
            return Err(format!("Policy '{}' name must not be empty", self.id));
        }
        if self.name.len() > MAX_POLICY_NAME_LEN {
            return Err(format!(
                "Policy '{}' name length {} exceeds max {}",
                self.id,
                self.name.len(),
                MAX_POLICY_NAME_LEN
            ));
        }
        if self
            .name
            .chars()
            .any(|c| c.is_control() || is_unicode_format_char(c))
        {
            return Err(format!(
                "Policy '{}' name contains control or format characters",
                self.id
            ));
        }
        if self.priority < 0 {
            return Err(format!(
                "Policy '{}' priority must be non-negative, got {}",
                self.id, self.priority
            ));
        }
        // SECURITY (FIND-R49-003): Reject oversized Conditional conditions to prevent
        // memory exhaustion via deeply nested or excessively large JSON values.
        if let PolicyType::Conditional { ref conditions } = self.policy_type {
            let serialized = serde_json::to_string(conditions).map_err(|e| {
                format!(
                    "Policy '{}' Conditional conditions failed to serialize: {}",
                    self.id, e
                )
            })?;
            if serialized.len() > MAX_CONDITIONS_SIZE {
                return Err(format!(
                    "Policy '{}' Conditional conditions exceed {} bytes (got {})",
                    self.id,
                    MAX_CONDITIONS_SIZE,
                    serialized.len()
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 TOOL NAME VALIDATION (Phase 30)
// ═══════════════════════════════════════════════════

/// Maximum length for MCP 2025-11-25 tool names.
const MCP_TOOL_NAME_MAX_LEN: usize = 64;

/// Validate a tool name per MCP 2025-11-25 specification.
///
/// Rules:
/// - Length: 1–64 characters
/// - Charset: `[a-zA-Z0-9_\-./]`
/// - No leading/trailing dots or slashes
/// - No consecutive dots (`..`) — prevents path traversal in tool namespaces
///
/// Returns `Ok(())` on valid names, `Err(description)` on invalid.
pub fn validate_mcp_tool_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("tool name must not be empty".to_string());
    }
    if name.len() > MCP_TOOL_NAME_MAX_LEN {
        return Err(format!(
            "tool name exceeds {} characters (got {})",
            MCP_TOOL_NAME_MAX_LEN,
            name.len()
        ));
    }
    // Charset: only [a-zA-Z0-9_\-./]
    for (i, ch) in name.chars().enumerate() {
        if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' | '/') {
            return Err(format!(
                "invalid character '{}' at position {} (allowed: a-zA-Z0-9_-./)",
                ch, i
            ));
        }
    }
    // No leading/trailing dots or slashes
    if name.starts_with('.') || name.starts_with('/') {
        return Err("tool name must not start with '.' or '/'".to_string());
    }
    if name.ends_with('.') || name.ends_with('/') {
        return Err("tool name must not end with '.' or '/'".to_string());
    }
    // No consecutive dots (path traversal prevention)
    if name.contains("..") {
        return Err("tool name must not contain consecutive dots '..'".to_string());
    }
    // No consecutive slashes (path normalization ambiguity)
    if name.contains("//") {
        return Err("tool name must not contain consecutive slashes '//'".to_string());
    }
    Ok(())
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

// ═══════════════════════════════════════════════════
// VERDICT EXPLANATION (Phase 24 — Art 50(2))
// ═══════════════════════════════════════════════════

/// Structured decision explanation for Art 50(2) transparency.
///
/// Transforms an `EvaluationTrace` into a consumer-facing explanation
/// at configurable verbosity levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictExplanation {
    /// Final verdict string ("Allow", "Deny", "RequireApproval").
    pub verdict: String,
    /// Human-readable reason (from Deny/RequireApproval).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Number of policies checked.
    pub policies_checked: usize,
    /// Number of policies that matched.
    pub policies_matched: usize,
    /// Evaluation duration in microseconds.
    pub duration_us: u64,
    /// Per-policy match details (only present at Full verbosity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_details: Option<Vec<PolicyMatchDetail>>,
}

/// Per-policy match detail within a verdict explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMatchDetail {
    /// Policy identifier.
    pub policy_id: String,
    /// Policy display name.
    pub policy_name: String,
    /// Policy priority.
    pub priority: i32,
    /// How this policy contributed to the final verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_contribution: Option<String>,
    /// Constraints that failed evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_constraints: Option<Vec<String>>,
}

impl VerdictExplanation {
    /// Build a summary explanation (verdict + reason + counts, no policy details).
    pub fn summary(trace: &EvaluationTrace) -> Self {
        let (verdict_str, reason) = Self::extract_verdict_info(&trace.verdict);
        Self {
            verdict: verdict_str,
            reason,
            policies_checked: trace.policies_checked,
            policies_matched: trace.policies_matched,
            duration_us: trace.duration_us,
            policy_details: None,
        }
    }

    /// Build a full explanation including per-policy match details.
    pub fn full(trace: &EvaluationTrace) -> Self {
        let (verdict_str, reason) = Self::extract_verdict_info(&trace.verdict);
        let details: Vec<PolicyMatchDetail> = trace
            .matches
            .iter()
            .map(|m| {
                let failed: Vec<String> = m
                    .constraint_results
                    .iter()
                    .filter(|c| !c.passed)
                    .map(|c| {
                        format!(
                            "{}: expected {} got {}",
                            c.constraint_type, c.expected, c.actual
                        )
                    })
                    .collect();
                let contribution = m.verdict_contribution.as_ref().map(|v| format!("{:?}", v));
                PolicyMatchDetail {
                    policy_id: m.policy_id.clone(),
                    policy_name: m.policy_name.clone(),
                    priority: m.priority,
                    verdict_contribution: contribution,
                    failed_constraints: if failed.is_empty() {
                        None
                    } else {
                        Some(failed)
                    },
                }
            })
            .collect();
        Self {
            verdict: verdict_str,
            reason,
            policies_checked: trace.policies_checked,
            policies_matched: trace.policies_matched,
            duration_us: trace.duration_us,
            policy_details: Some(details),
        }
    }

    #[allow(unreachable_patterns)] // Verdict is #[non_exhaustive]
    fn extract_verdict_info(verdict: &Verdict) -> (String, Option<String>) {
        match verdict {
            Verdict::Allow => ("Allow".to_string(), None),
            Verdict::Deny { reason } => ("Deny".to_string(), Some(reason.clone())),
            Verdict::RequireApproval { reason } => {
                ("RequireApproval".to_string(), Some(reason.clone()))
            }
            _ => ("Unknown".to_string(), None),
        }
    }
}
