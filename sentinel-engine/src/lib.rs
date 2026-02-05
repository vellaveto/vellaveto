use sentinel_types::{
    Action, ActionSummary, ConstraintResult, EvaluationContext, EvaluationTrace, Policy,
    PolicyMatch, PolicyType, Verdict,
};
use thiserror::Error;

use chrono::{Datelike, Timelike};
use globset::{Glob, GlobMatcher};
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Component, PathBuf};
use std::time::Instant;

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
    #[error("Path normalization failed (fail-closed): {reason}")]
    PathNormalization { reason: String },
}

// ═══════════════════════════════════════════════════
// PRE-COMPILED POLICY TYPES (C-9.2 / C-10.2)
// ═══════════════════════════════════════════════════

/// Error during policy compilation at load time.
#[derive(Debug, Clone)]
pub struct PolicyValidationError {
    pub policy_id: String,
    pub policy_name: String,
    pub reason: String,
}

impl std::fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Policy '{}' ({}): {}",
            self.policy_name, self.policy_id, self.reason
        )
    }
}

/// Pre-compiled pattern matcher for tool/function ID segments.
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Matches anything ("*")
    Any,
    /// Exact string match
    Exact(String),
    /// Prefix match ("prefix*")
    Prefix(String),
    /// Suffix match ("*suffix")
    Suffix(String),
}

impl PatternMatcher {
    fn compile(pattern: &str) -> Self {
        if pattern == "*" {
            PatternMatcher::Any
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            PatternMatcher::Suffix(suffix.to_string())
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            PatternMatcher::Prefix(prefix.to_string())
        } else {
            PatternMatcher::Exact(pattern.to_string())
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            PatternMatcher::Any => true,
            PatternMatcher::Exact(s) => s == value,
            PatternMatcher::Prefix(p) => value.starts_with(p.as_str()),
            PatternMatcher::Suffix(s) => value.ends_with(s.as_str()),
        }
    }
}

/// Pre-compiled tool:function matcher derived from policy ID.
#[derive(Debug, Clone)]
pub enum CompiledToolMatcher {
    /// Matches all tools and functions ("*")
    Universal,
    /// Matches tool only (no colon in policy ID)
    ToolOnly(PatternMatcher),
    /// Matches tool:function with independent matchers
    ToolAndFunction(PatternMatcher, PatternMatcher),
}

impl CompiledToolMatcher {
    fn compile(id: &str) -> Self {
        if id == "*" {
            CompiledToolMatcher::Universal
        } else if let Some((tool_pat, func_remainder)) = id.split_once(':') {
            // Support qualifier suffixes: "tool:func:qualifier" → match on "tool:func" only
            let func_pat = func_remainder
                .split_once(':')
                .map_or(func_remainder, |(f, _)| f);
            CompiledToolMatcher::ToolAndFunction(
                PatternMatcher::compile(tool_pat),
                PatternMatcher::compile(func_pat),
            )
        } else {
            CompiledToolMatcher::ToolOnly(PatternMatcher::compile(id))
        }
    }

    fn matches(&self, action: &Action) -> bool {
        match self {
            CompiledToolMatcher::Universal => true,
            CompiledToolMatcher::ToolOnly(m) => m.matches(&action.tool),
            CompiledToolMatcher::ToolAndFunction(t, f) => {
                t.matches(&action.tool) && f.matches(&action.function)
            }
        }
    }
}

/// A single pre-compiled parameter constraint with all patterns resolved at load time.
#[derive(Debug, Clone)]
pub enum CompiledConstraint {
    Glob {
        param: String,
        matcher: GlobMatcher,
        pattern_str: String,
        on_match: String,
        on_missing: String,
    },
    NotGlob {
        param: String,
        matchers: Vec<(String, GlobMatcher)>,
        on_match: String,
        on_missing: String,
    },
    Regex {
        param: String,
        regex: Regex,
        pattern_str: String,
        on_match: String,
        on_missing: String,
    },
    DomainMatch {
        param: String,
        pattern: String,
        on_match: String,
        on_missing: String,
    },
    DomainNotIn {
        param: String,
        patterns: Vec<String>,
        on_match: String,
        on_missing: String,
    },
    Eq {
        param: String,
        value: serde_json::Value,
        on_match: String,
        on_missing: String,
    },
    Ne {
        param: String,
        value: serde_json::Value,
        on_match: String,
        on_missing: String,
    },
    OneOf {
        param: String,
        values: Vec<serde_json::Value>,
        on_match: String,
        on_missing: String,
    },
    NoneOf {
        param: String,
        values: Vec<serde_json::Value>,
        on_match: String,
        on_missing: String,
    },
}

impl CompiledConstraint {
    fn param(&self) -> &str {
        match self {
            Self::Glob { param, .. }
            | Self::NotGlob { param, .. }
            | Self::Regex { param, .. }
            | Self::DomainMatch { param, .. }
            | Self::DomainNotIn { param, .. }
            | Self::Eq { param, .. }
            | Self::Ne { param, .. }
            | Self::OneOf { param, .. }
            | Self::NoneOf { param, .. } => param,
        }
    }

    fn on_match(&self) -> &str {
        match self {
            Self::Glob { on_match, .. }
            | Self::NotGlob { on_match, .. }
            | Self::Regex { on_match, .. }
            | Self::DomainMatch { on_match, .. }
            | Self::DomainNotIn { on_match, .. }
            | Self::Eq { on_match, .. }
            | Self::Ne { on_match, .. }
            | Self::OneOf { on_match, .. }
            | Self::NoneOf { on_match, .. } => on_match,
        }
    }

    fn on_missing(&self) -> &str {
        match self {
            Self::Glob { on_missing, .. }
            | Self::NotGlob { on_missing, .. }
            | Self::Regex { on_missing, .. }
            | Self::DomainMatch { on_missing, .. }
            | Self::DomainNotIn { on_missing, .. }
            | Self::Eq { on_missing, .. }
            | Self::Ne { on_missing, .. }
            | Self::OneOf { on_missing, .. }
            | Self::NoneOf { on_missing, .. } => on_missing,
        }
    }
}

/// Pre-compiled path rule glob matchers for a single policy.
#[derive(Debug, Clone)]
pub struct CompiledPathRules {
    pub allowed: Vec<(String, GlobMatcher)>,
    pub blocked: Vec<(String, GlobMatcher)>,
}

/// Pre-compiled network rule domain patterns for a single policy.
#[derive(Debug, Clone)]
pub struct CompiledNetworkRules {
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
}

/// Pre-compiled IP access control rules for DNS rebinding protection.
///
/// CIDRs are parsed at policy compile time so evaluation is a fast
/// prefix-length comparison with no parsing overhead.
#[derive(Debug, Clone)]
pub struct CompiledIpRules {
    pub block_private: bool,
    pub blocked_cidrs: Vec<IpNet>,
    pub allowed_cidrs: Vec<IpNet>,
}

/// A pre-compiled context condition for session-level policy evaluation.
///
/// Context conditions are checked after tool match and path/network rules,
/// but before policy type dispatch. They require an [`EvaluationContext`]
/// to evaluate — when no context is provided, all context conditions are skipped.
#[derive(Debug, Clone)]
pub enum CompiledContextCondition {
    /// Allow tool calls only within a time window.
    TimeWindow {
        start_hour: u8,
        end_hour: u8,
        /// ISO weekday numbers (1=Mon, 7=Sun). Empty = all days.
        days: Vec<u8>,
        deny_reason: String,
    },
    /// Limit how many times a tool (or tool pattern) can be called per session.
    MaxCalls {
        tool_pattern: PatternMatcher,
        max: u64,
        deny_reason: String,
    },
    /// Restrict which agent identities can use this policy.
    AgentId {
        allowed: Vec<String>,
        blocked: Vec<String>,
        deny_reason: String,
    },
    /// Require that a specific tool was called earlier in the session.
    RequirePreviousAction {
        required_tool: String,
        deny_reason: String,
    },
    /// Deny if a specific tool was called earlier in the session.
    ///
    /// Inverse of `RequirePreviousAction` — detects forbidden sequences like
    /// read-then-exfiltrate (if `read_file` was called, deny `http_request`).
    ForbiddenPreviousAction {
        /// Tool name that, if present in session history, triggers denial.
        forbidden_tool: String,
        deny_reason: String,
    },
    /// Deny if a tool pattern appears more than `max` times in the last `window`
    /// entries of the session history.
    ///
    /// Provides sliding-window rate limiting without requiring wall-clock
    /// timestamps. A `window` of 0 means the entire session history.
    MaxCallsInWindow {
        tool_pattern: PatternMatcher,
        max: u64,
        /// Number of most-recent history entries to consider. 0 = all.
        window: usize,
        deny_reason: String,
    },
    /// OWASP ASI08: Limit the depth of multi-agent call chains.
    ///
    /// In multi-hop MCP scenarios, an agent can request another agent to perform
    /// actions on its behalf. This condition limits how deep such chains can go
    /// to prevent privilege escalation through agent chaining.
    MaxChainDepth {
        /// Maximum allowed chain depth. A value of 0 means no multi-hop is allowed
        /// (direct calls only). A value of 1 allows one upstream agent, etc.
        max_depth: usize,
        deny_reason: String,
    },
    /// OWASP ASI07: Match on cryptographically attested agent identity claims.
    ///
    /// Requires a valid `X-Agent-Identity` JWT header. Policies can match on:
    /// - `issuer`: Required JWT issuer (`iss` claim)
    /// - `subject`: Required JWT subject (`sub` claim)
    /// - `audience`: Required audience (`aud` claim must contain this value)
    /// - `claims.<key>`: Custom claim matching (e.g., `claims.role == "admin"`)
    ///
    /// Unlike `AgentId` which matches on a simple string, this condition provides
    /// cryptographic attestation of the agent's identity via JWT signature verification.
    AgentIdentityMatch {
        /// Required JWT issuer. If set, the identity's `iss` claim must match.
        required_issuer: Option<String>,
        /// Required JWT subject. If set, the identity's `sub` claim must match.
        required_subject: Option<String>,
        /// Required audience. If set, the identity's `aud` claim must contain this value.
        required_audience: Option<String>,
        /// Required custom claims. All specified claims must match.
        /// Keys are claim names, values are expected string values.
        required_claims: std::collections::HashMap<String, String>,
        /// Blocked issuers. If the identity's `iss` matches any, deny.
        blocked_issuers: Vec<String>,
        /// Blocked subjects. If the identity's `sub` matches any, deny.
        blocked_subjects: Vec<String>,
        /// When true, fail-closed if no agent_identity is present.
        /// When false, fall back to legacy agent_id matching.
        require_attestation: bool,
        deny_reason: String,
    },
}

/// A policy with all patterns pre-compiled for zero-lock evaluation.
///
/// Created by [`PolicyEngine::compile_policies`] or [`PolicyEngine::with_policies`].
/// Stores the original [`Policy`] alongside pre-compiled matchers so that
/// `evaluate_action` requires zero Mutex acquisitions.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub policy: Policy,
    pub tool_matcher: CompiledToolMatcher,
    pub require_approval: bool,
    pub forbidden_parameters: Vec<String>,
    pub required_parameters: Vec<String>,
    pub constraints: Vec<CompiledConstraint>,
    /// When true, return None (skip to next policy) instead of Allow when no
    /// constraints fire. Set via `on_no_match: "continue"` in conditions JSON.
    pub on_no_match_continue: bool,
    /// Pre-computed "Denied by policy 'NAME'" reason string.
    pub deny_reason: String,
    /// Pre-computed "Approval required by policy 'NAME'" reason string.
    pub approval_reason: String,
    /// Pre-computed "Parameter 'P' is forbidden by policy 'NAME'" for each forbidden param.
    pub forbidden_reasons: Vec<String>,
    /// Pre-computed "Required parameter 'P' missing (policy 'NAME')" for each required param.
    pub required_reasons: Vec<String>,
    /// Pre-compiled path access control rules (from policy.path_rules).
    pub compiled_path_rules: Option<CompiledPathRules>,
    /// Pre-compiled network access control rules (from policy.network_rules).
    pub compiled_network_rules: Option<CompiledNetworkRules>,
    /// Pre-compiled IP access control rules (DNS rebinding protection).
    pub compiled_ip_rules: Option<CompiledIpRules>,
    /// Pre-compiled context conditions (from conditions JSON `context_conditions` key).
    pub context_conditions: Vec<CompiledContextCondition>,
}

/// Default maximum percent-decoding iterations in [`PolicyEngine::normalize_path`].
/// Paths requiring more iterations fail-closed to `"/"`.
pub const DEFAULT_MAX_PATH_DECODE_ITERATIONS: u32 = 20;

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
    compiled_policies: Vec<CompiledPolicy>,
    /// Maps exact tool names to sorted indices in `compiled_policies`.
    /// Only policies with an exact tool name pattern are indexed here.
    tool_index: HashMap<String, Vec<usize>>,
    /// Indices of policies that cannot be indexed by tool name
    /// (Universal, prefix, suffix, or Any tool patterns).
    /// Already sorted by position in `compiled_policies` (= priority order).
    always_check: Vec<usize>,
    /// When false (default), time-window context conditions always use wall-clock
    /// time. When true, the engine honors `EvaluationContext.timestamp` from the
    /// caller. **Only enable for deterministic testing** — in production, a client
    /// could supply a fake timestamp to bypass time-window policies.
    trust_context_timestamps: bool,
    /// Maximum percent-decoding iterations in `normalize_path` before
    /// fail-closing to `"/"`. Defaults to [`DEFAULT_MAX_PATH_DECODE_ITERATIONS`] (20).
    max_path_decode_iterations: u32,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("strict_mode", &self.strict_mode)
            .field("compiled_policies_count", &self.compiled_policies.len())
            .field("indexed_tools", &self.tool_index.len())
            .field("always_check_count", &self.always_check.len())
            .field(
                "max_path_decode_iterations",
                &self.max_path_decode_iterations,
            )
            .finish()
    }
}

impl PolicyEngine {
    /// Create a new policy engine.
    ///
    /// When `strict_mode` is true, the engine applies stricter validation
    /// on conditions and parameters.
    pub fn new(strict_mode: bool) -> Self {
        Self {
            strict_mode,
            compiled_policies: Vec::new(),
            tool_index: HashMap::new(),
            always_check: Vec::new(),
            trust_context_timestamps: false,
            max_path_decode_iterations: DEFAULT_MAX_PATH_DECODE_ITERATIONS,
        }
    }

    /// Validate a domain pattern used in network_rules.
    ///
    /// Rules per RFC 1035:
    /// - Labels (parts between dots) must be 1-63 characters each
    /// - Each label must be alphanumeric + hyphen only (no leading/trailing hyphen)
    /// - Total domain length max 253 characters
    /// - Wildcard `*.` prefix is allowed (only at the beginning)
    /// - Empty string is rejected
    pub fn validate_domain_pattern(pattern: &str) -> Result<(), String> {
        if pattern.is_empty() {
            return Err("Domain pattern cannot be empty".to_string());
        }

        // Strip wildcard prefix if present
        let domain = if let Some(rest) = pattern.strip_prefix("*.") {
            if rest.is_empty() {
                return Err("Domain pattern '*.' has no domain after wildcard".to_string());
            }
            rest
        } else if pattern.contains("*") {
            return Err(format!(
                "Wildcard '*' is only allowed as a prefix '*.domain', found in '{}'",
                pattern
            ));
        } else {
            pattern
        };

        // Check total length (max 253 for a fully qualified domain name)
        if domain.len() > 253 {
            return Err(format!(
                "Domain '{}' exceeds maximum length of 253 characters ({} chars)",
                &domain[..40],
                domain.len()
            ));
        }

        // Validate each label
        for label in domain.split('.') {
            if label.is_empty() {
                return Err(format!(
                    "Domain '{}' contains an empty label (consecutive dots or trailing dot)",
                    pattern
                ));
            }
            if label.len() > 63 {
                return Err(format!(
                    "Label '{}...' in domain '{}' exceeds maximum length of 63 characters",
                    &label[..20],
                    pattern
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(format!(
                    "Label '{}' in domain '{}' has leading or trailing hyphen",
                    label, pattern
                ));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(format!(
                    "Label '{}' in domain '{}' contains invalid characters (only alphanumeric and hyphen allowed)",
                    label, pattern
                ));
            }
        }

        Ok(())
    }

    /// Create a new policy engine with pre-compiled policies.
    ///
    /// All regex and glob patterns are compiled at construction time.
    /// Invalid patterns cause immediate rejection with descriptive errors.
    /// The compiled policies are sorted by priority (highest first, deny-overrides).
    pub fn with_policies(
        strict_mode: bool,
        policies: &[Policy],
    ) -> Result<Self, Vec<PolicyValidationError>> {
        let compiled = Self::compile_policies(policies, strict_mode)?;
        let (tool_index, always_check) = Self::build_tool_index(&compiled);
        Ok(Self {
            strict_mode,
            compiled_policies: compiled,
            tool_index,
            always_check,
            trust_context_timestamps: false,
            max_path_decode_iterations: DEFAULT_MAX_PATH_DECODE_ITERATIONS,
        })
    }

    /// Enable trusting `EvaluationContext.timestamp` for time-window checks.
    ///
    /// **WARNING:** Only use for deterministic testing. In production, a client
    /// can supply a fake timestamp to bypass time-window policies.
    #[cfg(test)]
    pub fn set_trust_context_timestamps(&mut self, trust: bool) {
        self.trust_context_timestamps = trust;
    }

    /// Set the maximum percent-decoding iterations for path normalization.
    ///
    /// Paths requiring more iterations fail-closed to `"/"`. The default is
    /// [`DEFAULT_MAX_PATH_DECODE_ITERATIONS`] (20). A value of 0 disables
    /// iterative decoding entirely (single pass only).
    pub fn set_max_path_decode_iterations(&mut self, max: u32) {
        self.max_path_decode_iterations = max;
    }

    /// Build a tool-name index for O(matching) evaluation.
    fn build_tool_index(compiled: &[CompiledPolicy]) -> (HashMap<String, Vec<usize>>, Vec<usize>) {
        let mut index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut always_check = Vec::new();
        for (i, cp) in compiled.iter().enumerate() {
            match &cp.tool_matcher {
                CompiledToolMatcher::Universal => always_check.push(i),
                CompiledToolMatcher::ToolOnly(PatternMatcher::Exact(name)) => {
                    index.entry(name.clone()).or_default().push(i);
                }
                CompiledToolMatcher::ToolAndFunction(PatternMatcher::Exact(name), _) => {
                    index.entry(name.clone()).or_default().push(i);
                }
                _ => always_check.push(i),
            }
        }
        (index, always_check)
    }

    /// Compile a set of policies, validating all patterns at load time.
    ///
    /// Returns pre-sorted `Vec<CompiledPolicy>` on success, or a list of
    /// all validation errors found across all policies on failure.
    pub fn compile_policies(
        policies: &[Policy],
        strict_mode: bool,
    ) -> Result<Vec<CompiledPolicy>, Vec<PolicyValidationError>> {
        let mut compiled = Vec::with_capacity(policies.len());
        let mut errors = Vec::new();

        for policy in policies {
            match Self::compile_single_policy(policy, strict_mode) {
                Ok(cp) => compiled.push(cp),
                Err(e) => errors.push(e),
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        // Sort compiled policies by priority (same order as sort_policies)
        compiled.sort_by(|a, b| {
            let pri = b.policy.priority.cmp(&a.policy.priority);
            if pri != std::cmp::Ordering::Equal {
                return pri;
            }
            let a_deny = matches!(a.policy.policy_type, PolicyType::Deny);
            let b_deny = matches!(b.policy.policy_type, PolicyType::Deny);
            let deny_ord = b_deny.cmp(&a_deny);
            if deny_ord != std::cmp::Ordering::Equal {
                return deny_ord;
            }
            a.policy.id.cmp(&b.policy.id)
        });
        Ok(compiled)
    }

    /// Compile a single policy, resolving all patterns.
    fn compile_single_policy(
        policy: &Policy,
        strict_mode: bool,
    ) -> Result<CompiledPolicy, PolicyValidationError> {
        let tool_matcher = CompiledToolMatcher::compile(&policy.id);

        let (
            require_approval,
            forbidden_parameters,
            required_parameters,
            constraints,
            on_no_match_continue,
            context_conditions,
        ) = match &policy.policy_type {
            PolicyType::Allow | PolicyType::Deny => {
                (false, Vec::new(), Vec::new(), Vec::new(), false, Vec::new())
            }
            PolicyType::Conditional { conditions } => {
                Self::compile_conditions(policy, conditions, strict_mode)?
            }
        };

        let deny_reason = format!("Denied by policy '{}'", policy.name);
        let approval_reason = format!("Approval required by policy '{}'", policy.name);
        let forbidden_reasons = forbidden_parameters
            .iter()
            .map(|p| format!("Parameter '{}' is forbidden by policy '{}'", p, policy.name))
            .collect();
        let required_reasons = required_parameters
            .iter()
            .map(|p| {
                format!(
                    "Required parameter '{}' missing (policy '{}')",
                    p, policy.name
                )
            })
            .collect();

        // Compile path rules — SECURITY: invalid globs cause a compile error
        // (fail-closed). Previously, filter_map silently dropped invalid patterns,
        // meaning a typo in a blocked path glob would silently fail to block.
        let compiled_path_rules = match policy.path_rules.as_ref() {
            Some(pr) => {
                let mut allowed = Vec::with_capacity(pr.allowed.len());
                for pattern in &pr.allowed {
                    let g = Glob::new(pattern).map_err(|e| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!("Invalid allowed path glob '{}': {}", pattern, e),
                    })?;
                    allowed.push((pattern.clone(), g.compile_matcher()));
                }
                let mut blocked = Vec::with_capacity(pr.blocked.len());
                for pattern in &pr.blocked {
                    let g = Glob::new(pattern).map_err(|e| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!("Invalid blocked path glob '{}': {}", pattern, e),
                    })?;
                    blocked.push((pattern.clone(), g.compile_matcher()));
                }
                Some(CompiledPathRules { allowed, blocked })
            }
            None => None,
        };

        // Compile network rules (domain patterns are matched directly, no glob needed)
        // Validate domain patterns at compile time per RFC 1035.
        let compiled_network_rules = match policy.network_rules.as_ref() {
            Some(nr) => {
                for domain in nr.allowed_domains.iter().chain(nr.blocked_domains.iter()) {
                    if let Err(reason) = Self::validate_domain_pattern(domain) {
                        return Err(PolicyValidationError {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            reason: format!("Invalid domain pattern: {}", reason),
                        });
                    }
                }
                Some(CompiledNetworkRules {
                    allowed_domains: nr.allowed_domains.clone(),
                    blocked_domains: nr.blocked_domains.clone(),
                })
            }
            None => None,
        };

        // Compile IP rules — parse CIDRs at compile time (fail-closed on invalid CIDR).
        let compiled_ip_rules = match policy
            .network_rules
            .as_ref()
            .and_then(|nr| nr.ip_rules.as_ref())
        {
            Some(ir) => {
                let mut blocked_cidrs = Vec::with_capacity(ir.blocked_cidrs.len());
                for cidr_str in &ir.blocked_cidrs {
                    let cidr: IpNet = cidr_str.parse().map_err(|e| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!("Invalid blocked CIDR '{}': {}", cidr_str, e),
                    })?;
                    blocked_cidrs.push(cidr);
                }
                let mut allowed_cidrs = Vec::with_capacity(ir.allowed_cidrs.len());
                for cidr_str in &ir.allowed_cidrs {
                    let cidr: IpNet = cidr_str.parse().map_err(|e| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!("Invalid allowed CIDR '{}': {}", cidr_str, e),
                    })?;
                    allowed_cidrs.push(cidr);
                }
                Some(CompiledIpRules {
                    block_private: ir.block_private,
                    blocked_cidrs,
                    allowed_cidrs,
                })
            }
            None => None,
        };

        Ok(CompiledPolicy {
            policy: policy.clone(),
            tool_matcher,
            require_approval,
            forbidden_parameters,
            required_parameters,
            constraints,
            on_no_match_continue,
            deny_reason,
            approval_reason,
            forbidden_reasons,
            required_reasons,
            compiled_path_rules,
            compiled_network_rules,
            compiled_ip_rules,
            context_conditions,
        })
    }

    /// Compile condition JSON into pre-parsed fields and compiled constraints.
    ///
    /// Returns: (require_approval, forbidden_parameters, required_parameters, constraints, on_no_match_continue, context_conditions)
    #[allow(clippy::type_complexity)]
    fn compile_conditions(
        policy: &Policy,
        conditions: &serde_json::Value,
        strict_mode: bool,
    ) -> Result<
        (
            bool,
            Vec<String>,
            Vec<String>,
            Vec<CompiledConstraint>,
            bool,
            Vec<CompiledContextCondition>,
        ),
        PolicyValidationError,
    > {
        // Validate JSON depth
        if Self::json_depth(conditions) > 10 {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "Condition JSON exceeds maximum nesting depth of 10".to_string(),
            });
        }

        // Validate JSON size
        let size = conditions.to_string().len();
        if size > 100_000 {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!("Condition JSON too large: {} bytes (max 100000)", size),
            });
        }

        let require_approval = conditions
            .get("require_approval")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let on_no_match_continue = conditions
            .get("on_no_match")
            .and_then(|v| v.as_str())
            .map(|s| s == "continue")
            .unwrap_or(false);

        let forbidden_parameters = conditions
            .get("forbidden_parameters")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let required_parameters = conditions
            .get("required_parameters")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let mut constraints = Vec::new();
        if let Some(constraint_arr) = conditions.get("parameter_constraints") {
            let arr = constraint_arr
                .as_array()
                .ok_or_else(|| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: "parameter_constraints must be an array".to_string(),
                })?;

            for constraint_val in arr {
                constraints.push(Self::compile_constraint(policy, constraint_val)?);
            }
        }

        // Parse context conditions (session-level checks)
        let mut context_conditions = Vec::new();
        if let Some(ctx_arr) = conditions.get("context_conditions") {
            let arr = ctx_arr.as_array().ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "context_conditions must be an array".to_string(),
            })?;

            for ctx_val in arr {
                context_conditions.push(Self::compile_context_condition(policy, ctx_val)?);
            }
        }

        // Validate strict mode unknown keys
        if strict_mode {
            let known_keys = [
                "require_approval",
                "forbidden_parameters",
                "required_parameters",
                "parameter_constraints",
                "context_conditions",
                "on_no_match",
            ];
            if let Some(obj) = conditions.as_object() {
                for key in obj.keys() {
                    if !known_keys.contains(&key.as_str()) {
                        return Err(PolicyValidationError {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            reason: format!("Unknown condition key '{}' in strict mode", key),
                        });
                    }
                }
            }
        }

        Ok((
            require_approval,
            forbidden_parameters,
            required_parameters,
            constraints,
            on_no_match_continue,
            context_conditions,
        ))
    }

    /// Compile a single constraint JSON object into a `CompiledConstraint`.
    fn compile_constraint(
        policy: &Policy,
        constraint: &serde_json::Value,
    ) -> Result<CompiledConstraint, PolicyValidationError> {
        let obj = constraint
            .as_object()
            .ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "Each parameter constraint must be a JSON object".to_string(),
            })?;

        let param = obj
            .get("param")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "Constraint missing required 'param' string field".to_string(),
            })?
            .to_string();

        let op = obj
            .get("op")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "Constraint missing required 'op' string field".to_string(),
            })?;

        let on_match = obj
            .get("on_match")
            .and_then(|v| v.as_str())
            .unwrap_or("deny")
            .to_string();
        // SECURITY (R8-11): Validate on_match at compile time — a typo like
        // "alow" would silently become a runtime error instead of a clear deny.
        match on_match.as_str() {
            "deny" | "allow" | "require_approval" => {}
            other => {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "Constraint 'on_match' value '{}' is invalid; expected 'deny', 'allow', or 'require_approval'",
                        other
                    ),
                });
            }
        }
        let on_missing = obj
            .get("on_missing")
            .and_then(|v| v.as_str())
            .unwrap_or("deny")
            .to_string();
        match on_missing.as_str() {
            "deny" | "skip" => {}
            other => {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "Constraint 'on_missing' value '{}' is invalid; expected 'deny' or 'skip'",
                        other
                    ),
                });
            }
        }

        match op {
            "glob" => {
                let pattern_str = obj
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "glob constraint missing 'pattern' string".to_string(),
                    })?
                    .to_string();

                let matcher = Glob::new(&pattern_str)
                    .map_err(|e| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!("Invalid glob pattern '{}': {}", pattern_str, e),
                    })?
                    .compile_matcher();

                Ok(CompiledConstraint::Glob {
                    param,
                    matcher,
                    pattern_str,
                    on_match,
                    on_missing,
                })
            }
            "not_glob" => {
                let patterns = obj
                    .get("patterns")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "not_glob constraint missing 'patterns' array".to_string(),
                    })?;

                let mut matchers = Vec::new();
                for pat_val in patterns {
                    let pat_str = pat_val.as_str().ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "not_glob patterns must be strings".to_string(),
                    })?;
                    let matcher = Glob::new(pat_str)
                        .map_err(|e| PolicyValidationError {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            reason: format!("Invalid glob pattern '{}': {}", pat_str, e),
                        })?
                        .compile_matcher();
                    matchers.push((pat_str.to_string(), matcher));
                }

                Ok(CompiledConstraint::NotGlob {
                    param,
                    matchers,
                    on_match,
                    on_missing,
                })
            }
            "regex" => {
                let pattern_str = obj
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "regex constraint missing 'pattern' string".to_string(),
                    })?
                    .to_string();

                // H2: ReDoS safety check at policy load time (early rejection)
                Self::validate_regex_safety(&pattern_str).map_err(|reason| {
                    PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason,
                    }
                })?;

                let regex = Regex::new(&pattern_str).map_err(|e| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!("Invalid regex pattern '{}': {}", pattern_str, e),
                })?;

                Ok(CompiledConstraint::Regex {
                    param,
                    regex,
                    pattern_str,
                    on_match,
                    on_missing,
                })
            }
            "domain_match" => {
                let pattern = obj
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "domain_match constraint missing 'pattern' string".to_string(),
                    })?
                    .to_string();

                Ok(CompiledConstraint::DomainMatch {
                    param,
                    pattern,
                    on_match,
                    on_missing,
                })
            }
            "domain_not_in" => {
                let patterns_arr =
                    obj.get("patterns")
                        .and_then(|v| v.as_array())
                        .ok_or_else(|| PolicyValidationError {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            reason: "domain_not_in constraint missing 'patterns' array".to_string(),
                        })?;

                let mut patterns = Vec::new();
                for pat_val in patterns_arr {
                    let pat_str = pat_val.as_str().ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "domain_not_in patterns must be strings".to_string(),
                    })?;
                    patterns.push(pat_str.to_string());
                }

                Ok(CompiledConstraint::DomainNotIn {
                    param,
                    patterns,
                    on_match,
                    on_missing,
                })
            }
            "eq" => {
                let value = obj
                    .get("value")
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "eq constraint missing 'value' field".to_string(),
                    })?
                    .clone();

                Ok(CompiledConstraint::Eq {
                    param,
                    value,
                    on_match,
                    on_missing,
                })
            }
            "ne" => {
                let value = obj
                    .get("value")
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "ne constraint missing 'value' field".to_string(),
                    })?
                    .clone();

                Ok(CompiledConstraint::Ne {
                    param,
                    value,
                    on_match,
                    on_missing,
                })
            }
            "one_of" => {
                let values = obj
                    .get("values")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "one_of constraint missing 'values' array".to_string(),
                    })?
                    .clone();

                Ok(CompiledConstraint::OneOf {
                    param,
                    values,
                    on_match,
                    on_missing,
                })
            }
            "none_of" => {
                let values = obj
                    .get("values")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "none_of constraint missing 'values' array".to_string(),
                    })?
                    .clone();

                Ok(CompiledConstraint::NoneOf {
                    param,
                    values,
                    on_match,
                    on_missing,
                })
            }
            _ => Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!("Unknown constraint operator '{}'", op),
            }),
        }
    }

    /// Compile a single context condition JSON object into a [`CompiledContextCondition`].
    fn compile_context_condition(
        policy: &Policy,
        value: &serde_json::Value,
    ) -> Result<CompiledContextCondition, PolicyValidationError> {
        let obj = value.as_object().ok_or_else(|| PolicyValidationError {
            policy_id: policy.id.clone(),
            policy_name: policy.name.clone(),
            reason: "Each context condition must be a JSON object".to_string(),
        })?;

        let kind =
            obj.get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: "Context condition missing required 'type' string field".to_string(),
                })?;

        match kind {
            "time_window" => {
                // SECURITY (R19-TRUNC): Validate u64 range BEFORE casting to u8.
                // Without this, `start_hour: 265` truncates to `265 % 256 = 9` as u8,
                // silently passing the `> 23` check. An attacker could craft a policy
                // that appears to restrict hours but actually maps to a different hour.
                let start_hour_u64 =
                    obj.get("start_hour")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| PolicyValidationError {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            reason: "time_window missing 'start_hour' integer".to_string(),
                        })?;
                let end_hour_u64 =
                    obj.get("end_hour")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| PolicyValidationError {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            reason: "time_window missing 'end_hour' integer".to_string(),
                        })?;
                if start_hour_u64 > 23 || end_hour_u64 > 23 {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "time_window hours must be 0-23, got start={} end={}",
                            start_hour_u64, end_hour_u64
                        ),
                    });
                }
                let start_hour = start_hour_u64 as u8;
                let end_hour = end_hour_u64 as u8;
                // SECURITY (R19-TRUNC): Validate day values as u64 BEFORE casting to u8.
                // Same truncation issue as hours: `day: 258` → `258 % 256 = 2` as u8.
                let days_u64: Vec<u64> = obj
                    .get("days")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect())
                    .unwrap_or_default();
                for &day in &days_u64 {
                    if !(1..=7).contains(&day) {
                        return Err(PolicyValidationError {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            reason: format!(
                                "time_window day value must be 1-7 (Mon-Sun), got {}",
                                day
                            ),
                        });
                    }
                }
                let days: Vec<u8> = days_u64.iter().map(|&d| d as u8).collect();
                // SECURITY (R19-WINDOW-EQ): Reject start_hour == end_hour as a
                // configuration error. The window check `hour >= X && hour < X` is
                // always false, creating a permanent deny that looks like a time
                // restriction but blocks all hours silently.
                if start_hour == end_hour {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "time_window start_hour and end_hour must differ (both are {}); \
                             a zero-width window permanently denies all requests",
                            start_hour
                        ),
                    });
                }
                let deny_reason = format!(
                    "Outside allowed time window ({:02}:00-{:02}:00) for policy '{}'",
                    start_hour, end_hour, policy.name
                );
                Ok(CompiledContextCondition::TimeWindow {
                    start_hour,
                    end_hour,
                    days,
                    deny_reason,
                })
            }
            "max_calls" => {
                let tool_pattern = obj
                    .get("tool_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string();
                let max = obj.get("max").and_then(|v| v.as_u64()).ok_or_else(|| {
                    PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "max_calls missing 'max' integer".to_string(),
                    }
                })?;
                let deny_reason = format!(
                    "Tool call limit ({}) exceeded for pattern '{}' in policy '{}'",
                    max, tool_pattern, policy.name
                );
                Ok(CompiledContextCondition::MaxCalls {
                    tool_pattern: PatternMatcher::compile(&tool_pattern),
                    max,
                    deny_reason,
                })
            }
            "agent_id" => {
                // SECURITY: Normalize agent IDs to lowercase at compile time
                // to prevent case-variation bypasses (e.g., "Agent-A" vs "agent-a").
                let allowed = obj
                    .get("allowed")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();
                let blocked = obj
                    .get("blocked")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();
                let deny_reason =
                    format!("Agent identity not authorized by policy '{}'", policy.name);
                Ok(CompiledContextCondition::AgentId {
                    allowed,
                    blocked,
                    deny_reason,
                })
            }
            "require_previous_action" => {
                let required_tool = obj
                    .get("required_tool")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "require_previous_action missing 'required_tool' string"
                            .to_string(),
                    })?
                    .to_string();
                let deny_reason = format!(
                    "Required previous action '{}' not found in session history (policy '{}')",
                    required_tool, policy.name
                );
                Ok(CompiledContextCondition::RequirePreviousAction {
                    required_tool,
                    deny_reason,
                })
            }
            "forbidden_previous_action" => {
                let forbidden_tool = obj
                    .get("forbidden_tool")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "forbidden_previous_action missing 'forbidden_tool' string"
                            .to_string(),
                    })?
                    .to_string();
                let deny_reason = format!(
                    "Forbidden previous action '{}' detected in session history (policy '{}')",
                    forbidden_tool, policy.name
                );
                Ok(CompiledContextCondition::ForbiddenPreviousAction {
                    forbidden_tool,
                    deny_reason,
                })
            }
            "max_calls_in_window" => {
                let tool_pattern = obj
                    .get("tool_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string();
                let max = obj.get("max").and_then(|v| v.as_u64()).ok_or_else(|| {
                    PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "max_calls_in_window missing 'max' integer".to_string(),
                    }
                })?;
                let window = obj.get("window").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let deny_reason = format!(
                    "Tool '{}' called more than {} times in last {} actions (policy '{}')",
                    tool_pattern,
                    max,
                    if window == 0 {
                        "all".to_string()
                    } else {
                        window.to_string()
                    },
                    policy.name
                );
                Ok(CompiledContextCondition::MaxCallsInWindow {
                    tool_pattern: PatternMatcher::compile(&tool_pattern),
                    max,
                    window,
                    deny_reason,
                })
            }
            "max_chain_depth" => {
                // OWASP ASI08: Multi-agent communication monitoring
                let max_depth = obj
                    .get("max_depth")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "max_chain_depth missing 'max_depth' integer".to_string(),
                    })? as usize;
                let deny_reason = format!(
                    "Call chain depth exceeds maximum of {} (policy '{}')",
                    max_depth, policy.name
                );
                Ok(CompiledContextCondition::MaxChainDepth {
                    max_depth,
                    deny_reason,
                })
            }
            "agent_identity" => {
                // OWASP ASI07: Agent identity attestation via signed JWT
                let required_issuer = obj
                    .get("issuer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let required_subject = obj
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let required_audience = obj
                    .get("audience")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Parse required_claims as a map of string -> string
                let required_claims = obj
                    .get("claims")
                    .and_then(|v| v.as_object())
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect::<std::collections::HashMap<String, String>>()
                    })
                    .unwrap_or_default();

                // SECURITY: Normalize blocked lists to lowercase for case-insensitive matching
                let blocked_issuers = obj
                    .get("blocked_issuers")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();

                let blocked_subjects = obj
                    .get("blocked_subjects")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();

                // When true, fail if no agent_identity is present (require JWT attestation)
                let require_attestation = obj
                    .get("require_attestation")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true); // Default to true for security

                let deny_reason = format!(
                    "Agent identity attestation failed for policy '{}'",
                    policy.name
                );

                Ok(CompiledContextCondition::AgentIdentityMatch {
                    required_issuer,
                    required_subject,
                    required_audience,
                    required_claims,
                    blocked_issuers,
                    blocked_subjects,
                    require_attestation,
                    deny_reason,
                })
            }
            _ => Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!("Unknown context condition type '{}'", kind),
            }),
        }
    }

    /// Sort policies by priority (highest first), with deny-overrides at equal priority,
    /// and a stable tertiary tiebreaker by policy ID for deterministic ordering.
    ///
    /// Call this once when loading or modifying policies, then pass the sorted
    /// slice to [`Self::evaluate_action`] to avoid re-sorting on every evaluation.
    pub fn sort_policies(policies: &mut [Policy]) {
        policies.sort_by(|a, b| {
            let pri = b.priority.cmp(&a.priority);
            if pri != std::cmp::Ordering::Equal {
                return pri;
            }
            let a_deny = matches!(a.policy_type, PolicyType::Deny);
            let b_deny = matches!(b.policy_type, PolicyType::Deny);
            let deny_ord = b_deny.cmp(&a_deny);
            if deny_ord != std::cmp::Ordering::Equal {
                return deny_ord;
            }
            // Tertiary tiebreaker: lexicographic by ID for deterministic ordering
            a.id.cmp(&b.id)
        });
    }

    /// Evaluate an action against a set of policies.
    ///
    /// For best performance, pass policies that have been pre-sorted with
    /// [`Self::sort_policies`]. If not pre-sorted, this method will sort a temporary
    /// copy (which adds O(n log n) overhead per call).
    ///
    /// The first matching policy determines the verdict.
    /// If no policy matches, the default is Deny (fail-closed).
    pub fn evaluate_action(
        &self,
        action: &Action,
        policies: &[Policy],
    ) -> Result<Verdict, EngineError> {
        // Fast path: use pre-compiled policies (zero Mutex, zero runtime compilation)
        if !self.compiled_policies.is_empty() {
            return self.evaluate_with_compiled(action);
        }

        // Legacy path: evaluate ad-hoc policies (compiles patterns on the fly)
        if policies.is_empty() {
            return Ok(Verdict::Deny {
                reason: "No policies defined".to_string(),
            });
        }

        // Check if already sorted (by priority desc, deny-first at equal priority)
        let is_sorted = policies.windows(2).all(|w| {
            let pri = w[0].priority.cmp(&w[1].priority);
            if pri == std::cmp::Ordering::Equal {
                let a_deny = matches!(w[0].policy_type, PolicyType::Deny);
                let b_deny = matches!(w[1].policy_type, PolicyType::Deny);
                b_deny <= a_deny
            } else {
                pri != std::cmp::Ordering::Less
            }
        });

        if is_sorted {
            for policy in policies {
                if self.matches_action(action, policy) {
                    if let Some(verdict) = self.apply_policy(action, policy)? {
                        return Ok(verdict);
                    }
                    // None: on_no_match="continue", try next policy
                }
            }
        } else {
            let mut sorted: Vec<&Policy> = policies.iter().collect();
            sorted.sort_by(|a, b| {
                let pri = b.priority.cmp(&a.priority);
                if pri != std::cmp::Ordering::Equal {
                    return pri;
                }
                let a_deny = matches!(a.policy_type, PolicyType::Deny);
                let b_deny = matches!(b.policy_type, PolicyType::Deny);
                b_deny.cmp(&a_deny)
            });
            for policy in &sorted {
                if self.matches_action(action, policy) {
                    if let Some(verdict) = self.apply_policy(action, policy)? {
                        return Ok(verdict);
                    }
                    // None: on_no_match="continue", try next policy
                }
            }
        }

        Ok(Verdict::Deny {
            reason: "No matching policy".to_string(),
        })
    }

    /// Evaluate an action with optional session context.
    ///
    /// This is the context-aware counterpart to [`Self::evaluate_action`].
    /// When `context` is `Some`, context conditions (time windows, call limits,
    /// agent identity, action history) are evaluated. When `None`, behaves
    /// identically to `evaluate_action`.
    pub fn evaluate_action_with_context(
        &self,
        action: &Action,
        policies: &[Policy],
        context: Option<&EvaluationContext>,
    ) -> Result<Verdict, EngineError> {
        if context.is_none() {
            return self.evaluate_action(action, policies);
        }
        // Fast path: use pre-compiled policies
        if !self.compiled_policies.is_empty() {
            return self.evaluate_with_compiled_ctx(action, context);
        }
        // SECURITY (R13-LEG-7): Fail-closed when context is provided but
        // compiled policies are unavailable. The legacy path cannot evaluate
        // context conditions (time windows, call limits, agent identity,
        // forbidden sequences). Silently dropping context would bypass all
        // context-based restrictions.
        if let Some(ctx) = context {
            if ctx.has_any_meaningful_fields() {
                return Ok(Verdict::Deny {
                    reason: "Policy engine has no compiled policies; \
                             context conditions cannot be evaluated (fail-closed)"
                        .to_string(),
                });
            }
        }
        // Context was provided but empty — safe to fall through to legacy
        self.evaluate_action(action, policies)
    }

    /// Evaluate an action with full decision trace and optional session context.
    pub fn evaluate_action_traced_with_context(
        &self,
        action: &Action,
        context: Option<&EvaluationContext>,
    ) -> Result<(Verdict, EvaluationTrace), EngineError> {
        if context.is_none() {
            return self.evaluate_action_traced(action);
        }
        // Traced context-aware path
        self.evaluate_action_traced_ctx(action, context)
    }

    // ═══════════════════════════════════════════════════
    // COMPILED EVALUATION PATH (zero Mutex, zero runtime compilation)
    // ═══════════════════════════════════════════════════

    /// Evaluate an action using pre-compiled policies. Zero Mutex acquisitions.
    /// Compiled policies are already sorted at compile time.
    ///
    /// Uses the tool-name index when available: only checks policies whose tool
    /// pattern could match `action.tool`, plus `always_check` (wildcard/prefix/suffix).
    /// Falls back to linear scan when no index has been built.
    fn evaluate_with_compiled(&self, action: &Action) -> Result<Verdict, EngineError> {
        // If index was built, use it for O(matching) instead of O(all)
        if !self.tool_index.is_empty() || !self.always_check.is_empty() {
            let tool_specific = self.tool_index.get(&action.tool);
            let tool_slice = tool_specific.map(|v| v.as_slice()).unwrap_or(&[]);
            let always_slice = &self.always_check;

            // Merge two sorted index slices, iterating in priority order.
            // SECURITY (R26-ENG-1): When both slices reference the same policy index,
            // increment BOTH pointers to avoid evaluating the policy twice.
            let mut ti = 0;
            let mut ai = 0;
            loop {
                let next_idx = match (tool_slice.get(ti), always_slice.get(ai)) {
                    (Some(&t), Some(&a)) => {
                        if t < a {
                            ti += 1;
                            t
                        } else if t > a {
                            ai += 1;
                            a
                        } else {
                            // t == a: same policy in both slices, skip duplicate
                            ti += 1;
                            ai += 1;
                            t
                        }
                    }
                    (Some(&t), None) => {
                        ti += 1;
                        t
                    }
                    (None, Some(&a)) => {
                        ai += 1;
                        a
                    }
                    (None, None) => break,
                };

                let cp = &self.compiled_policies[next_idx];
                if cp.tool_matcher.matches(action) {
                    if let Some(verdict) = self.apply_compiled_policy(action, cp)? {
                        return Ok(verdict);
                    }
                    // None: on_no_match="continue", try next policy
                }
            }
        } else {
            // No index: linear scan (legacy compiled path)
            for cp in &self.compiled_policies {
                if cp.tool_matcher.matches(action) {
                    if let Some(verdict) = self.apply_compiled_policy(action, cp)? {
                        return Ok(verdict);
                    }
                    // None: on_no_match="continue", try next policy
                }
            }
        }

        Ok(Verdict::Deny {
            reason: "No matching policy".to_string(),
        })
    }

    /// Evaluate with compiled policies and session context.
    fn evaluate_with_compiled_ctx(
        &self,
        action: &Action,
        context: Option<&EvaluationContext>,
    ) -> Result<Verdict, EngineError> {
        if !self.tool_index.is_empty() || !self.always_check.is_empty() {
            let tool_specific = self.tool_index.get(&action.tool);
            let tool_slice = tool_specific.map(|v| v.as_slice()).unwrap_or(&[]);
            let always_slice = &self.always_check;

            // SECURITY (R26-ENG-1): Deduplicate merge — see evaluate_compiled().
            let mut ti = 0;
            let mut ai = 0;
            loop {
                let next_idx = match (tool_slice.get(ti), always_slice.get(ai)) {
                    (Some(&t), Some(&a)) => {
                        if t < a {
                            ti += 1;
                            t
                        } else if t > a {
                            ai += 1;
                            a
                        } else {
                            ti += 1;
                            ai += 1;
                            t
                        }
                    }
                    (Some(&t), None) => {
                        ti += 1;
                        t
                    }
                    (None, Some(&a)) => {
                        ai += 1;
                        a
                    }
                    (None, None) => break,
                };

                let cp = &self.compiled_policies[next_idx];
                if cp.tool_matcher.matches(action) {
                    if let Some(verdict) = self.apply_compiled_policy_ctx(action, cp, context)? {
                        return Ok(verdict);
                    }
                }
            }
        } else {
            for cp in &self.compiled_policies {
                if cp.tool_matcher.matches(action) {
                    if let Some(verdict) = self.apply_compiled_policy_ctx(action, cp, context)? {
                        return Ok(verdict);
                    }
                }
            }
        }

        Ok(Verdict::Deny {
            reason: "No matching policy".to_string(),
        })
    }

    /// Apply a matched compiled policy to produce a verdict (no context).
    /// Returns `None` when a Conditional policy with `on_no_match: "continue"` has no
    /// constraints fire, signaling the evaluation loop to try the next policy.
    fn apply_compiled_policy(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<Option<Verdict>, EngineError> {
        self.apply_compiled_policy_ctx(action, cp, None)
    }

    /// Apply a matched compiled policy with optional context.
    fn apply_compiled_policy_ctx(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
        context: Option<&EvaluationContext>,
    ) -> Result<Option<Verdict>, EngineError> {
        // Check path rules before policy type dispatch.
        // Blocked paths → deny immediately regardless of policy type.
        if let Some(denial) = self.check_path_rules(action, cp) {
            return Ok(Some(denial));
        }
        // Check network rules before policy type dispatch.
        if let Some(denial) = self.check_network_rules(action, cp) {
            return Ok(Some(denial));
        }
        // Check IP rules (DNS rebinding protection) after network rules.
        if let Some(denial) = self.check_ip_rules(action, cp) {
            return Ok(Some(denial));
        }
        // Check context conditions (session-level) before policy type dispatch.
        // SECURITY: If a policy declares context conditions but no context is
        // provided, deny the action (fail-closed). Skipping would let callers
        // bypass time-window / max-calls / agent-id restrictions by omitting context.
        if !cp.context_conditions.is_empty() {
            match context {
                Some(ctx) => {
                    if let Some(denial) = self.check_context_conditions(ctx, cp) {
                        return Ok(Some(denial));
                    }
                }
                None => {
                    return Ok(Some(Verdict::Deny {
                        reason: format!(
                            "Policy '{}' requires evaluation context (has {} context condition(s)) but none was provided",
                            cp.policy.name,
                            cp.context_conditions.len()
                        ),
                    }));
                }
            }
        }

        match &cp.policy.policy_type {
            PolicyType::Allow => Ok(Some(Verdict::Allow)),
            PolicyType::Deny => Ok(Some(Verdict::Deny {
                reason: cp.deny_reason.clone(),
            })),
            PolicyType::Conditional { .. } => self.evaluate_compiled_conditions(action, cp),
        }
    }

    /// Evaluate context conditions against session state.
    ///
    /// Returns `Some(Deny)` if any context condition fails, `None` if all pass.
    fn check_context_conditions(
        &self,
        context: &EvaluationContext,
        cp: &CompiledPolicy,
    ) -> Option<Verdict> {
        for cond in &cp.context_conditions {
            match cond {
                CompiledContextCondition::TimeWindow {
                    start_hour,
                    end_hour,
                    days,
                    deny_reason,
                } => {
                    // SECURITY: Use wall-clock time unless trust_context_timestamps
                    // is explicitly enabled (test-only). context.timestamp is untrusted
                    // in production — an attacker could supply a fake timestamp to bypass
                    // time-window restrictions.
                    let now = if self.trust_context_timestamps {
                        context
                            .timestamp
                            .as_ref()
                            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .unwrap_or_else(chrono::Utc::now)
                    } else {
                        chrono::Utc::now()
                    };

                    let hour = now.hour() as u8;

                    // Check day of week (1=Mon, 7=Sun)
                    if !days.is_empty() {
                        let weekday = now.weekday().num_days_from_monday() as u8 + 1;
                        if !days.contains(&weekday) {
                            return Some(Verdict::Deny {
                                reason: deny_reason.clone(),
                            });
                        }
                    }

                    // Check hour window (supports midnight wrap)
                    let in_window = if start_hour <= end_hour {
                        // Normal: 9-17 means 9 <= hour < 17
                        hour >= *start_hour && hour < *end_hour
                    } else {
                        // Midnight wrap: 22-6 means hour >= 22 || hour < 6
                        hour >= *start_hour || hour < *end_hour
                    };

                    if !in_window {
                        return Some(Verdict::Deny {
                            reason: deny_reason.clone(),
                        });
                    }
                }
                CompiledContextCondition::MaxCalls {
                    tool_pattern,
                    max,
                    deny_reason,
                } => {
                    // SECURITY (R15-ENG-1): Fail-closed when call_counts is empty.
                    // If a policy declares MaxCalls but the caller provides no
                    // call_counts (e.g., stateless API), we deny rather than
                    // silently allowing unlimited calls. An empty map means the
                    // caller cannot track session state, so the rate limit cannot
                    // be enforced — deny to be safe.
                    if context.call_counts.is_empty() {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{} (no session call counts available — fail-closed)",
                                deny_reason
                            ),
                        });
                    }

                    // SECURITY (R8-6): Use saturating_add to prevent u64 overflow
                    // which could wrap to 0, bypassing rate limits.
                    let count = if matches!(tool_pattern, PatternMatcher::Any) {
                        context
                            .call_counts
                            .values()
                            .fold(0u64, |acc, v| acc.saturating_add(*v))
                    } else {
                        context
                            .call_counts
                            .iter()
                            .filter(|(name, _)| tool_pattern.matches(name))
                            .map(|(_, count)| count)
                            .fold(0u64, |acc, v| acc.saturating_add(*v))
                    };

                    if count >= *max {
                        return Some(Verdict::Deny {
                            reason: deny_reason.clone(),
                        });
                    }
                }
                CompiledContextCondition::AgentId {
                    allowed,
                    blocked,
                    deny_reason,
                } => {
                    match &context.agent_id {
                        Some(id) => {
                            // SECURITY: Compare case-insensitively to prevent
                            // bypasses via "Agent-A" when policy specifies "agent-a".
                            let id_lower = id.to_lowercase();
                            // Check blocked list first
                            if blocked.contains(&id_lower) {
                                return Some(Verdict::Deny {
                                    reason: deny_reason.clone(),
                                });
                            }
                            // If allowed list is non-empty, agent must be in it
                            if !allowed.is_empty() && !allowed.contains(&id_lower) {
                                return Some(Verdict::Deny {
                                    reason: deny_reason.clone(),
                                });
                            }
                        }
                        None => {
                            // Fail-closed: no agent_id + non-empty allowed/blocked lists = deny
                            if !allowed.is_empty() || !blocked.is_empty() {
                                return Some(Verdict::Deny {
                                    reason: deny_reason.clone(),
                                });
                            }
                        }
                    }
                }
                CompiledContextCondition::RequirePreviousAction {
                    required_tool,
                    deny_reason,
                } => {
                    if !context.previous_actions.iter().any(|a| a == required_tool) {
                        return Some(Verdict::Deny {
                            reason: deny_reason.clone(),
                        });
                    }
                }
                CompiledContextCondition::ForbiddenPreviousAction {
                    forbidden_tool,
                    deny_reason,
                } => {
                    if context.previous_actions.iter().any(|a| a == forbidden_tool) {
                        return Some(Verdict::Deny {
                            reason: deny_reason.clone(),
                        });
                    }
                }
                CompiledContextCondition::MaxCallsInWindow {
                    tool_pattern,
                    max,
                    window,
                    deny_reason,
                } => {
                    // SECURITY (R21-ENG-1): Fail-closed when previous_actions
                    // is empty. MaxCallsInWindow counts over previous_actions
                    // only — call_counts is irrelevant here. Without history,
                    // windowed rate limits cannot be enforced — deny to be safe.
                    if context.previous_actions.is_empty() {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{} (no session history available — fail-closed)",
                                deny_reason
                            ),
                        });
                    }

                    let history = if *window > 0 {
                        let start = context.previous_actions.len().saturating_sub(*window);
                        &context.previous_actions[start..]
                    } else {
                        &context.previous_actions[..]
                    };
                    // SECURITY (R26-ENG-3): Fail-closed on count overflow.
                    let count_usize = history.iter().filter(|a| tool_pattern.matches(a)).count();
                    let count = u64::try_from(count_usize).unwrap_or(u64::MAX);
                    if count >= *max {
                        return Some(Verdict::Deny {
                            reason: deny_reason.clone(),
                        });
                    }
                }
                CompiledContextCondition::MaxChainDepth {
                    max_depth,
                    deny_reason,
                } => {
                    // OWASP ASI08: Check call chain depth for multi-agent scenarios
                    if context.call_chain.len() > *max_depth {
                        return Some(Verdict::Deny {
                            reason: deny_reason.clone(),
                        });
                    }
                }
                CompiledContextCondition::AgentIdentityMatch {
                    required_issuer,
                    required_subject,
                    required_audience,
                    required_claims,
                    blocked_issuers,
                    blocked_subjects,
                    require_attestation,
                    deny_reason,
                } => {
                    // OWASP ASI07: Agent identity attestation via signed JWT
                    match &context.agent_identity {
                        Some(identity) => {
                            // Check blocked issuers first (case-insensitive)
                            if let Some(ref iss) = identity.issuer {
                                if blocked_issuers.contains(&iss.to_lowercase()) {
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{} (blocked issuer: {})",
                                            deny_reason, iss
                                        ),
                                    });
                                }
                            }

                            // Check blocked subjects (case-insensitive)
                            if let Some(ref sub) = identity.subject {
                                if blocked_subjects.contains(&sub.to_lowercase()) {
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{} (blocked subject: {})",
                                            deny_reason, sub
                                        ),
                                    });
                                }
                            }

                            // Check required issuer (case-sensitive for standards compliance)
                            if let Some(ref req_iss) = required_issuer {
                                match &identity.issuer {
                                    Some(iss) if iss == req_iss => {}
                                    _ => {
                                        return Some(Verdict::Deny {
                                            reason: format!(
                                                "{} (issuer mismatch: expected '{}', got '{}')",
                                                deny_reason,
                                                req_iss,
                                                identity.issuer.as_deref().unwrap_or("<none>")
                                            ),
                                        });
                                    }
                                }
                            }

                            // Check required subject (case-sensitive)
                            if let Some(ref req_sub) = required_subject {
                                match &identity.subject {
                                    Some(sub) if sub == req_sub => {}
                                    _ => {
                                        return Some(Verdict::Deny {
                                            reason: format!(
                                                "{} (subject mismatch: expected '{}', got '{}')",
                                                deny_reason,
                                                req_sub,
                                                identity.subject.as_deref().unwrap_or("<none>")
                                            ),
                                        });
                                    }
                                }
                            }

                            // Check required audience
                            if let Some(ref req_aud) = required_audience {
                                if !identity.audience.contains(req_aud) {
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{} (audience mismatch: '{}' not in {:?})",
                                            deny_reason, req_aud, identity.audience
                                        ),
                                    });
                                }
                            }

                            // Check required custom claims
                            for (claim_key, expected_value) in required_claims {
                                match identity.claim_str(claim_key) {
                                    Some(actual) if actual == expected_value => {}
                                    actual => {
                                        return Some(Verdict::Deny {
                                            reason: format!(
                                                "{} (claim '{}' mismatch: expected '{}', got '{}')",
                                                deny_reason,
                                                claim_key,
                                                expected_value,
                                                actual.unwrap_or("<none>")
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                        None => {
                            // No agent_identity present
                            if *require_attestation {
                                // Fail-closed: attestation required but not provided
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{} (X-Agent-Identity header required but not provided)",
                                        deny_reason
                                    ),
                                });
                            }
                            // Fall back to legacy agent_id matching is handled by AgentId condition
                        }
                    }
                }
            }
        }
        None
    }

    /// Check action target_paths against compiled path rules.
    /// Returns Some(Deny) if any path is blocked or not in the allowed set.
    fn check_path_rules(&self, action: &Action, cp: &CompiledPolicy) -> Option<Verdict> {
        let rules = match &cp.compiled_path_rules {
            Some(r) => r,
            None => return None,
        };

        if action.target_paths.is_empty() {
            return None; // No paths to check
        }

        for raw_path in &action.target_paths {
            let normalized = match Self::normalize_path_bounded(
                raw_path, self.max_path_decode_iterations,
            ) {
                Ok(n) => n,
                Err(e) => return Some(Verdict::Deny {
                    reason: format!("Path normalization failed: {}", e),
                }),
            };

            // Check blocked patterns first (blocked takes precedence)
            for (pattern, matcher) in &rules.blocked {
                if matcher.is_match(&normalized) {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Path '{}' blocked by pattern '{}' in policy '{}'",
                            normalized, pattern, cp.policy.name
                        ),
                    });
                }
            }

            // If allowed list is non-empty, path must match at least one
            if !rules.allowed.is_empty()
                && !rules.allowed.iter().any(|(_, m)| m.is_match(&normalized))
            {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Path '{}' not in allowed paths for policy '{}'",
                        normalized, cp.policy.name
                    ),
                });
            }
        }

        None
    }

    /// Check action target_domains against compiled network rules.
    /// Returns Some(Deny) if any domain is blocked or not in the allowed set.
    fn check_network_rules(&self, action: &Action, cp: &CompiledPolicy) -> Option<Verdict> {
        let rules = match &cp.compiled_network_rules {
            Some(r) => r,
            None => return None,
        };

        if action.target_domains.is_empty() {
            return None; // No domains to check
        }

        for raw_domain in &action.target_domains {
            let domain = raw_domain.to_lowercase();

            // Check blocked domains first
            for pattern in &rules.blocked_domains {
                if Self::match_domain_pattern(&domain, pattern) {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Domain '{}' blocked by pattern '{}' in policy '{}'",
                            domain, pattern, cp.policy.name
                        ),
                    });
                }
            }

            // If allowed list is non-empty, domain must match at least one
            if !rules.allowed_domains.is_empty()
                && !rules
                    .allowed_domains
                    .iter()
                    .any(|p| Self::match_domain_pattern(&domain, p))
            {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Domain '{}' not in allowed domains for policy '{}'",
                        domain, cp.policy.name
                    ),
                });
            }
        }

        None
    }

    /// Check resolved IPs against compiled IP rules (DNS rebinding protection).
    ///
    /// Returns `Some(Deny)` if any resolved IP violates the rules.
    /// Returns `None` if all IPs pass or no IP rules are configured.
    fn check_ip_rules(&self, action: &Action, cp: &CompiledPolicy) -> Option<Verdict> {
        let ip_rules = match &cp.compiled_ip_rules {
            Some(r) => r,
            None => return None,
        };

        // Fail-closed: if ip_rules are configured but no resolved IPs provided
        // and the action has target domains, deny (caller didn't perform DNS resolution).
        if action.resolved_ips.is_empty() && !action.target_domains.is_empty() {
            return Some(Verdict::Deny {
                reason: format!(
                    "IP rules configured but no resolved IPs provided for policy '{}'",
                    cp.policy.name
                ),
            });
        }

        for ip_str in &action.resolved_ips {
            let raw_ip: IpAddr = match ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    return Some(Verdict::Deny {
                        reason: format!("Invalid resolved IP '{}'", ip_str),
                    })
                }
            };

            // SECURITY (R24-ENG-1): Canonicalize IPv4-mapped IPv6 addresses
            // (e.g., ::ffff:10.0.0.1) to their IPv4 form so that IPv4 CIDRs
            // like 10.0.0.0/8 correctly match. Without this, an attacker can
            // bypass CIDR blocklists by using the mapped form.
            let ip = match raw_ip {
                IpAddr::V6(v6) => {
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        IpAddr::V4(v4)
                    } else {
                        raw_ip
                    }
                }
                _ => raw_ip,
            };

            // Check private IP blocking
            if ip_rules.block_private && is_private_ip(ip) {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Resolved IP '{}' is a private/reserved address (DNS rebinding protection) in policy '{}'",
                        ip, cp.policy.name
                    ),
                });
            }

            // Check blocked CIDRs
            for cidr in &ip_rules.blocked_cidrs {
                if cidr.contains(&ip) {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Resolved IP '{}' in blocked CIDR '{}' in policy '{}'",
                            ip, cidr, cp.policy.name
                        ),
                    });
                }
            }

            // Check allowed CIDRs (allowlist mode)
            if !ip_rules.allowed_cidrs.is_empty()
                && !ip_rules.allowed_cidrs.iter().any(|c| c.contains(&ip))
            {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Resolved IP '{}' not in allowed CIDRs for policy '{}'",
                        ip, cp.policy.name
                    ),
                });
            }
        }

        None
    }

    /// Evaluate pre-compiled conditions against an action (no tracing).
    fn evaluate_compiled_conditions(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<Option<Verdict>, EngineError> {
        self.evaluate_compiled_conditions_core(action, cp, &mut None)
    }

    /// Core implementation shared by traced and non-traced compiled condition evaluation.
    ///
    /// When `trace` is `Some`, collects `ConstraintResult` records for each check.
    /// When `None`, skips trace collection (zero overhead).
    ///
    /// Returns `Ok(None)` when `on_no_match: "continue"` is set and no constraints fired,
    /// signaling the evaluation loop to skip to the next policy.
    fn evaluate_compiled_conditions_core(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
        trace: &mut Option<Vec<ConstraintResult>>,
    ) -> Result<Option<Verdict>, EngineError> {
        // Check require_approval first
        if cp.require_approval {
            if let Some(results) = trace.as_mut() {
                results.push(ConstraintResult {
                    constraint_type: "require_approval".to_string(),
                    param: "".to_string(),
                    expected: "true".to_string(),
                    actual: "true".to_string(),
                    passed: false,
                });
            }
            return Ok(Some(Verdict::RequireApproval {
                reason: cp.approval_reason.clone(),
            }));
        }

        // Check forbidden parameters
        for (i, param_str) in cp.forbidden_parameters.iter().enumerate() {
            let param_val = action.parameters.get(param_str);
            let present = param_val.is_some();
            if let Some(results) = trace.as_mut() {
                let actual = match param_val {
                    Some(v) => format!("present: {}", Self::describe_value(v)),
                    None => "absent".to_string(),
                };
                results.push(ConstraintResult {
                    constraint_type: "forbidden_parameter".to_string(),
                    param: param_str.clone(),
                    expected: "absent".to_string(),
                    actual,
                    passed: !present,
                });
            }
            if present {
                return Ok(Some(Verdict::Deny {
                    reason: cp.forbidden_reasons[i].clone(),
                }));
            }
        }

        // Check required parameters
        for (i, param_str) in cp.required_parameters.iter().enumerate() {
            let param_val = action.parameters.get(param_str);
            let present = param_val.is_some();
            if let Some(results) = trace.as_mut() {
                let actual = match param_val {
                    Some(v) => format!("present: {}", Self::describe_value(v)),
                    None => "absent".to_string(),
                };
                results.push(ConstraintResult {
                    constraint_type: "required_parameter".to_string(),
                    param: param_str.clone(),
                    expected: "present".to_string(),
                    actual,
                    passed: present,
                });
            }
            if !present {
                return Ok(Some(Verdict::Deny {
                    reason: cp.required_reasons[i].clone(),
                }));
            }
        }

        // Evaluate compiled constraints.
        // Track whether any constraint actually evaluated (vs all being skipped).
        // If ALL constraints skip (every required parameter is missing), this is
        // a fail-open vulnerability — deny instead of allowing silently.
        let mut any_evaluated = false;
        let total_constraints = cp.constraints.len();

        for constraint in &cp.constraints {
            if let Some(results) = trace.as_mut() {
                let (maybe_verdict, constraint_results) =
                    self.evaluate_compiled_constraint_traced(action, &cp.policy, constraint)?;
                results.extend(constraint_results);
                if let Some(verdict) = maybe_verdict {
                    return Ok(Some(verdict));
                }
            } else if let Some(verdict) =
                self.evaluate_compiled_constraint(action, &cp.policy, constraint)?
            {
                return Ok(Some(verdict));
            }
            // Check if this constraint was actually evaluated (not skipped)
            let param_name = constraint.param();
            let on_missing = constraint.on_missing();
            if param_name == "*" {
                let all_values = Self::collect_all_string_values(&action.parameters);
                if !all_values.is_empty() || on_missing != "skip" {
                    any_evaluated = true;
                }
            } else {
                let has_param = Self::get_param_by_path(&action.parameters, param_name).is_some();
                if has_param || on_missing != "skip" {
                    any_evaluated = true;
                }
            }
        }

        // Fail-closed: if ALL constraints were skipped due to missing parameters,
        // deny the action. A Conditional policy where nothing was checked is not
        // a positive allow signal — it means the action didn't provide enough
        // information for evaluation.
        // Exception: when on_no_match="continue", skip to next policy instead.
        if total_constraints > 0 && !any_evaluated {
            if cp.on_no_match_continue {
                return Ok(None);
            }
            if let Some(results) = trace.as_mut() {
                results.push(ConstraintResult {
                    constraint_type: "all_skipped_fail_closed".to_string(),
                    param: "".to_string(),
                    expected: "at least one constraint evaluated".to_string(),
                    actual: format!(
                        "all {} constraints skipped (missing params)",
                        total_constraints
                    ),
                    passed: false,
                });
            }
            return Ok(Some(Verdict::Deny {
                reason: format!(
                    "All {} constraints skipped (parameters missing) in policy '{}' — fail-closed",
                    total_constraints, cp.policy.name
                ),
            }));
        }

        // No constraints fired. If on_no_match is "continue", skip to next policy.
        if cp.on_no_match_continue {
            Ok(None)
        } else {
            Ok(Some(Verdict::Allow))
        }
    }

    /// Evaluate a single pre-compiled constraint against an action.
    fn evaluate_compiled_constraint(
        &self,
        action: &Action,
        policy: &Policy,
        constraint: &CompiledConstraint,
    ) -> Result<Option<Verdict>, EngineError> {
        let param_name = constraint.param();
        let on_match = constraint.on_match();
        let on_missing = constraint.on_missing();

        // Wildcard param "*": scan all string values
        if param_name == "*" {
            let all_values = Self::collect_all_string_values(&action.parameters);
            if all_values.is_empty() {
                if on_missing == "skip" {
                    return Ok(None);
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "No string values found in parameters (fail-closed) in policy '{}'",
                        policy.name
                    ),
                )?));
            }
            for (value_path, value_str) in &all_values {
                let json_val = serde_json::Value::String((*value_str).to_string());
                if let Some(verdict) = self.evaluate_compiled_constraint_value(
                    policy, value_path, on_match, &json_val, constraint,
                )? {
                    return Ok(Some(verdict));
                }
            }
            return Ok(None);
        }

        // Get the parameter value
        let param_value = match Self::get_param_by_path(&action.parameters, param_name) {
            Some(v) => v,
            None => {
                if on_missing == "skip" {
                    return Ok(None);
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' missing (fail-closed) in policy '{}'",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        self.evaluate_compiled_constraint_value(
            policy,
            param_name,
            on_match,
            param_value,
            constraint,
        )
    }

    /// Evaluate a compiled constraint against a specific parameter value.
    fn evaluate_compiled_constraint_value(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &CompiledConstraint,
    ) -> Result<Option<Verdict>, EngineError> {
        match constraint {
            CompiledConstraint::Glob {
                matcher,
                pattern_str,
                ..
            } => {
                let raw = match value.as_str() {
                    Some(s) => s,
                    None => {
                        if self.strict_mode {
                            return Err(EngineError::InvalidCondition {
                                policy_id: policy.id.clone(),
                                reason: format!(
                                    "Parameter '{}' is not a string for glob operator",
                                    param_name
                                ),
                            });
                        }
                        return Ok(Some(Self::make_constraint_verdict(
                            "deny",
                            &format!(
                                "Parameter '{}' is not a string (policy '{}')",
                                param_name, policy.name
                            ),
                        )?));
                    }
                };
                let normalized = match Self::normalize_path_bounded(raw, self.max_path_decode_iterations) {
                    Ok(n) => n,
                    Err(e) => return Ok(Some(Verdict::Deny { reason: format!("Path normalization failed: {}", e) })),
                };
                if matcher.is_match(&normalized) {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        &format!(
                            "Parameter '{}' path '{}' matches glob '{}' (policy '{}')",
                            param_name, normalized, pattern_str, policy.name
                        ),
                    )?))
                } else {
                    Ok(None)
                }
            }
            CompiledConstraint::NotGlob { matchers, .. } => {
                let raw = match value.as_str() {
                    Some(s) => s,
                    None => {
                        if self.strict_mode {
                            return Err(EngineError::InvalidCondition {
                                policy_id: policy.id.clone(),
                                reason: format!(
                                    "Parameter '{}' is not a string for not_glob operator",
                                    param_name
                                ),
                            });
                        }
                        return Ok(Some(Self::make_constraint_verdict(
                            "deny",
                            &format!(
                                "Parameter '{}' is not a string (policy '{}')",
                                param_name, policy.name
                            ),
                        )?));
                    }
                };
                let normalized = match Self::normalize_path_bounded(raw, self.max_path_decode_iterations) {
                    Ok(n) => n,
                    Err(e) => return Ok(Some(Verdict::Deny { reason: format!("Path normalization failed: {}", e) })),
                };
                for (_, m) in matchers {
                    if m.is_match(&normalized) {
                        return Ok(None); // Matched allowlist
                    }
                }
                Ok(Some(Self::make_constraint_verdict(
                    on_match,
                    &format!(
                        "Parameter '{}' path '{}' not in allowlist (policy '{}')",
                        param_name, normalized, policy.name
                    ),
                )?))
            }
            CompiledConstraint::Regex {
                regex, pattern_str, ..
            } => {
                let raw = match value.as_str() {
                    Some(s) => s,
                    None => {
                        if self.strict_mode {
                            return Err(EngineError::InvalidCondition {
                                policy_id: policy.id.clone(),
                                reason: format!(
                                    "Parameter '{}' is not a string for regex operator",
                                    param_name
                                ),
                            });
                        }
                        return Ok(Some(Self::make_constraint_verdict(
                            "deny",
                            &format!(
                                "Parameter '{}' is not a string (policy '{}')",
                                param_name, policy.name
                            ),
                        )?));
                    }
                };
                if regex.is_match(raw) {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        &format!(
                            "Parameter '{}' matches regex '{}' (policy '{}')",
                            param_name, pattern_str, policy.name
                        ),
                    )?))
                } else {
                    Ok(None)
                }
            }
            CompiledConstraint::DomainMatch { pattern, .. } => {
                let raw = match value.as_str() {
                    Some(s) => s,
                    None => {
                        if self.strict_mode {
                            return Err(EngineError::InvalidCondition {
                                policy_id: policy.id.clone(),
                                reason: format!(
                                    "Parameter '{}' is not a string for domain_match operator",
                                    param_name
                                ),
                            });
                        }
                        return Ok(Some(Self::make_constraint_verdict(
                            "deny",
                            &format!(
                                "Parameter '{}' is not a string (policy '{}')",
                                param_name, policy.name
                            ),
                        )?));
                    }
                };
                let domain = Self::extract_domain(raw);
                if Self::match_domain_pattern(&domain, pattern) {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        &format!(
                            "Parameter '{}' domain '{}' matches '{}' (policy '{}')",
                            param_name, domain, pattern, policy.name
                        ),
                    )?))
                } else {
                    Ok(None)
                }
            }
            CompiledConstraint::DomainNotIn { patterns, .. } => {
                let raw = match value.as_str() {
                    Some(s) => s,
                    None => {
                        if self.strict_mode {
                            return Err(EngineError::InvalidCondition {
                                policy_id: policy.id.clone(),
                                reason: format!(
                                    "Parameter '{}' is not a string for domain_not_in operator",
                                    param_name
                                ),
                            });
                        }
                        return Ok(Some(Self::make_constraint_verdict(
                            "deny",
                            &format!(
                                "Parameter '{}' is not a string (policy '{}')",
                                param_name, policy.name
                            ),
                        )?));
                    }
                };
                let domain = Self::extract_domain(raw);
                for pat_str in patterns {
                    if Self::match_domain_pattern(&domain, pat_str) {
                        return Ok(None); // Matched allowlist
                    }
                }
                Ok(Some(Self::make_constraint_verdict(
                    on_match,
                    &format!(
                        "Parameter '{}' domain '{}' not in allowlist (policy '{}')",
                        param_name, domain, policy.name
                    ),
                )?))
            }
            CompiledConstraint::Eq {
                value: expected, ..
            } => {
                if value == expected {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        &format!(
                            "Parameter '{}' equals {:?} (policy '{}')",
                            param_name, expected, policy.name
                        ),
                    )?))
                } else {
                    Ok(None)
                }
            }
            CompiledConstraint::Ne {
                value: expected, ..
            } => {
                if value != expected {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        &format!(
                            "Parameter '{}' != {:?} (policy '{}')",
                            param_name, expected, policy.name
                        ),
                    )?))
                } else {
                    Ok(None)
                }
            }
            CompiledConstraint::OneOf { values, .. } => {
                if values.contains(value) {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        &format!(
                            "Parameter '{}' is in the specified set (policy '{}')",
                            param_name, policy.name
                        ),
                    )?))
                } else {
                    Ok(None)
                }
            }
            CompiledConstraint::NoneOf { values, .. } => {
                if !values.contains(value) {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        &format!(
                            "Parameter '{}' is not in the allowed set (policy '{}')",
                            param_name, policy.name
                        ),
                    )?))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Check if a policy matches an action.
    ///
    /// Policy ID convention: `"tool:function"`, `"tool:*"`, `"*:function"`, or `"*"`.
    fn matches_action(&self, action: &Action, policy: &Policy) -> bool {
        let id = &policy.id;

        if id == "*" {
            return true;
        }

        if let Some((tool_pat, func_remainder)) = id.split_once(':') {
            // Support qualifier suffixes: "tool:func:qualifier" → match on "tool:func" only
            let func_pat = func_remainder
                .split_once(':')
                .map_or(func_remainder, |(f, _)| f);
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
    /// Returns `None` when a Conditional policy with `on_no_match: "continue"` has no
    /// conditions fire, signaling the evaluation loop to try the next policy.
    fn apply_policy(
        &self,
        action: &Action,
        policy: &Policy,
    ) -> Result<Option<Verdict>, EngineError> {
        match &policy.policy_type {
            PolicyType::Allow => Ok(Some(Verdict::Allow)),
            PolicyType::Deny => Ok(Some(Verdict::Deny {
                reason: format!("Denied by policy '{}'", policy.name),
            })),
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
    ) -> Result<Option<Verdict>, EngineError> {
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
                return Ok(Some(Verdict::RequireApproval {
                    reason: format!("Approval required by policy '{}'", policy.name),
                }));
            }
        }

        // Check forbidden parameters
        if let Some(forbidden) = conditions.get("forbidden_parameters") {
            if let Some(forbidden_arr) = forbidden.as_array() {
                for param in forbidden_arr {
                    if let Some(param_str) = param.as_str() {
                        if action.parameters.get(param_str).is_some() {
                            return Ok(Some(Verdict::Deny {
                                reason: format!(
                                    "Parameter '{}' is forbidden by policy '{}'",
                                    param_str, policy.name
                                ),
                            }));
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
                            return Ok(Some(Verdict::Deny {
                                reason: format!(
                                    "Required parameter '{}' missing (policy '{}')",
                                    param_str, policy.name
                                ),
                            }));
                        }
                    }
                }
            }
        }

        let on_no_match_continue = conditions
            .get("on_no_match")
            .and_then(|v| v.as_str())
            .map(|s| s == "continue")
            .unwrap_or(false);

        // Evaluate parameter constraints
        if let Some(constraints) = conditions.get("parameter_constraints") {
            if let Some(arr) = constraints.as_array() {
                if let Some(verdict) =
                    self.evaluate_parameter_constraints(action, policy, arr, on_no_match_continue)?
                {
                    return Ok(Some(verdict));
                }
            } else {
                return Err(EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "parameter_constraints must be an array".to_string(),
                });
            }
        }

        // In strict mode, reject unrecognized condition keys
        if self.strict_mode {
            let known_keys = [
                "require_approval",
                "forbidden_parameters",
                "required_parameters",
                "parameter_constraints",
                "on_no_match",
            ];
            if let Some(obj) = conditions.as_object() {
                for key in obj.keys() {
                    if !known_keys.contains(&key.as_str()) {
                        return Err(EngineError::InvalidCondition {
                            policy_id: policy.id.clone(),
                            reason: format!("Unknown condition key '{}' in strict mode", key),
                        });
                    }
                }
            }
        }

        // No conditions triggered. Check on_no_match setting.
        if on_no_match_continue {
            Ok(None)
        } else {
            Ok(Some(Verdict::Allow))
        }
    }

    /// Evaluate an array of parameter constraints against the action.
    ///
    /// Returns `Ok(Some(verdict))` if a constraint fires, `Ok(None)` if all pass.
    /// If ALL constraints are skipped due to missing parameters, returns a Deny
    /// verdict (fail-closed) instead of `None`.
    fn evaluate_parameter_constraints(
        &self,
        action: &Action,
        policy: &Policy,
        constraints: &[serde_json::Value],
        on_no_match_continue: bool,
    ) -> Result<Option<Verdict>, EngineError> {
        let mut any_evaluated = false;
        let total_constraints = constraints.len();

        for constraint in constraints {
            let obj = constraint
                .as_object()
                .ok_or_else(|| EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "Each parameter constraint must be a JSON object".to_string(),
                })?;

            let param_name = obj.get("param").and_then(|v| v.as_str()).ok_or_else(|| {
                EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "Constraint missing required 'param' string field".to_string(),
                }
            })?;

            let op = obj.get("op").and_then(|v| v.as_str()).ok_or_else(|| {
                EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "Constraint missing required 'op' string field".to_string(),
                }
            })?;

            let on_match = obj
                .get("on_match")
                .and_then(|v| v.as_str())
                .unwrap_or("deny");

            let on_missing = obj
                .get("on_missing")
                .and_then(|v| v.as_str())
                .unwrap_or("deny");

            // Wildcard param "*": recursively scan ALL string values in parameters
            if param_name == "*" {
                let all_values = Self::collect_all_string_values(&action.parameters);
                if all_values.is_empty() {
                    if on_missing == "skip" {
                        continue;
                    }
                    return Ok(Some(Self::make_constraint_verdict(
                        "deny",
                        &format!(
                            "No string values found in parameters (fail-closed) in policy '{}'",
                            policy.name
                        ),
                    )?));
                }
                any_evaluated = true;
                for (value_path, value_str) in &all_values {
                    let json_val = serde_json::Value::String((*value_str).to_string());
                    if let Some(verdict) = self.evaluate_single_constraint(
                        policy, value_path, op, on_match, &json_val, obj,
                    )? {
                        return Ok(Some(verdict));
                    }
                }
                continue;
            }

            // Get the parameter value from the action, supporting dot-separated paths
            // e.g. "config.output.path" traverses into nested objects
            let param_value = match Self::get_param_by_path(&action.parameters, param_name) {
                Some(v) => v,
                None => {
                    if on_missing == "skip" {
                        continue;
                    }
                    // Fail-closed: missing parameter → deny
                    return Ok(Some(Self::make_constraint_verdict(
                        "deny",
                        &format!(
                            "Parameter '{}' missing (fail-closed) in policy '{}'",
                            param_name, policy.name
                        ),
                    )?));
                }
            };

            any_evaluated = true;
            if let Some(verdict) =
                self.evaluate_single_constraint(policy, param_name, op, on_match, param_value, obj)?
            {
                return Ok(Some(verdict));
            }
        }

        // Fail-closed: if ALL constraints were skipped, deny (unless on_no_match="continue")
        if total_constraints > 0 && !any_evaluated && !on_no_match_continue {
            return Ok(Some(Verdict::Deny {
                reason: format!(
                    "All {} constraints skipped (parameters missing) in policy '{}' — fail-closed",
                    total_constraints, policy.name
                ),
            }));
        }

        Ok(None)
    }

    /// Dispatch a single constraint by operator.
    fn evaluate_single_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        op: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        match op {
            "glob" => self.eval_glob_constraint(policy, param_name, on_match, value, constraint),
            "not_glob" => {
                self.eval_not_glob_constraint(policy, param_name, on_match, value, constraint)
            }
            "domain_match" => {
                self.eval_domain_match_constraint(policy, param_name, on_match, value, constraint)
            }
            "domain_not_in" => {
                self.eval_domain_not_in_constraint(policy, param_name, on_match, value, constraint)
            }
            "regex" => self.eval_regex_constraint(policy, param_name, on_match, value, constraint),
            "eq" => self.eval_eq_constraint(policy, param_name, on_match, value, constraint),
            "ne" => self.eval_ne_constraint(policy, param_name, on_match, value, constraint),
            "one_of" => {
                self.eval_one_of_constraint(policy, param_name, on_match, value, constraint)
            }
            "none_of" => {
                self.eval_none_of_constraint(policy, param_name, on_match, value, constraint)
            }
            _ => Err(EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: format!("Unknown constraint operator '{}'", op),
            }),
        }
    }

    /// Glob match: fires when normalized path matches the glob pattern.
    fn eval_glob_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{}' is not a string for glob operator",
                            param_name
                        ),
                    });
                }
                // Non-strict: non-string on string operator → deny
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let pattern_str = constraint
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "glob constraint missing 'pattern' string".to_string(),
            })?;

        let normalized = match Self::normalize_path_bounded(raw, self.max_path_decode_iterations) {
            Ok(n) => n,
            Err(e) => return Ok(Some(Verdict::Deny { reason: format!("Path normalization failed: {}", e) })),
        };

        if self.glob_is_match(pattern_str, &normalized, &policy.id)? {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' path '{}' matches glob '{}' (policy '{}')",
                    param_name, normalized, pattern_str, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Not-glob: fires when path matches NONE of the allowlist glob patterns.
    fn eval_not_glob_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{}' is not a string for not_glob operator",
                            param_name
                        ),
                    });
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let patterns = constraint
            .get("patterns")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "not_glob constraint missing 'patterns' array".to_string(),
            })?;

        let normalized = match Self::normalize_path_bounded(raw, self.max_path_decode_iterations) {
            Ok(n) => n,
            Err(e) => return Ok(Some(Verdict::Deny { reason: format!("Path normalization failed: {}", e) })),
        };

        for pat_val in patterns {
            let pat_str = pat_val
                .as_str()
                .ok_or_else(|| EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "not_glob patterns must be strings".to_string(),
                })?;
            if self.glob_is_match(pat_str, &normalized, &policy.id)? {
                return Ok(None); // Matched allowlist, no fire
            }
        }

        // Matched NONE → fire
        Ok(Some(Self::make_constraint_verdict(
            on_match,
            &format!(
                "Parameter '{}' path '{}' not in allowlist (policy '{}')",
                param_name, normalized, policy.name
            ),
        )?))
    }

    /// Domain match: fires when extracted domain matches a `*.example.com` style pattern.
    fn eval_domain_match_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{}' is not a string for domain_match operator",
                            param_name
                        ),
                    });
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let pattern = constraint
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "domain_match constraint missing 'pattern' string".to_string(),
            })?;

        let domain = Self::extract_domain(raw);

        if Self::match_domain_pattern(&domain, pattern) {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' domain '{}' matches '{}' (policy '{}')",
                    param_name, domain, pattern, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Domain not-in: fires when extracted domain matches NONE of the allowlist patterns.
    fn eval_domain_not_in_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{}' is not a string for domain_not_in operator",
                            param_name
                        ),
                    });
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let patterns = constraint
            .get("patterns")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "domain_not_in constraint missing 'patterns' array".to_string(),
            })?;

        let domain = Self::extract_domain(raw);

        for pat_val in patterns {
            let pat_str = pat_val
                .as_str()
                .ok_or_else(|| EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: "domain_not_in patterns must be strings".to_string(),
                })?;
            if Self::match_domain_pattern(&domain, pat_str) {
                return Ok(None); // Matched allowlist
            }
        }

        Ok(Some(Self::make_constraint_verdict(
            on_match,
            &format!(
                "Parameter '{}' domain '{}' not in allowlist (policy '{}')",
                param_name, domain, policy.name
            ),
        )?))
    }

    /// Regex: fires when value matches the regex pattern.
    fn eval_regex_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let raw = match value.as_str() {
            Some(s) => s,
            None => {
                if self.strict_mode {
                    return Err(EngineError::InvalidCondition {
                        policy_id: policy.id.clone(),
                        reason: format!(
                            "Parameter '{}' is not a string for regex operator",
                            param_name
                        ),
                    });
                }
                return Ok(Some(Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' is not a string (policy '{}')",
                        param_name, policy.name
                    ),
                )?));
            }
        };

        let pattern = constraint
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "regex constraint missing 'pattern' string".to_string(),
            })?;

        let matched = self.regex_is_match(pattern, raw, &policy.id)?;

        if matched {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' matches regex '{}' (policy '{}')",
                    param_name, pattern, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Eq: fires when value equals the specified value exactly.
    fn eval_eq_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let expected = constraint
            .get("value")
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "eq constraint missing 'value' field".to_string(),
            })?;

        if value == expected {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' equals {:?} (policy '{}')",
                    param_name, expected, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Ne: fires when value does NOT equal the specified value.
    fn eval_ne_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let expected = constraint
            .get("value")
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "ne constraint missing 'value' field".to_string(),
            })?;

        if value != expected {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' != {:?} (policy '{}')",
                    param_name, expected, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// One-of: fires when value is in the specified set.
    fn eval_one_of_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let values = constraint
            .get("values")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "one_of constraint missing 'values' array".to_string(),
            })?;

        if values.contains(value) {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' is in the specified set (policy '{}')",
                    param_name, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// None-of: fires when value is NOT in the specified set.
    fn eval_none_of_constraint(
        &self,
        policy: &Policy,
        param_name: &str,
        on_match: &str,
        value: &serde_json::Value,
        constraint: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Verdict>, EngineError> {
        let values = constraint
            .get("values")
            .and_then(|v| v.as_array())
            .ok_or_else(|| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: "none_of constraint missing 'values' array".to_string(),
            })?;

        if !values.contains(value) {
            Ok(Some(Self::make_constraint_verdict(
                on_match,
                &format!(
                    "Parameter '{}' is not in the allowed set (policy '{}')",
                    param_name, policy.name
                ),
            )?))
        } else {
            Ok(None)
        }
    }

    /// Normalize a file path: resolve `..`, `.`, reject null bytes, ensure deterministic form.
    ///
    /// Uses the default decode iteration limit ([`DEFAULT_MAX_PATH_DECODE_ITERATIONS`]).
    /// For a configurable limit, use [`normalize_path_bounded`](Self::normalize_path_bounded).
    pub fn normalize_path(raw: &str) -> Result<String, EngineError> {
        Self::normalize_path_bounded(raw, DEFAULT_MAX_PATH_DECODE_ITERATIONS)
    }

    /// Normalize a file path with a configurable percent-decoding iteration limit.
    ///
    /// Iteratively decodes percent-encoding until stable. If `max_iterations` is
    /// reached before stabilization, returns `"/"` (fail-closed) and emits a
    /// warning via `tracing`.
    pub fn normalize_path_bounded(raw: &str, max_iterations: u32) -> Result<String, EngineError> {
        // Reject null bytes — return root instead of empty/raw to prevent bypass
        if raw.contains('\0') {
            return Err(EngineError::PathNormalization {
                reason: "input contains null byte".to_string(),
            });
        }

        // Phase 4.2: Percent-decode the path before normalization.
        // Decode in a loop until stable to guarantee idempotency:
        //   normalize_path(normalize_path(x)) == normalize_path(x)
        // Without loop decode, inputs like "%2570" produce "%70" on first call,
        // which decodes to "p" on the next call — breaking idempotency.
        // Safety cap prevents DoS from deeply-nested encodings.
        // If the cap is reached, return "/" (fail-closed).
        //
        // Uses Cow to avoid allocation when no percent sequences are present.
        let mut current = std::borrow::Cow::Borrowed(raw);
        let mut iterations = 0u32;
        loop {
            let decoded = percent_encoding::percent_decode_str(&current).decode_utf8_lossy();
            if decoded.contains('\0') {
                return Err(EngineError::PathNormalization {
                    reason: "decoded path contains null byte".to_string(),
                });
            }
            if decoded.as_ref() == current.as_ref() {
                break; // Stable — no more percent sequences to decode
            }
            iterations += 1;
            if iterations >= max_iterations {
                tracing::warn!(
                    path = raw,
                    iterations,
                    max_iterations,
                    "path normalization hit decode iteration limit — returning \"/\" (possible adversarial input)"
                );
                return Err(EngineError::PathNormalization {
                    reason: format!("decode iteration limit ({}) exceeded", max_iterations),
                });
            }
            current = std::borrow::Cow::Owned(decoded.into_owned());
        }

        let path = PathBuf::from(current.as_ref());
        let mut components = Vec::new();

        for component in path.components() {
            match component {
                Component::ParentDir => {
                    match components.last() {
                        Some(Component::RootDir) | None => {
                            // At root or empty — absorb the .., can't go above root
                            continue;
                        }
                        _ => {
                            components.pop();
                            continue;
                        }
                    }
                }
                Component::CurDir => continue,
                _ => {}
            }
            components.push(component);
        }

        let result: PathBuf = components.iter().collect();
        let s = result.to_string_lossy();
        if s.is_empty() {
            // Fix #9: Return "/" (root) instead of the raw input when normalization
            // produces an empty string. The raw input contains the traversal sequences
            // that normalization was supposed to remove.
            return Err(EngineError::PathNormalization {
                reason: "normalization produced empty path".to_string(),
            });
        }

        // SECURITY (R11-PATH-6): Enforce absolute path output.
        // If the input was a relative path (e.g., "etc/passwd"), the result
        // will not start with '/', causing it to miss absolute-path glob
        // patterns like "/etc/**". Prepend '/' to make it matchable.
        let s = s.into_owned();
        if !s.starts_with('/') {
            return Ok(format!("/{}", s));
        }

        Ok(s)
    }

    /// Extract the domain from a URL string.
    ///
    /// Strips scheme, port, path, query, and fragment.
    pub fn extract_domain(url: &str) -> String {
        let without_scheme = if let Some(pos) = url.find("://") {
            &url[pos + 3..]
        } else {
            url
        };

        // SECURITY (R22-ENG-5): Normalize backslashes to forward slashes BEFORE
        // splitting on path separator. Per the WHATWG URL Standard, `\` is treated
        // as a path separator in "special" schemes (http, https, ftp, etc.).
        // Without this, "http://evil.com\@legit.com/path" splits on '/' but the
        // `\@legit.com/path` remains in the authority portion, and after rfind('@')
        // we extract "legit.com/path" — completely wrong domain.
        let normalized = without_scheme.replace('\\', "/");
        let without_scheme = normalized.as_str();

        // Fix #8: Extract the authority portion FIRST (before the first '/'),
        // then search for '@' only within the authority. This prevents
        // ?email=user@safe.com in query params from being mistaken for userinfo.
        let authority_raw = without_scheme.split('/').next().unwrap_or(without_scheme);

        // Fix #30: Percent-decode the authority BEFORE searching for '@'.
        // Without this, "http://evil.com%40blocked.com/path" extracts authority
        // "evil.com%40blocked.com" — rfind('@') misses the encoded %40, and the
        // domain becomes "evil.com@blocked.com" instead of "blocked.com".
        // A standards-compliant parser decoding first would see userinfo="evil.com",
        // host="blocked.com", so we must decode before splitting on '@'.
        let decoded_authority =
            percent_encoding::percent_decode_str(authority_raw).decode_utf8_lossy();
        // SECURITY (R26-ENG-4): Apply backslash normalization AGAIN after percent-decode.
        // Input like "http://evil.com%5C@legit.com" has %5C decoded to '\' here.
        // After normalization, the decoded backslash becomes '/', which is a path
        // separator per WHATWG — so "evil.com/@legit.com" means authority="evil.com",
        // path="@legit.com". We re-split on '/' to get the true authority.
        let decoded_normalized = decoded_authority.replace('\\', "/");
        let authority = decoded_normalized
            .split('/')
            .next()
            .unwrap_or(&decoded_normalized);

        // Strip userinfo (user:pass@) — only within the authority portion
        let without_userinfo = if let Some(pos) = authority.rfind('@') {
            &authority[pos + 1..]
        } else {
            authority
        };

        // Strip query and fragment (shouldn't normally be in authority, but defensive)
        let host_port = without_userinfo;
        let host_port = host_port.split('?').next().unwrap_or(host_port);
        let host_port = host_port.split('#').next().unwrap_or(host_port);

        // Strip port
        let host = if let Some(bracket_end) = host_port.find(']') {
            // IPv6: [::1]:port
            &host_port[..bracket_end + 1]
        } else if let Some(pos) = host_port.rfind(':') {
            // Only strip if what follows looks like a port number
            if host_port[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
                &host_port[..pos]
            } else {
                host_port
            }
        } else {
            host_port
        };

        // Phase 4.2: Percent-decode the host to prevent bypass via encoded characters
        // (e.g., evil%2ecom → evil.com bypassing domain patterns).
        let decoded_host = percent_encoding::percent_decode_str(host).decode_utf8_lossy();
        // Fix #33: Strip trailing dot (DNS FQDN notation) to prevent bypass.
        // "evil.com." and "evil.com" must resolve to the same domain.
        // Single allocation: lowercase first, then strip trailing dots in-place.
        let mut result = decoded_host.to_lowercase();
        while result.ends_with('.') {
            result.pop();
        }
        result
    }

    /// Match a domain against a pattern like `*.example.com` or `example.com`.
    ///
    /// Both domain and pattern are normalized (lowercase, IDNA, strip trailing dots).
    /// Returns `false` (fail-closed) if either domain or pattern fails IDNA normalization.
    pub fn match_domain_pattern(domain: &str, pattern: &str) -> bool {
        // Normalize domain and pattern with IDNA.
        // Fail-closed: if normalization fails, treat as non-matching.
        let dom = match Self::normalize_domain_for_match(domain) {
            Some(d) => d,
            None => return false,
        };
        let pat = match Self::normalize_domain_for_match(pattern) {
            Some(p) => p,
            None => return false,
        };

        if let Some(suffix) = pat.strip_prefix("*.") {
            // Wildcard: domain must end with .suffix or be exactly suffix.
            // Use byte-level check to avoid format!() allocation.
            dom == suffix
                || (dom.len() > suffix.len()
                    && dom.ends_with(suffix)
                    && dom.as_bytes()[dom.len() - suffix.len() - 1] == b'.')
        } else {
            dom == pat
        }
    }

    /// Normalize a domain for matching: lowercase, strip trailing dots, apply IDNA.
    ///
    /// SECURITY (R18-DOMAIN-1): Applies IDNA (Internationalized Domain Names in
    /// Applications) normalization to convert Unicode domains to ASCII Punycode.
    /// This prevents bypass attacks using internationalized domain names that
    /// visually resemble blocked domains but differ in encoding.
    ///
    /// Returns `None` if IDNA conversion fails (invalid domain) — callers should
    /// treat this as fail-closed (non-matching).
    fn normalize_domain_for_match(s: &str) -> Option<std::borrow::Cow<'_, str>> {
        // Strip trailing dots first
        let stripped = s.trim_end_matches('.');

        // Check if the domain is already pure ASCII lowercase
        let is_ascii_lower = stripped
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'*');

        if is_ascii_lower && stripped == s {
            // Already normalized, no IDNA needed
            return Some(std::borrow::Cow::Borrowed(s));
        }

        if is_ascii_lower {
            // Just needed trailing dot removal
            return Some(std::borrow::Cow::Owned(stripped.to_string()));
        }

        // SECURITY (R25-ENG-5): Strip wildcard prefix before IDNA normalization.
        // IDNA rejects "*" as an invalid label, so "*.münchen.de" would fail
        // normalization and the pattern would never match — effectively allowing
        // the internationalized domain to bypass wildcard blocking.
        let (wildcard_prefix, idna_input) = if let Some(rest) = stripped.strip_prefix("*.") {
            ("*.", rest)
        } else {
            ("", stripped)
        };

        // Apply IDNA normalization for internationalized domains
        // This converts Unicode to Punycode (e.g., "münchen.de" -> "xn--mnchen-3ya.de")
        match idna::domain_to_ascii(idna_input) {
            Ok(ascii) => {
                if wildcard_prefix.is_empty() {
                    Some(std::borrow::Cow::Owned(ascii))
                } else {
                    Some(std::borrow::Cow::Owned(format!("{}{}", wildcard_prefix, ascii)))
                }
            }
            Err(_) => {
                // Invalid domain name — fail-closed by returning None
                tracing::debug!(domain = s, "IDNA normalization failed for domain");
                None
            }
        }
    }

    /// Maximum regex pattern length to prevent ReDoS via overlength patterns.
    const MAX_REGEX_LEN: usize = 1024;

    /// Validate a regex pattern for ReDoS safety.
    ///
    /// Rejects patterns that are too long (>1024 chars) or contain nested
    /// quantifiers like `(a+)+`, `(a*)*`, `(a+)*`, `(a*)+` which can cause
    /// exponential backtracking in regex engines.
    fn validate_regex_safety(pattern: &str) -> Result<(), String> {
        if pattern.len() > Self::MAX_REGEX_LEN {
            return Err(format!(
                "Regex pattern exceeds maximum length of {} chars ({} chars)",
                Self::MAX_REGEX_LEN,
                pattern.len()
            ));
        }

        // Detect nested quantifiers: a quantifier applied to a group that
        // itself contains a quantifier. Simplified check for common patterns.
        let quantifiers = ['+', '*'];
        let mut paren_depth = 0i32;
        let mut has_inner_quantifier = false;
        let chars: Vec<char> = pattern.chars().collect();
        // SECURITY (R8-5): Use a skip_next flag to correctly handle escape
        // sequences. The previous approach checked chars[i-1] == '\\' but
        // failed for double-escapes like `\\\\(` (literal backslash + open paren).
        let mut skip_next = false;

        for i in 0..chars.len() {
            if skip_next {
                skip_next = false;
                continue;
            }
            match chars[i] {
                '\\' => {
                    // Skip the NEXT character (the escaped one)
                    skip_next = true;
                    continue;
                }
                '(' => {
                    paren_depth += 1;
                    has_inner_quantifier = false;
                }
                ')' => {
                    paren_depth -= 1;
                    // Check if the next char is a quantifier
                    if i + 1 < chars.len()
                        && quantifiers.contains(&chars[i + 1])
                        && has_inner_quantifier
                    {
                        return Err(format!(
                            "Regex pattern contains nested quantifiers (potential ReDoS): '{}'",
                            &pattern[..pattern.len().min(100)]
                        ));
                    }
                }
                c if quantifiers.contains(&c) && paren_depth > 0 => {
                    has_inner_quantifier = true;
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Compile a regex pattern and test whether it matches the input.
    ///
    /// Legacy path: compiles the pattern on each call (no caching).
    /// For zero-overhead evaluation, use `with_policies()` to pre-compile.
    ///
    /// Validates the pattern for ReDoS safety before compilation (H2).
    fn regex_is_match(
        &self,
        pattern: &str,
        input: &str,
        policy_id: &str,
    ) -> Result<bool, EngineError> {
        Self::validate_regex_safety(pattern).map_err(|reason| EngineError::InvalidCondition {
            policy_id: policy_id.to_string(),
            reason,
        })?;
        let re = Regex::new(pattern).map_err(|e| EngineError::InvalidCondition {
            policy_id: policy_id.to_string(),
            reason: format!("Invalid regex pattern '{}': {}", pattern, e),
        })?;
        Ok(re.is_match(input))
    }

    /// Compile a glob pattern and test whether it matches the input.
    ///
    /// Legacy path: compiles the pattern on each call (no caching).
    /// For zero-overhead evaluation, use `with_policies()` to pre-compile.
    fn glob_is_match(
        &self,
        pattern: &str,
        input: &str,
        policy_id: &str,
    ) -> Result<bool, EngineError> {
        let matcher = Glob::new(pattern)
            .map_err(|e| EngineError::InvalidCondition {
                policy_id: policy_id.to_string(),
                reason: format!("Invalid glob pattern '{}': {}", pattern, e),
            })?
            .compile_matcher();
        Ok(matcher.is_match(input))
    }

    /// Retrieve a parameter value by dot-separated path.
    ///
    /// Supports both simple keys (`"path"`) and nested paths (`"config.output.path"`).
    ///
    /// **Resolution order** (Exploit #5 fix): When the path contains dots, the function
    /// checks both an exact key match (e.g., `params["config.path"]`) and dot-split
    /// traversal (e.g., `params["config"]["path"]`).
    ///
    /// **Ambiguity handling (fail-closed):** If both interpretations resolve to different
    /// values, the function returns `None`. This prevents an attacker from shadowing a
    /// nested value with a literal dotted key (or vice versa). The `None` triggers
    /// deny behavior through the constraint's `on_missing` handling.
    ///
    /// When only one interpretation resolves, that value is returned.
    /// When both resolve to the same value, that value is returned.
    pub fn get_param_by_path<'a>(
        params: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let exact_match = params.get(path);

        // For non-dotted paths, exact match is the only interpretation
        if !path.contains('.') {
            return exact_match;
        }

        // Try dot-split traversal for nested objects
        let traversal_match = {
            let mut current = params;
            let mut found = true;
            for segment in path.split('.') {
                match current.get(segment) {
                    Some(v) => current = v,
                    None => {
                        found = false;
                        break;
                    }
                }
            }
            if found {
                Some(current)
            } else {
                None
            }
        };

        match (exact_match, traversal_match) {
            // Both exist but differ: ambiguous — fail-closed (return None)
            (Some(exact), Some(traversal)) if exact != traversal => None,
            // Both exist and are equal: no ambiguity
            (Some(exact), Some(_)) => Some(exact),
            // Only one interpretation resolves
            (Some(exact), None) => Some(exact),
            (None, Some(traversal)) => Some(traversal),
            (None, None) => None,
        }
    }

    /// Maximum number of string values to collect during recursive parameter scanning.
    /// Prevents DoS from parameters with thousands of nested string values.
    const MAX_SCAN_VALUES: usize = 500;

    /// Maximum nesting depth for recursive parameter scanning.
    const MAX_JSON_DEPTH: usize = 32;

    /// Recursively collect all string values from a JSON structure.
    ///
    /// Returns a list of `(path, value)` pairs where `path` is a dot-separated
    /// description of where the value was found (e.g., `"options.target"`).
    /// Uses an iterative approach to avoid stack overflow on deep JSON.
    ///
    /// Bounded by [`MAX_SCAN_VALUES`] total values and [`MAX_JSON_DEPTH`] nesting depth.
    fn collect_all_string_values(params: &serde_json::Value) -> Vec<(String, &str)> {
        let mut results = Vec::new();
        // Stack: (value, current_path, depth)
        let mut stack: Vec<(&serde_json::Value, String, usize)> = vec![(params, String::new(), 0)];

        while let Some((val, path, depth)) = stack.pop() {
            if results.len() >= Self::MAX_SCAN_VALUES {
                break;
            }
            match val {
                serde_json::Value::String(s) => {
                    if !path.is_empty() {
                        results.push((path, s.as_str()));
                    }
                }
                serde_json::Value::Object(obj) => {
                    if depth >= Self::MAX_JSON_DEPTH {
                        continue;
                    }
                    for (key, child) in obj {
                        let child_path = if path.is_empty() {
                            key.clone()
                        } else {
                            let mut p = String::with_capacity(path.len() + 1 + key.len());
                            p.push_str(&path);
                            p.push('.');
                            p.push_str(key);
                            p
                        };
                        stack.push((child, child_path, depth + 1));
                    }
                }
                serde_json::Value::Array(arr) => {
                    if depth >= Self::MAX_JSON_DEPTH {
                        continue;
                    }
                    for (i, child) in arr.iter().enumerate() {
                        let child_path = if path.is_empty() {
                            format!("[{}]", i)
                        } else {
                            format!("{}[{}]", path, i)
                        };
                        stack.push((child, child_path, depth + 1));
                    }
                }
                _ => {}
            }
        }

        results
    }

    /// Convert an `on_match` action string into a Verdict.
    fn make_constraint_verdict(on_match: &str, reason: &str) -> Result<Verdict, EngineError> {
        match on_match {
            "deny" => Ok(Verdict::Deny {
                reason: reason.to_string(),
            }),
            "require_approval" => Ok(Verdict::RequireApproval {
                reason: reason.to_string(),
            }),
            "allow" => Ok(Verdict::Allow),
            other => Err(EngineError::EvaluationError(format!(
                "Unknown on_match action: '{}'",
                other
            ))),
        }
    }

    // ═══════════════════════════════════════════════════
    // TRACED EVALUATION (Phase 10.4)
    // ═══════════════════════════════════════════════════

    /// Evaluate an action with full decision trace.
    ///
    /// Opt-in alternative to [`Self::evaluate_action`] that records per-policy match
    /// details for OPA-style decision explanations. Has ~20% allocation overhead
    /// compared to the non-traced hot path, so use only when `?trace=true`.
    pub fn evaluate_action_traced(
        &self,
        action: &Action,
    ) -> Result<(Verdict, EvaluationTrace), EngineError> {
        let start = Instant::now();
        let mut policy_matches: Vec<PolicyMatch> = Vec::new();
        let mut policies_checked: usize = 0;
        let mut final_verdict: Option<Verdict> = None;

        let action_summary = ActionSummary {
            tool: action.tool.clone(),
            function: action.function.clone(),
            param_count: action.parameters.as_object().map(|o| o.len()).unwrap_or(0),
            param_keys: action
                .parameters
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default(),
        };

        if self.compiled_policies.is_empty() {
            let verdict = Verdict::Deny {
                reason: "No policies defined".to_string(),
            };
            let trace = EvaluationTrace {
                action_summary,
                policies_checked: 0,
                policies_matched: 0,
                matches: Vec::new(),
                verdict: verdict.clone(),
                duration_us: start.elapsed().as_micros() as u64,
            };
            return Ok((verdict, trace));
        }

        // Walk compiled policies using the tool index (same order as evaluate_with_compiled)
        let indices = self.collect_candidate_indices(action);

        for idx in &indices {
            let cp = &self.compiled_policies[*idx];
            policies_checked += 1;

            let tool_matched = cp.tool_matcher.matches(action);
            if !tool_matched {
                policy_matches.push(PolicyMatch {
                    policy_id: cp.policy.id.clone(),
                    policy_name: cp.policy.name.clone(),
                    policy_type: Self::policy_type_str(&cp.policy.policy_type),
                    priority: cp.policy.priority,
                    tool_matched: false,
                    constraint_results: Vec::new(),
                    verdict_contribution: None,
                });
                continue;
            }

            // Tool matched — evaluate the policy and record constraint details
            let (verdict, constraint_results) = self.apply_compiled_policy_traced(action, cp)?;

            let pm = PolicyMatch {
                policy_id: cp.policy.id.clone(),
                policy_name: cp.policy.name.clone(),
                policy_type: Self::policy_type_str(&cp.policy.policy_type),
                priority: cp.policy.priority,
                tool_matched: true,
                constraint_results,
                verdict_contribution: verdict.clone(),
            };
            policy_matches.push(pm);

            if let Some(v) = verdict {
                if final_verdict.is_none() {
                    final_verdict = Some(v);
                }
                // First match wins — stop checking further policies
                break;
            }
            // None: on_no_match="continue", try next policy
        }

        let verdict = final_verdict.unwrap_or(Verdict::Deny {
            reason: "No matching policy".to_string(),
        });

        let policies_matched = policy_matches.iter().filter(|m| m.tool_matched).count();

        let trace = EvaluationTrace {
            action_summary,
            policies_checked,
            policies_matched,
            matches: policy_matches,
            verdict: verdict.clone(),
            duration_us: start.elapsed().as_micros() as u64,
        };

        Ok((verdict, trace))
    }

    /// Traced evaluation with optional session context.
    fn evaluate_action_traced_ctx(
        &self,
        action: &Action,
        context: Option<&EvaluationContext>,
    ) -> Result<(Verdict, EvaluationTrace), EngineError> {
        let start = Instant::now();
        let mut policy_matches: Vec<PolicyMatch> = Vec::new();
        let mut policies_checked: usize = 0;
        let mut final_verdict: Option<Verdict> = None;

        let action_summary = ActionSummary {
            tool: action.tool.clone(),
            function: action.function.clone(),
            param_count: action.parameters.as_object().map(|o| o.len()).unwrap_or(0),
            param_keys: action
                .parameters
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default(),
        };

        if self.compiled_policies.is_empty() {
            let verdict = Verdict::Deny {
                reason: "No policies defined".to_string(),
            };
            let trace = EvaluationTrace {
                action_summary,
                policies_checked: 0,
                policies_matched: 0,
                matches: Vec::new(),
                verdict: verdict.clone(),
                duration_us: start.elapsed().as_micros() as u64,
            };
            return Ok((verdict, trace));
        }

        let indices = self.collect_candidate_indices(action);

        for idx in &indices {
            let cp = &self.compiled_policies[*idx];
            policies_checked += 1;

            let tool_matched = cp.tool_matcher.matches(action);
            if !tool_matched {
                policy_matches.push(PolicyMatch {
                    policy_id: cp.policy.id.clone(),
                    policy_name: cp.policy.name.clone(),
                    policy_type: Self::policy_type_str(&cp.policy.policy_type),
                    priority: cp.policy.priority,
                    tool_matched: false,
                    constraint_results: Vec::new(),
                    verdict_contribution: None,
                });
                continue;
            }

            let (verdict, constraint_results) =
                self.apply_compiled_policy_traced_ctx(action, cp, context)?;

            let pm = PolicyMatch {
                policy_id: cp.policy.id.clone(),
                policy_name: cp.policy.name.clone(),
                policy_type: Self::policy_type_str(&cp.policy.policy_type),
                priority: cp.policy.priority,
                tool_matched: true,
                constraint_results,
                verdict_contribution: verdict.clone(),
            };
            policy_matches.push(pm);

            if let Some(v) = verdict {
                if final_verdict.is_none() {
                    final_verdict = Some(v);
                }
                break;
            }
        }

        let verdict = final_verdict.unwrap_or(Verdict::Deny {
            reason: "No matching policy".to_string(),
        });

        let policies_matched = policy_matches.iter().filter(|m| m.tool_matched).count();

        let trace = EvaluationTrace {
            action_summary,
            policies_checked,
            policies_matched,
            matches: policy_matches,
            verdict: verdict.clone(),
            duration_us: start.elapsed().as_micros() as u64,
        };

        Ok((verdict, trace))
    }

    /// Collect candidate policy indices in priority order using the tool index.
    fn collect_candidate_indices(&self, action: &Action) -> Vec<usize> {
        if self.tool_index.is_empty() && self.always_check.is_empty() {
            // No index: return all indices in order
            return (0..self.compiled_policies.len()).collect();
        }

        let tool_specific = self.tool_index.get(&action.tool);
        let tool_slice = tool_specific.map(|v| v.as_slice()).unwrap_or(&[]);
        let always_slice = &self.always_check;

        // Merge two sorted index slices.
        // SECURITY (R26-ENG-1): Deduplicate when same index in both slices.
        let mut result = Vec::with_capacity(tool_slice.len() + always_slice.len());
        let mut ti = 0;
        let mut ai = 0;
        loop {
            let next_idx = match (tool_slice.get(ti), always_slice.get(ai)) {
                (Some(&t), Some(&a)) => {
                    if t < a {
                        ti += 1;
                        t
                    } else if t > a {
                        ai += 1;
                        a
                    } else {
                        ti += 1;
                        ai += 1;
                        t
                    }
                }
                (Some(&t), None) => {
                    ti += 1;
                    t
                }
                (None, Some(&a)) => {
                    ai += 1;
                    a
                }
                (None, None) => break,
            };
            result.push(next_idx);
        }
        result
    }

    /// Apply a compiled policy and return both the verdict and constraint trace.
    /// Returns `None` as the verdict when `on_no_match: "continue"` and no constraints fired.
    fn apply_compiled_policy_traced(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<(Option<Verdict>, Vec<ConstraintResult>), EngineError> {
        self.apply_compiled_policy_traced_ctx(action, cp, None)
    }

    fn apply_compiled_policy_traced_ctx(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
        context: Option<&EvaluationContext>,
    ) -> Result<(Option<Verdict>, Vec<ConstraintResult>), EngineError> {
        // Check path rules BEFORE policy type dispatch (mirrors apply_compiled_policy).
        // Without this, ?trace=true would bypass all path/domain blocking.
        if let Some(denial) = self.check_path_rules(action, cp) {
            return Ok((Some(denial), Vec::new()));
        }
        // Check network rules before policy type dispatch.
        if let Some(denial) = self.check_network_rules(action, cp) {
            return Ok((Some(denial), Vec::new()));
        }
        // Check IP rules (DNS rebinding protection) after network rules.
        // SECURITY: Without this, ?trace=true would bypass IP-based blocking.
        if let Some(denial) = self.check_ip_rules(action, cp) {
            return Ok((Some(denial), Vec::new()));
        }
        // Check context conditions.
        // SECURITY: Fail-closed when context conditions exist but no context provided.
        if !cp.context_conditions.is_empty() {
            match context {
                Some(ctx) => {
                    if let Some(denial) = self.check_context_conditions(ctx, cp) {
                        return Ok((Some(denial), Vec::new()));
                    }
                }
                None => {
                    return Ok((Some(Verdict::Deny {
                        reason: format!(
                            "Policy '{}' requires evaluation context (has {} context condition(s)) but none was provided",
                            cp.policy.name,
                            cp.context_conditions.len()
                        ),
                    }), Vec::new()));
                }
            }
        }

        match &cp.policy.policy_type {
            PolicyType::Allow => Ok((Some(Verdict::Allow), Vec::new())),
            PolicyType::Deny => Ok((
                Some(Verdict::Deny {
                    reason: cp.deny_reason.clone(),
                }),
                Vec::new(),
            )),
            PolicyType::Conditional { .. } => self.evaluate_compiled_conditions_traced(action, cp),
        }
    }

    /// Evaluate compiled conditions with full constraint tracing.
    /// Delegates to `evaluate_compiled_conditions_core` with trace collection enabled.
    /// Returns `None` as the verdict when `on_no_match: "continue"` and no constraints fired.
    fn evaluate_compiled_conditions_traced(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<(Option<Verdict>, Vec<ConstraintResult>), EngineError> {
        let mut results = Some(Vec::new());
        let verdict = self.evaluate_compiled_conditions_core(action, cp, &mut results)?;
        Ok((verdict, results.unwrap_or_default()))
    }

    /// Evaluate a single compiled constraint with tracing.
    fn evaluate_compiled_constraint_traced(
        &self,
        action: &Action,
        policy: &Policy,
        constraint: &CompiledConstraint,
    ) -> Result<(Option<Verdict>, Vec<ConstraintResult>), EngineError> {
        let param_name = constraint.param();
        let on_match = constraint.on_match();
        let on_missing = constraint.on_missing();

        // Wildcard param: scan all string values
        if param_name == "*" {
            let all_values = Self::collect_all_string_values(&action.parameters);
            let mut results = Vec::new();
            if all_values.is_empty() {
                if on_missing == "skip" {
                    return Ok((None, Vec::new()));
                }
                results.push(ConstraintResult {
                    constraint_type: Self::constraint_type_str(constraint),
                    param: "*".to_string(),
                    expected: "any string values".to_string(),
                    actual: "none found".to_string(),
                    passed: false,
                });
                let verdict = Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "No string values found in parameters (fail-closed) in policy '{}'",
                        policy.name
                    ),
                )?;
                return Ok((Some(verdict), results));
            }
            for (value_path, value_str) in &all_values {
                let json_val = serde_json::Value::String((*value_str).to_string());
                let matched = self.constraint_matches_value(&json_val, constraint);
                results.push(ConstraintResult {
                    constraint_type: Self::constraint_type_str(constraint),
                    param: value_path.clone(),
                    expected: Self::constraint_expected_str(constraint),
                    actual: value_str.to_string(),
                    passed: !matched,
                });
                if matched {
                    let verdict = Self::make_constraint_verdict(
                        on_match,
                        &format!(
                            "Parameter '{}' value triggered constraint (policy '{}')",
                            value_path, policy.name
                        ),
                    )?;
                    return Ok((Some(verdict), results));
                }
            }
            return Ok((None, results));
        }

        // Get specific parameter
        let param_value = match Self::get_param_by_path(&action.parameters, param_name) {
            Some(v) => v,
            None => {
                if on_missing == "skip" {
                    return Ok((
                        None,
                        vec![ConstraintResult {
                            constraint_type: Self::constraint_type_str(constraint),
                            param: param_name.to_string(),
                            expected: Self::constraint_expected_str(constraint),
                            actual: "missing".to_string(),
                            passed: true,
                        }],
                    ));
                }
                let verdict = Self::make_constraint_verdict(
                    "deny",
                    &format!(
                        "Parameter '{}' missing (fail-closed) in policy '{}'",
                        param_name, policy.name
                    ),
                )?;
                return Ok((
                    Some(verdict),
                    vec![ConstraintResult {
                        constraint_type: Self::constraint_type_str(constraint),
                        param: param_name.to_string(),
                        expected: Self::constraint_expected_str(constraint),
                        actual: "missing".to_string(),
                        passed: false,
                    }],
                ));
            }
        };

        let matched = self.constraint_matches_value(param_value, constraint);
        let actual_str = param_value
            .as_str()
            .unwrap_or(&param_value.to_string())
            .to_string();
        let result = ConstraintResult {
            constraint_type: Self::constraint_type_str(constraint),
            param: param_name.to_string(),
            expected: Self::constraint_expected_str(constraint),
            actual: actual_str,
            passed: !matched,
        };

        if matched {
            let verdict = self.evaluate_compiled_constraint_value(
                policy,
                param_name,
                on_match,
                param_value,
                constraint,
            )?;
            Ok((verdict, vec![result]))
        } else {
            Ok((None, vec![result]))
        }
    }

    /// Check if a constraint matches a given value (without producing a verdict).
    fn constraint_matches_value(
        &self,
        value: &serde_json::Value,
        constraint: &CompiledConstraint,
    ) -> bool {
        match constraint {
            CompiledConstraint::Glob { matcher, .. } => {
                if let Some(s) = value.as_str() {
                    match Self::normalize_path_bounded(s, self.max_path_decode_iterations) {
                        Ok(ref normalized) => matcher.is_match(normalized),
                        Err(_) => true,
                    }
                } else {
                    true // non-string → treated as match (fail-closed)
                }
            }
            CompiledConstraint::NotGlob { matchers, .. } => {
                if let Some(s) = value.as_str() {
                    match Self::normalize_path_bounded(s, self.max_path_decode_iterations) {
                        Ok(ref normalized) => !matchers.iter().any(|(_, m)| m.is_match(normalized)),
                        Err(_) => true,
                    }
                } else {
                    true
                }
            }
            CompiledConstraint::Regex { regex, .. } => {
                if let Some(s) = value.as_str() {
                    regex.is_match(s)
                } else {
                    true
                }
            }
            CompiledConstraint::DomainMatch { pattern, .. } => {
                if let Some(s) = value.as_str() {
                    let domain = Self::extract_domain(s);
                    Self::match_domain_pattern(&domain, pattern)
                } else {
                    true
                }
            }
            CompiledConstraint::DomainNotIn { patterns, .. } => {
                if let Some(s) = value.as_str() {
                    let domain = Self::extract_domain(s);
                    !patterns
                        .iter()
                        .any(|p| Self::match_domain_pattern(&domain, p))
                } else {
                    true
                }
            }
            CompiledConstraint::Eq {
                value: expected, ..
            } => value == expected,
            CompiledConstraint::Ne {
                value: expected, ..
            } => value != expected,
            CompiledConstraint::OneOf { values, .. } => values.contains(value),
            CompiledConstraint::NoneOf { values, .. } => !values.contains(value),
        }
    }

    fn policy_type_str(pt: &PolicyType) -> String {
        match pt {
            PolicyType::Allow => "allow".to_string(),
            PolicyType::Deny => "deny".to_string(),
            PolicyType::Conditional { .. } => "conditional".to_string(),
        }
    }

    fn constraint_type_str(c: &CompiledConstraint) -> String {
        match c {
            CompiledConstraint::Glob { .. } => "glob".to_string(),
            CompiledConstraint::NotGlob { .. } => "not_glob".to_string(),
            CompiledConstraint::Regex { .. } => "regex".to_string(),
            CompiledConstraint::DomainMatch { .. } => "domain_match".to_string(),
            CompiledConstraint::DomainNotIn { .. } => "domain_not_in".to_string(),
            CompiledConstraint::Eq { .. } => "eq".to_string(),
            CompiledConstraint::Ne { .. } => "ne".to_string(),
            CompiledConstraint::OneOf { .. } => "one_of".to_string(),
            CompiledConstraint::NoneOf { .. } => "none_of".to_string(),
        }
    }

    fn constraint_expected_str(c: &CompiledConstraint) -> String {
        match c {
            CompiledConstraint::Glob { pattern_str, .. } => {
                format!("matches glob '{}'", pattern_str)
            }
            CompiledConstraint::NotGlob { matchers, .. } => {
                let pats: Vec<&str> = matchers.iter().map(|(s, _)| s.as_str()).collect();
                format!("not in [{}]", pats.join(", "))
            }
            CompiledConstraint::Regex { pattern_str, .. } => {
                format!("matches regex '{}'", pattern_str)
            }
            CompiledConstraint::DomainMatch { pattern, .. } => {
                format!("domain matches '{}'", pattern)
            }
            CompiledConstraint::DomainNotIn { patterns, .. } => {
                format!("domain not in [{}]", patterns.join(", "))
            }
            CompiledConstraint::Eq { value, .. } => format!("equals {}", value),
            CompiledConstraint::Ne { value, .. } => format!("not equal {}", value),
            CompiledConstraint::OneOf { values, .. } => format!("one of {:?}", values),
            CompiledConstraint::NoneOf { values, .. } => format!("none of {:?}", values),
        }
    }

    /// Describe a JSON value's type and size without exposing raw content.
    /// Used in trace output to give useful debugging info without leaking secrets.
    fn describe_value(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Null => "null".to_string(),
            serde_json::Value::Bool(b) => format!("bool({})", b),
            serde_json::Value::Number(n) => format!("number({})", n),
            serde_json::Value::String(s) => format!("string({} chars)", s.len()),
            serde_json::Value::Array(arr) => format!("array({} items)", arr.len()),
            serde_json::Value::Object(obj) => format!("object({} keys)", obj.len()),
        }
    }

    /// Calculate the nesting depth of a JSON value using an iterative approach.
    /// Avoids stack overflow on adversarially deep JSON (e.g., 10,000+ levels).
    fn json_depth(value: &serde_json::Value) -> usize {
        let mut max_depth: usize = 0;
        // Stack of (value, current_depth) to process iteratively
        let mut stack: Vec<(&serde_json::Value, usize)> = vec![(value, 0)];

        while let Some((val, depth)) = stack.pop() {
            if depth > max_depth {
                max_depth = depth;
            }
            // Early termination: if we already exceed any reasonable limit, stop
            if max_depth > 128 {
                return max_depth;
            }
            match val {
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        stack.push((item, depth + 1));
                    }
                }
                serde_json::Value::Object(obj) => {
                    for item in obj.values() {
                        stack.push((item, depth + 1));
                    }
                }
                _ => {}
            }
        }

        max_depth
    }

    /// Returns true if any compiled policy has IP rules configured.
    ///
    /// Used by proxy layers to skip DNS resolution when no policies require it.
    pub fn has_ip_rules(&self) -> bool {
        self.compiled_policies
            .iter()
            .any(|cp| cp.compiled_ip_rules.is_some())
    }
}

/// Check whether an IP address is private/reserved (RFC 1918, loopback, link-local, etc.).
///
/// Used by [`PolicyEngine::check_ip_rules`] when `block_private` is enabled.
///
/// SECURITY (R18-IPV6-1): Comprehensive IPv6 special-purpose address coverage.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()      // 127.0.0.0/8
            || v4.is_private()     // 10/8, 172.16/12, 192.168/16
            || v4.is_link_local()  // 169.254/16
            || v4.is_unspecified() // 0.0.0.0
            || v4.is_broadcast()   // 255.255.255.255
            // SECURITY (R21-ENG-3): Additional reserved ranges
            || octets[0] == 0                                        // 0.0.0.0/8 (RFC 1122)
            || (octets[0] == 100 && (octets[1] & 0xC0) == 64)       // 100.64.0.0/10 CGNAT (RFC 6598)
            || (octets[0] == 198 && (octets[1] & 0xFE) == 18)       // 198.18.0.0/15 benchmarking (RFC 2544)
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24 (RFC 6890)
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // 192.0.2.0/24 TEST-NET-1 (RFC 5737)
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // 198.51.100.0/24 TEST-NET-2
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)  // 203.0.113.0/24 TEST-NET-3
            // SECURITY (R23-ENG-3): Additional IANA reserved ranges
            || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99) // 192.88.99.0/24 deprecated 6to4 relay (RFC 7526)
            || (octets[0] & 0xF0) == 240                               // 240.0.0.0/4 Reserved/Class E (RFC 1112)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()       // ::1
            || v6.is_unspecified() // ::
            || is_ipv6_unique_local(&v6)   // fc00::/7 (ULA)
            || is_ipv6_link_local(&v6)     // fe80::/10
            || is_ipv6_multicast(&v6)      // ff00::/8
            || is_ipv6_documentation(&v6)  // 2001:db8::/32
            || is_ipv6_discard(&v6)        // 100::/64
            // Transition mechanisms with embedded IPv4
            || is_ipv4_mapped_private(&v6)      // ::ffff:x.x.x.x
            || is_ipv4_compatible_private(&v6)   // ::x.x.x.x (R21-ENG-2)
            || is_6to4_private(&v6)              // 2002::/16
            || is_teredo_private(&v6)            // 2001::/32
            || is_nat64_private(&v6)             // 64:ff9b::/96
            || is_nat64_local_private(&v6)       // 64:ff9b:1::/48 (RFC 8215)
        }
    }
}

/// fc00::/7 — Unique Local Address (RFC 4193)
fn is_ipv6_unique_local(v6: &std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

/// fe80::/10 — Link-Local (RFC 4291)
fn is_ipv6_link_local(v6: &std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// ff00::/8 — Multicast (RFC 4291)
fn is_ipv6_multicast(v6: &std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xff00) == 0xff00
}

/// 2001:db8::/32 — Documentation (RFC 3849)
fn is_ipv6_documentation(v6: &std::net::Ipv6Addr) -> bool {
    v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8
}

/// 100::/64 — Discard-Only (RFC 6666)
fn is_ipv6_discard(v6: &std::net::Ipv6Addr) -> bool {
    v6.segments()[0] == 0x0100
        && v6.segments()[1] == 0
        && v6.segments()[2] == 0
        && v6.segments()[3] == 0
}

/// SECURITY (R22-ENG-2): Consistent reserved-range check for embedded IPv4 addresses.
///
/// All IPv6 transition mechanisms (mapped, compatible, 6to4, Teredo, NAT64) must
/// use the same set of checks. Previously, some functions only checked loopback +
/// private + link-local, while is_ipv4_compatible_private also checked CGNAT, 0/8,
/// and benchmarking ranges — creating inconsistent bypass opportunities.
fn is_embedded_ipv4_reserved(v4: &std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()                                            // 127.0.0.0/8
        || v4.is_private()                                       // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()                                    // 169.254/16
        || v4.is_unspecified()                                   // 0.0.0.0
        || v4.is_broadcast()                                     // 255.255.255.255
        || octets[0] == 0                                        // 0.0.0.0/8 (RFC 1122)
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)       // 100.64.0.0/10 CGNAT (RFC 6598)
        || (octets[0] == 198 && (octets[1] & 0xFE) == 18)       // 198.18.0.0/15 benchmarking (RFC 2544)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24 (RFC 6890)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // 192.0.2.0/24 TEST-NET-1
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // 198.51.100.0/24 TEST-NET-2
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)  // 203.0.113.0/24 TEST-NET-3
        // SECURITY (R23-ENG-3): Additional IANA reserved ranges
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99) // 192.88.99.0/24 deprecated 6to4 relay (RFC 7526)
        || (octets[0] & 0xF0) == 240                               // 240.0.0.0/4 Reserved/Class E (RFC 1112)
}

/// ::ffff:x.x.x.x — IPv4-mapped IPv6 (check embedded IPv4)
fn is_ipv4_mapped_private(v6: &std::net::Ipv6Addr) -> bool {
    v6.to_ipv4_mapped()
        .is_some_and(|v4| is_embedded_ipv4_reserved(&v4))
}

/// SECURITY (R21-ENG-2): ::x.x.x.x — IPv4-compatible IPv6 (deprecated, RFC 4291 §2.5.5.1)
///
/// Segments 0-4 are zero, segment 5 is NOT 0xffff (that would be IPv4-mapped).
/// The embedded IPv4 is in segments 6-7. Many OS kernels route these to the
/// embedded IPv4 address, enabling DNS rebinding if not blocked.
fn is_ipv4_compatible_private(v6: &std::net::Ipv6Addr) -> bool {
    let segs = v6.segments();
    if segs[0] == 0 && segs[1] == 0 && segs[2] == 0
        && segs[3] == 0 && segs[4] == 0 && segs[5] == 0
    {
        // Skip ::0.0.0.0 and ::0.0.0.1 (unspecified/loopback already covered)
        if segs[6] == 0 && segs[7] <= 1 {
            return false; // handled by is_loopback/is_unspecified
        }
        let octets = [
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        ];
        let embedded = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        return is_embedded_ipv4_reserved(&embedded);
    }
    false
}

/// 2002::/16 — 6to4 (RFC 3056) — extract embedded IPv4 from bits 16-47
fn is_6to4_private(v6: &std::net::Ipv6Addr) -> bool {
    if v6.segments()[0] != 0x2002 {
        return false;
    }
    // Embedded IPv4 is in segments 1 and 2 (bits 16-47)
    let octets = [
        (v6.segments()[1] >> 8) as u8,
        (v6.segments()[1] & 0xff) as u8,
        (v6.segments()[2] >> 8) as u8,
        (v6.segments()[2] & 0xff) as u8,
    ];
    let embedded = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    is_embedded_ipv4_reserved(&embedded)
}

/// 2001::/32 — Teredo (RFC 4380) — extract embedded IPv4 from last 32 bits (XORed)
fn is_teredo_private(v6: &std::net::Ipv6Addr) -> bool {
    if v6.segments()[0] != 0x2001 || v6.segments()[1] != 0 {
        return false;
    }
    // Teredo client IPv4 is in segments 6-7, XORed with 0xFFFF
    let octets = [
        ((v6.segments()[6] >> 8) ^ 0xff) as u8,
        ((v6.segments()[6] & 0xff) ^ 0xff) as u8,
        ((v6.segments()[7] >> 8) ^ 0xff) as u8,
        ((v6.segments()[7] & 0xff) ^ 0xff) as u8,
    ];
    let embedded = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    is_embedded_ipv4_reserved(&embedded)
}

/// 64:ff9b::/96 — NAT64 well-known prefix (RFC 6052) — extract embedded IPv4 from last 32 bits
fn is_nat64_private(v6: &std::net::Ipv6Addr) -> bool {
    // Check prefix 64:ff9b::/96 (segments 0-5 must be 0x0064, 0xff9b, 0, 0, 0, 0)
    if v6.segments()[0] != 0x0064
        || v6.segments()[1] != 0xff9b
        || v6.segments()[2] != 0
        || v6.segments()[3] != 0
        || v6.segments()[4] != 0
        || v6.segments()[5] != 0
    {
        return false;
    }
    // Embedded IPv4 is in segments 6-7
    let octets = [
        (v6.segments()[6] >> 8) as u8,
        (v6.segments()[6] & 0xff) as u8,
        (v6.segments()[7] >> 8) as u8,
        (v6.segments()[7] & 0xff) as u8,
    ];
    let embedded = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    is_embedded_ipv4_reserved(&embedded)
}

/// SECURITY (R25-ENG-2): 64:ff9b:1::/48 — NAT64 local-use prefix (RFC 8215)
///
/// RFC 8215 defines this range for NAT64 deployments that use locally assigned
/// prefixes. Like the well-known prefix (64:ff9b::/96), it embeds IPv4 addresses
/// in the last 32 bits. An attacker could use this to bypass private IP blocking
/// since the well-known prefix is already detected but the local-use prefix was not.
fn is_nat64_local_private(v6: &std::net::Ipv6Addr) -> bool {
    // Check prefix 64:ff9b:0001::/48
    // Segment 0 = 0x0064, Segment 1 = 0xff9b, Segment 2 = 0x0001
    if v6.segments()[0] != 0x0064
        || v6.segments()[1] != 0xff9b
        || v6.segments()[2] != 0x0001
    {
        return false;
    }
    // Embedded IPv4 is in segments 6-7 (last 32 bits)
    let octets = [
        (v6.segments()[6] >> 8) as u8,
        (v6.segments()[6] & 0xff) as u8,
        (v6.segments()[7] >> 8) as u8,
        (v6.segments()[7] & 0xff) as u8,
    ];
    let embedded = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    is_embedded_ipv4_reserved(&embedded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_policies_deny() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_deny_policy_match() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
        let policies = vec![Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_allow_policy_match() {
        let engine = PolicyEngine::new(false);
        let action = Action::new(
            "file_system".to_string(),
            "read_file".to_string(),
            json!({}),
        );
        let policies = vec![Policy {
            id: "file_system:read_file".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        }];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_priority_ordering() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
        let policies = vec![
            Policy {
                id: "*".to_string(),
                name: "Allow all (low priority)".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Deny bash (high priority)".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
        ];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_conditional_require_approval() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("network".to_string(), "connect".to_string(), json!({}));
        let policies = vec![Policy {
            id: "network:*".to_string(),
            name: "Network requires approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "require_approval": true
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    }

    // ═══════════════════════════════════════════════════
    // HELPER: build a conditional policy with constraints
    // ═══════════════════════════════════════════════════

    fn constraint_policy(constraints: serde_json::Value) -> Vec<Policy> {
        vec![Policy {
            id: "*".to_string(),
            name: "constraint-policy".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({ "parameter_constraints": constraints }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }]
    }

    fn action_with(tool: &str, func: &str, params: serde_json::Value) -> Action {
        Action::new(tool.to_string(), func.to_string(), params)
    }

    // ═══════════════════════════════════════════════════
    // PATH CONSTRAINTS: GLOB OPERATOR
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_glob_blocks_sensitive_path() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "file",
            "read",
            json!({"path": "/home/user/.aws/credentials"}),
        );
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/home/*/.aws/**",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_glob_allows_safe_path() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "file",
            "read",
            json!({"path": "/home/user/project/src/main.rs"}),
        );
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/home/*/.aws/**",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_glob_blocks_ssh_keys() {
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({"path": "/home/user/.ssh/id_rsa"}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/home/*/.ssh/**",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_glob_blocks_etc_passwd() {
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({"path": "/etc/passwd"}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/etc/passwd",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_glob_normalizes_traversal() {
        let engine = PolicyEngine::new(false);
        // Attempt path traversal: /home/user/project/../../.aws/credentials → /home/.aws/credentials
        let action = action_with(
            "file",
            "read",
            json!({"path": "/home/user/project/../../.aws/credentials"}),
        );
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/home/.aws/**",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_glob_normalizes_dot_segments() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "file",
            "read",
            json!({"path": "/home/user/./project/./src/main.rs"}),
        );
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/home/user/project/src/*",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_glob_null_byte_path_no_match() {
        let engine = PolicyEngine::new(false);
        // Null byte injection attempt
        let action = action_with(
            "file",
            "read",
            json!({"path": "/safe/path\u{0000}/../etc/passwd"}),
        );
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/safe/**",
            "on_match": "allow"
        }]));
        // Null byte path: normalization Err -> fail-closed -> Deny
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_glob_require_approval_on_match() {
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "write", json!({"path": "/etc/nginx/nginx.conf"}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/etc/**",
            "on_match": "require_approval"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    }

    #[test]
    fn test_glob_invalid_pattern_errors() {
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({"path": "/tmp/test"}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "[invalid",
            "on_match": "deny"
        }]));
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════
    // PATH CONSTRAINTS: NOT_GLOB OPERATOR (ALLOWLIST)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_not_glob_denies_outside_allowlist() {
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({"path": "/etc/shadow"}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "not_glob",
            "patterns": ["/home/user/project/**", "/tmp/**"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_not_glob_allows_inside_allowlist() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "file",
            "read",
            json!({"path": "/home/user/project/src/lib.rs"}),
        );
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "not_glob",
            "patterns": ["/home/user/project/**", "/tmp/**"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_not_glob_denies_traversal_outside_allowlist() {
        let engine = PolicyEngine::new(false);
        // Traversal: /home/user/project/../../.ssh/id_rsa → /home/.ssh/id_rsa
        let action = action_with(
            "file",
            "read",
            json!({"path": "/home/user/project/../../.ssh/id_rsa"}),
        );
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "not_glob",
            "patterns": ["/home/user/project/**"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_not_glob_multiple_allowed_paths() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "file",
            "write",
            json!({"path": "/tmp/workspace/output.json"}),
        );
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "not_glob",
            "patterns": ["/home/user/project/**", "/tmp/workspace/**", "/var/log/app/**"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    // ═══════════════════════════════════════════════════
    // DOMAIN CONSTRAINTS: DOMAIN_MATCH OPERATOR
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_domain_match_blocks_exact() {
        let engine = PolicyEngine::new(false);
        let action = action_with("http", "get", json!({"url": "https://evil.com/exfil"}));
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_match",
            "pattern": "evil.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_domain_match_blocks_wildcard_subdomain() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "http",
            "post",
            json!({"url": "https://data.pastebin.com/upload"}),
        );
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_match",
            "pattern": "*.pastebin.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_domain_match_wildcard_matches_bare_domain() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "http",
            "get",
            json!({"url": "https://pastebin.com/raw/abc"}),
        );
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_match",
            "pattern": "*.pastebin.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_domain_match_no_match_allows() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "http",
            "get",
            json!({"url": "https://api.anthropic.com/v1/messages"}),
        );
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_match",
            "pattern": "*.pastebin.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_domain_match_strips_port() {
        let engine = PolicyEngine::new(false);
        let action = action_with("http", "get", json!({"url": "https://evil.com:8443/path"}));
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_match",
            "pattern": "evil.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_domain_match_case_insensitive() {
        let engine = PolicyEngine::new(false);
        let action = action_with("http", "get", json!({"url": "https://Evil.COM/path"}));
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_match",
            "pattern": "evil.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_domain_match_strips_userinfo() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "http",
            "get",
            json!({"url": "https://user:pass@evil.com/path"}),
        );
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_match",
            "pattern": "evil.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_domain_match_no_scheme() {
        let engine = PolicyEngine::new(false);
        let action = action_with("http", "get", json!({"url": "evil.com/path"}));
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_match",
            "pattern": "evil.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    // ═══════════════════════════════════════════════════
    // DOMAIN CONSTRAINTS: DOMAIN_NOT_IN OPERATOR (ALLOWLIST)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_domain_not_in_denies_unlisted_domain() {
        let engine = PolicyEngine::new(false);
        let action = action_with("http", "post", json!({"url": "https://attacker.com/exfil"}));
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_not_in",
            "patterns": ["api.anthropic.com", "*.github.com", "*.company.internal"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_domain_not_in_allows_listed_domain() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "http",
            "post",
            json!({"url": "https://api.anthropic.com/v1/messages"}),
        );
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_not_in",
            "patterns": ["api.anthropic.com", "*.github.com"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_domain_not_in_allows_wildcard_subdomain() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "http",
            "get",
            json!({"url": "https://api.github.com/repos"}),
        );
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_not_in",
            "patterns": ["*.github.com"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_domain_not_in_blocks_ngrok() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "http",
            "post",
            json!({"url": "https://abc123.ngrok.io/callback"}),
        );
        let policies = constraint_policy(json!([{
            "param": "url",
            "op": "domain_not_in",
            "patterns": ["api.anthropic.com", "*.company.internal"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    // ═══════════════════════════════════════════════════
    // REGEX CONSTRAINTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_regex_blocks_sql_injection() {
        let engine = PolicyEngine::new(false);
        let action = action_with("db", "query", json!({"sql": "DROP TABLE users;"}));
        let policies = constraint_policy(json!([{
            "param": "sql",
            "op": "regex",
            "pattern": "(?i)drop\\s+table",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_regex_allows_safe_query() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "db",
            "query",
            json!({"sql": "SELECT * FROM users WHERE id = 1"}),
        );
        let policies = constraint_policy(json!([{
            "param": "sql",
            "op": "regex",
            "pattern": "(?i)drop\\s+table",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_regex_require_approval_for_delete() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "db",
            "query",
            json!({"sql": "DELETE FROM orders WHERE status = 'cancelled'"}),
        );
        let policies = constraint_policy(json!([{
            "param": "sql",
            "op": "regex",
            "pattern": "(?i)delete\\s+from",
            "on_match": "require_approval"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    }

    #[test]
    fn test_regex_invalid_pattern_errors() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"value": "test"}));
        let policies = constraint_policy(json!([{
            "param": "value",
            "op": "regex",
            "pattern": "(unclosed",
            "on_match": "deny"
        }]));
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════
    // EQ / NE CONSTRAINTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_eq_fires_on_match() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"mode": "destructive"}));
        let policies = constraint_policy(json!([{
            "param": "mode",
            "op": "eq",
            "value": "destructive",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_eq_does_not_fire_on_mismatch() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"mode": "safe"}));
        let policies = constraint_policy(json!([{
            "param": "mode",
            "op": "eq",
            "value": "destructive",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_ne_fires_when_not_equal() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"env": "production"}));
        let policies = constraint_policy(json!([{
            "param": "env",
            "op": "ne",
            "value": "staging",
            "on_match": "require_approval"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    }

    #[test]
    fn test_ne_does_not_fire_when_equal() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"env": "staging"}));
        let policies = constraint_policy(json!([{
            "param": "env",
            "op": "ne",
            "value": "staging",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    // ═══════════════════════════════════════════════════
    // ONE_OF / NONE_OF CONSTRAINTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_one_of_fires_when_in_set() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"action": "delete"}));
        let policies = constraint_policy(json!([{
            "param": "action",
            "op": "one_of",
            "values": ["delete", "drop", "truncate"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_one_of_does_not_fire_when_not_in_set() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"action": "read"}));
        let policies = constraint_policy(json!([{
            "param": "action",
            "op": "one_of",
            "values": ["delete", "drop", "truncate"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_none_of_fires_when_not_in_set() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"format": "xml"}));
        let policies = constraint_policy(json!([{
            "param": "format",
            "op": "none_of",
            "values": ["json", "csv"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_none_of_does_not_fire_when_in_set() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"format": "json"}));
        let policies = constraint_policy(json!([{
            "param": "format",
            "op": "none_of",
            "values": ["json", "csv"],
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    // ═══════════════════════════════════════════════════
    // MISSING PARAM / ERROR CASES
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_missing_param_denies_by_default() {
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/safe/**",
            "on_match": "allow"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_missing_param_skips_when_configured() {
        // Exploit #2 fix: a single constraint with on_missing=skip and missing param
        // means ALL constraints skipped → fail-closed → Deny
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/dangerous/**",
            "on_match": "deny",
            "on_missing": "skip"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "All constraints skipped → fail-closed deny, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_unknown_operator_errors() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"x": "y"}));
        let policies = constraint_policy(json!([{
            "param": "x",
            "op": "bogus_op",
            "on_match": "deny"
        }]));
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_on_match_action_errors() {
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({"path": "/etc/passwd"}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/etc/**",
            "on_match": "explode"
        }]));
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_err());
    }

    #[test]
    fn test_constraint_missing_param_field_errors() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"x": "y"}));
        let policies = constraint_policy(json!([{
            "op": "eq",
            "value": "y",
            "on_match": "deny"
        }]));
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_err());
    }

    #[test]
    fn test_constraint_missing_op_field_errors() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"x": "y"}));
        let policies = constraint_policy(json!([{
            "param": "x",
            "value": "y",
            "on_match": "deny"
        }]));
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_string_value_with_glob_denies_in_non_strict() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"path": 42}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/safe/**",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_non_string_value_with_glob_errors_in_strict() {
        let engine = PolicyEngine::new(true);
        let action = action_with("tool", "func", json!({"path": 42}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/safe/**",
            "on_match": "deny"
        }]));
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════
    // MULTIPLE CONSTRAINTS (LAYERED SECURITY)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_multiple_constraints_all_must_pass() {
        let engine = PolicyEngine::new(false);
        // Path is allowed, but domain is blocked
        let action = action_with(
            "http",
            "get",
            json!({
                "path": "/home/user/project/data.json",
                "url": "https://evil.com/exfil"
            }),
        );
        let policies = constraint_policy(json!([
            {
                "param": "path",
                "op": "not_glob",
                "patterns": ["/home/user/project/**"],
                "on_match": "deny"
            },
            {
                "param": "url",
                "op": "domain_match",
                "pattern": "evil.com",
                "on_match": "deny"
            }
        ]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        // Path passes (in allowlist), but domain is blocked
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_multiple_constraints_first_fires_wins() {
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({"path": "/etc/shadow"}));
        let policies = constraint_policy(json!([
            {
                "param": "path",
                "op": "glob",
                "pattern": "/etc/shadow",
                "on_match": "deny"
            },
            {
                "param": "path",
                "op": "glob",
                "pattern": "/etc/**",
                "on_match": "require_approval"
            }
        ]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        // First constraint fires → deny (not require_approval)
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    // ═══════════════════════════════════════════════════
    // PATH NORMALIZATION UNIT TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_normalize_path_resolves_parent() {
        assert_eq!(PolicyEngine::normalize_path("/a/b/../c").unwrap(), "/a/c");
    }

    #[test]
    fn test_normalize_path_resolves_dot() {
        assert_eq!(PolicyEngine::normalize_path("/a/./b/./c").unwrap(), "/a/b/c");
    }

    #[test]
    fn test_normalize_path_prevents_root_escape() {
        assert_eq!(
            PolicyEngine::normalize_path("/a/../../etc/passwd").unwrap(),
            "/etc/passwd"
        );
    }

    #[test]
    fn test_normalize_path_root_on_null_byte() {
        // Fix #9: Null byte paths now return "/" instead of empty string or raw input
        assert!(PolicyEngine::normalize_path("/a/b\0/c").is_err());
    }

    #[test]
    fn test_normalize_path_absolute_stays_absolute() {
        assert_eq!(
            PolicyEngine::normalize_path("/usr/local/bin").unwrap(),
            "/usr/local/bin"
        );
    }

    // ═══════════════════════════════════════════════════
    // DOMAIN EXTRACTION UNIT TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_extract_domain_https() {
        assert_eq!(
            PolicyEngine::extract_domain("https://example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_with_port() {
        assert_eq!(
            PolicyEngine::extract_domain("https://example.com:8443/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_with_userinfo() {
        assert_eq!(
            PolicyEngine::extract_domain("https://user:pass@example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_no_scheme() {
        assert_eq!(
            PolicyEngine::extract_domain("example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_with_query_and_fragment() {
        assert_eq!(
            PolicyEngine::extract_domain("https://example.com/path?q=1#frag"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_lowercases() {
        assert_eq!(
            PolicyEngine::extract_domain("https://Example.COM/path"),
            "example.com"
        );
    }

    // ═══════════════════════════════════════════════════
    // DOMAIN PATTERN MATCHING UNIT TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_match_domain_exact() {
        assert!(PolicyEngine::match_domain_pattern(
            "example.com",
            "example.com"
        ));
    }

    #[test]
    fn test_match_domain_exact_no_match() {
        assert!(!PolicyEngine::match_domain_pattern(
            "other.com",
            "example.com"
        ));
    }

    #[test]
    fn test_match_domain_wildcard_subdomain() {
        assert!(PolicyEngine::match_domain_pattern(
            "sub.example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_match_domain_wildcard_bare() {
        assert!(PolicyEngine::match_domain_pattern(
            "example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_match_domain_wildcard_deep_sub() {
        assert!(PolicyEngine::match_domain_pattern(
            "a.b.example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_match_domain_wildcard_no_match() {
        assert!(!PolicyEngine::match_domain_pattern(
            "example.org",
            "*.example.com"
        ));
    }

    #[test]
    fn test_match_domain_case_insensitive() {
        assert!(PolicyEngine::match_domain_pattern(
            "Example.COM",
            "example.com"
        ));
    }

    #[test]
    fn test_match_domain_idna_wildcard() {
        // R25-ENG-5: IDNA wildcard patterns should work with internationalized domains.
        // "*.münchen.de" should match "sub.münchen.de" after IDNA normalization.
        // Previously, the "*." prefix caused IDNA normalization to fail entirely.
        assert!(
            PolicyEngine::match_domain_pattern(
                "sub.xn--mnchen-3ya.de",
                "*.münchen.de"
            ),
            "IDNA wildcard should match punycode subdomain"
        );
        // Also test that the bare domain matches
        assert!(
            PolicyEngine::match_domain_pattern(
                "xn--mnchen-3ya.de",
                "*.münchen.de"
            ),
            "IDNA wildcard should match bare punycode domain"
        );
    }

    // ═══════════════════════════════════════════════════
    // PARAMETER_CONSTRAINTS MUST BE ARRAY
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_parameter_constraints_not_array_errors() {
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"x": "y"}));
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "bad-policy".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({ "parameter_constraints": "not-an-array" }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let result = engine.evaluate_action(&action, &policies);
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════
    // JSON PATH TRAVERSAL (DEEP PARAMETER INSPECTION)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_json_path_nested_parameter() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "tool",
            "func",
            json!({"config": {"output": {"path": "/etc/shadow"}}}),
        );
        let policies = constraint_policy(json!([{
            "param": "config.output.path",
            "op": "glob",
            "pattern": "/etc/**",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_json_path_nested_allows_safe_value() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "tool",
            "func",
            json!({"config": {"output": {"path": "/tmp/output.json"}}}),
        );
        let policies = constraint_policy(json!([{
            "param": "config.output.path",
            "op": "glob",
            "pattern": "/etc/**",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_json_path_missing_intermediate_denies() {
        let engine = PolicyEngine::new(false);
        // "config" exists but "config.output" doesn't
        let action = action_with("tool", "func", json!({"config": {"other": "value"}}));
        let policies = constraint_policy(json!([{
            "param": "config.output.path",
            "op": "glob",
            "pattern": "/etc/**",
            "on_match": "deny"
        }]));
        // Missing intermediate → fail-closed deny
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_json_path_missing_intermediate_skip() {
        // Exploit #2 fix: missing intermediate path + on_missing=skip means all constraints
        // skipped → fail-closed → Deny
        let engine = PolicyEngine::new(false);
        let action = action_with("tool", "func", json!({"config": {"other": "value"}}));
        let policies = constraint_policy(json!([{
            "param": "config.output.path",
            "op": "glob",
            "pattern": "/etc/**",
            "on_match": "deny",
            "on_missing": "skip"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "All constraints skipped → fail-closed deny, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_json_path_simple_key_still_works() {
        // Simple keys (no dots) should work exactly as before
        let engine = PolicyEngine::new(false);
        let action = action_with("file", "read", json!({"path": "/etc/passwd"}));
        let policies = constraint_policy(json!([{
            "param": "path",
            "op": "glob",
            "pattern": "/etc/**",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_json_path_domain_in_nested_object() {
        let engine = PolicyEngine::new(false);
        let action = action_with(
            "http",
            "request",
            json!({"options": {"target": "https://evil.com/exfil"}}),
        );
        let policies = constraint_policy(json!([{
            "param": "options.target",
            "op": "domain_match",
            "pattern": "evil.com",
            "on_match": "deny"
        }]));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_get_param_by_path_unit() {
        let params = json!({"a": {"b": {"c": 42}}, "top": "val"});
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "a.b.c"),
            Some(&json!(42))
        );
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "top"),
            Some(&json!("val"))
        );
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "a.b.missing"),
            None
        );
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "nonexistent"),
            None
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Exploit #5 Regression: Parameter path dot-splitting ambiguity
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_get_param_by_path_exact_key_with_literal_dot() {
        // Literal dotted key with no nested equivalent — should resolve
        let params = json!({"config.path": "/tmp/safe.txt"});
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "config.path"),
            Some(&json!("/tmp/safe.txt"))
        );
    }

    #[test]
    fn test_get_param_by_path_nested_only() {
        // Nested path with no literal dotted key — should resolve via traversal
        let params = json!({"config": {"path": "/etc/shadow"}});
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "config.path"),
            Some(&json!("/etc/shadow"))
        );
    }

    #[test]
    fn test_get_param_by_path_ambiguous_different_values_returns_none() {
        // EXPLOIT #5: Both literal key AND nested path exist with DIFFERENT values.
        // Attacker adds "config.path": "/tmp/safe.txt" to shadow nested "config"."path": "/etc/shadow".
        // Engine MUST return None (ambiguous) to trigger fail-closed deny.
        let params = json!({
            "config.path": "/tmp/safe.txt",
            "config": {"path": "/etc/shadow"}
        });
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "config.path"),
            None,
            "Ambiguous parameter (exact key differs from nested path) must return None for fail-closed"
        );
    }

    #[test]
    fn test_get_param_by_path_ambiguous_same_values_resolves() {
        // Both literal key AND nested path exist with the SAME value — no ambiguity
        let params = json!({
            "config.path": "/tmp/safe.txt",
            "config": {"path": "/tmp/safe.txt"}
        });
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "config.path"),
            Some(&json!("/tmp/safe.txt")),
            "Non-ambiguous (both interpretations agree) should resolve"
        );
    }

    #[test]
    fn test_get_param_by_path_deep_ambiguity_returns_none() {
        // Deep nesting: "a.b.c" as literal key vs a→b→c traversal
        let params = json!({
            "a.b.c": "literal_value",
            "a": {"b": {"c": "nested_value"}}
        });
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "a.b.c"),
            None,
            "Deep ambiguity must return None for fail-closed"
        );
    }

    #[test]
    fn test_get_param_by_path_partial_traversal_no_ambiguity() {
        // Literal key exists but nested traversal fails (partial path) — unambiguous
        let params = json!({
            "config.path": "/tmp/safe.txt",
            "config": {"other": "value"}
        });
        assert_eq!(
            PolicyEngine::get_param_by_path(&params, "config.path"),
            Some(&json!("/tmp/safe.txt")),
            "Exact key with no nested equivalent should resolve normally"
        );
    }

    // ═══════════════════════════════════════════════════
    // SECURITY REGRESSION TESTS (Controller Directive C-2)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_fix8_extract_domain_at_in_query_not_authority() {
        // Fix #8: @-sign in query params must NOT be treated as userinfo separator.
        // https://evil.com/path?email=user@safe.com should extract "evil.com", not "safe.com"
        assert_eq!(
            PolicyEngine::extract_domain("https://evil.com/path?email=user@safe.com"),
            "evil.com"
        );
    }

    #[test]
    fn test_fix8_extract_domain_at_in_fragment() {
        // @-sign in fragment must not affect domain extraction
        assert_eq!(
            PolicyEngine::extract_domain("https://evil.com/page#section@anchor"),
            "evil.com"
        );
    }

    #[test]
    fn test_fix8_extract_domain_legitimate_userinfo_still_works() {
        // Legitimate userinfo still strips correctly
        assert_eq!(
            PolicyEngine::extract_domain("https://admin:secret@internal.corp.com/api"),
            "internal.corp.com"
        );
    }

    #[test]
    fn test_fix9_normalize_path_empty_returns_root() {
        // Fix #9: When normalization produces empty string (e.g., null byte input),
        // return "/" instead of the raw input containing dangerous sequences.
        assert!(
            PolicyEngine::normalize_path("/a/b\0/c").is_err(),
            "Null-byte path should return Err (fail-closed)"
        );
    }

    #[test]
    fn test_fix9_normalize_path_traversal_only() {
        // A path that is ONLY traversal sequences produces an empty result
        // after normalization, which now returns Err (fail-closed).
        assert!(
            PolicyEngine::normalize_path("../../..").is_err(),
            "Pure traversal path should return Err (fail-closed)"
        );
    }

    // --- Phase 4.2: Percent-encoding normalization tests ---

    #[test]
    fn test_normalize_path_percent_encoded_filename() {
        // %70 = 'p', so /etc/%70asswd → /etc/passwd
        assert_eq!(PolicyEngine::normalize_path("/etc/%70asswd").unwrap(), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_percent_encoded_traversal() {
        // %2F = '/', %2E = '.', so /%2E%2E/%2E%2E/etc/passwd → /etc/passwd
        assert_eq!(
            PolicyEngine::normalize_path("/%2E%2E/%2E%2E/etc/passwd").unwrap(),
            "/etc/passwd"
        );
    }

    #[test]
    fn test_normalize_path_percent_encoded_slash() {
        // %2F = '/' — encoded slashes in a single component
        // After decoding, path should be normalized correctly
        assert_eq!(PolicyEngine::normalize_path("/etc%2Fpasswd").unwrap(), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_encoded_null_byte() {
        // %00 = null byte — should be rejected after decoding
        assert!(PolicyEngine::normalize_path("/etc/%00passwd").is_err());
    }

    #[test]
    fn test_normalize_path_double_encoding_fully_decoded() {
        // %2570 = %25 + 70 → first decode: %70 → second decode: p
        // Loop decode ensures idempotency: normalize(normalize(x)) == normalize(x)
        // Full decode is more secure — prevents bypass via multi-layer encoding.
        let result = PolicyEngine::normalize_path("/etc/%2570asswd").unwrap();
        assert_eq!(
            result, "/etc/passwd",
            "Double-encoded input should be fully decoded for idempotency"
        );
    }

    #[test]
    fn test_normalize_path_mixed_encoded_and_plain() {
        assert_eq!(
            PolicyEngine::normalize_path("/home/%75ser/.aws/credentials").unwrap(),
            "/home/user/.aws/credentials"
        );
    }

    #[test]
    fn test_normalize_path_fully_encoded_path() {
        // Full path encoded
        assert_eq!(
            PolicyEngine::normalize_path("%2Fetc%2Fshadow").unwrap(),
            "/etc/shadow"
        );
    }

    #[test]
    fn test_normalize_path_six_level_encoding_decodes_fully() {
        // Build a 6-level encoded 'p': p → %70 → %2570 → %252570 → %25252570 → %2525252570 → %252525252570
        // Previous 5-iteration limit would fail to fully decode this.
        let result = PolicyEngine::normalize_path("/etc/%252525252570asswd").unwrap();
        assert_eq!(
            result, "/etc/passwd",
            "6-level encoding should be fully decoded with new higher limit"
        );
    }

    #[test]
    fn test_normalize_path_deep_encoding_returns_root() {
        // Build a path where "%25" is repeated enough that >20 decode iterations
        // are needed. Each iteration peels one layer of %25 → %.
        // 21 layers of %25 followed by 70 (= 'p') will require 21 decode passes.
        let mut encoded = "%70".to_string(); // level 0: %70 → p
        for _ in 0..21 {
            // Encode the leading '%' as %25
            encoded = format!("%25{}", &encoded[1..]);
        }
        let input = format!("/etc/{}asswd", encoded);
        assert!(
            PolicyEngine::normalize_path(&input).is_err(),
            "Encoding requiring >20 decode iterations should fail-closed with Err"
        );
    }

    #[test]
    fn test_normalize_path_bounded_custom_limit() {
        // Build a 5-level encoded path that needs exactly 5 decode passes.
        let mut encoded = "%70".to_string(); // level 0: %70 → p
        for _ in 0..5 {
            encoded = format!("%25{}", &encoded[1..]);
        }
        let input = format!("/etc/{}asswd", encoded);

        // With limit=10, 5 iterations succeeds.
        assert_eq!(
            PolicyEngine::normalize_path_bounded(&input, 10).unwrap(),
            "/etc/passwd"
        );

        // With limit=3, 5 iterations exceeds the cap → fail-closed to "/".
        assert!(PolicyEngine::normalize_path_bounded(&input, 3).is_err());
    }

    #[test]
    fn test_normalize_path_bounded_zero_limit() {
        // With limit=0, even a single percent-encoded char fails closed.
        assert!(
            PolicyEngine::normalize_path_bounded("/etc/%70asswd", 0).is_err()
        );
        // Plain paths (no percent-encoding) still work fine.
        assert_eq!(
            PolicyEngine::normalize_path_bounded("/etc/passwd", 0).unwrap(),
            "/etc/passwd"
        );
    }

    #[test]
    fn test_set_max_path_decode_iterations() {
        let mut engine = PolicyEngine::new(false);
        // Default is the constant.
        assert_eq!(PolicyEngine::normalize_path("/etc/%70asswd").unwrap(), "/etc/passwd");

        // After setting to 0, the engine's internal calls would use the
        // configured limit. Verify the setter doesn't panic.
        engine.set_max_path_decode_iterations(5);
        // The public associated function still uses the default (backward compat).
        assert_eq!(PolicyEngine::normalize_path("/etc/%70asswd").unwrap(), "/etc/passwd");
    }

    #[test]
    fn test_extract_domain_percent_encoded_dot() {
        // %2E = '.', so evil%2Ecom → evil.com
        assert_eq!(
            PolicyEngine::extract_domain("https://evil%2Ecom/path"),
            "evil.com"
        );
    }

    #[test]
    fn test_extract_domain_percent_encoded_host() {
        // Encoded characters in hostname
        assert_eq!(
            PolicyEngine::extract_domain("https://%65vil.com/data"),
            "evil.com"
        );
    }

    #[test]
    fn test_extract_domain_backslash_as_path_separator() {
        // SECURITY (R22-ENG-5): Per WHATWG URL Standard, `\` is treated as a
        // path separator in special schemes. Without normalization, the authority
        // portion includes the backslash and everything after it.
        assert_eq!(
            PolicyEngine::extract_domain("http://evil.com\\@legit.com/path"),
            "evil.com"
        );
        // Backslash before path — should split correctly
        assert_eq!(
            PolicyEngine::extract_domain("https://evil.com\\path\\to\\resource"),
            "evil.com"
        );
        // Multiple backslashes
        assert_eq!(
            PolicyEngine::extract_domain("http://host.com\\\\foo"),
            "host.com"
        );
    }

    #[test]
    fn test_extract_domain_backslash_with_userinfo() {
        // Combined: backslash + userinfo should extract correct domain
        assert_eq!(
            PolicyEngine::extract_domain("http://user:pass@host.com\\path"),
            "host.com"
        );
    }

    #[test]
    fn test_extract_domain_percent_encoded_backslash_before_at() {
        // SECURITY (R26-ENG-4): %5C is a percent-encoded backslash.
        // "http://evil.com%5C@legit.com/path" should extract "evil.com" (backslash
        // becomes path separator after decode), NOT "legit.com" (@ as userinfo).
        // After decoding, "evil.com\@legit.com" → backslash normalized to "/" →
        // "evil.com/@legit.com" → split on '/' → authority is "evil.com"
        let domain = PolicyEngine::extract_domain("http://evil.com%5C@legit.com/path");
        assert_eq!(
            domain, "evil.com",
            "R26-ENG-4: %5C before @ must not bypass domain extraction"
        );
    }

    #[test]
    fn test_extract_domain_double_encoded_backslash() {
        // %255C = double-encoded backslash → decodes to "%5C" (literal, not backslash)
        // This should NOT trigger backslash normalization
        let domain = PolicyEngine::extract_domain("http://evil.com%255C@legit.com/path");
        // After decode: "evil.com%5C@legit.com" — %5C is literal text, @ is userinfo separator
        assert_eq!(domain, "legit.com");
    }

    // ---- Recursive parameter scanning (param: "*") tests ----

    fn make_wildcard_policy(op: &str, constraint_extras: serde_json::Value) -> Policy {
        let mut base = serde_json::json!({
            "param": "*",
            "op": op,
            "on_match": "deny"
        });
        if let serde_json::Value::Object(extras) = constraint_extras {
            for (k, v) in extras {
                base.as_object_mut().unwrap().insert(k, v);
            }
        }
        Policy {
            id: "test:*".to_string(),
            name: "Wildcard scanner".to_string(),
            priority: 200,
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [base]
                }),
            },
            path_rules: None,
            network_rules: None,
        }
    }

    #[test]
    fn test_wildcard_scan_catches_nested_url() {
        // A dangerous URL buried in nested parameters should be caught
        let engine = PolicyEngine::new(false);
        let policy = make_wildcard_policy("domain_match", json!({"pattern": "*.evil.com"}));

        let action = Action::new(
            "test".to_string(),
            "call".to_string(),
            json!({
                "options": {
                    "target": "https://data.evil.com/exfil",
                    "retries": 3
                }
            }),
        );

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Deny { .. }),
            "Should deny: nested URL matches *.evil.com, got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_allows_when_no_match() {
        // No string values match — should fall through to allow
        let engine = PolicyEngine::new(false);
        let policy = make_wildcard_policy("domain_match", json!({"pattern": "*.evil.com"}));

        let action = Action::new(
            "test".to_string(),
            "call".to_string(),
            json!({
                "url": "https://safe.example.com/api",
                "data": "hello world"
            }),
        );

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Allow),
            "Should allow: no values match *.evil.com, got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_catches_path_in_array() {
        // Dangerous path buried in an array element
        let engine = PolicyEngine::new(false);
        let policy = make_wildcard_policy("glob", json!({"pattern": "/home/*/.ssh/**"}));

        let action = Action::new(
            "test".to_string(),
            "batch_read".to_string(),
            json!({
                "files": [
                    "/tmp/safe.txt",
                    "/home/user/.ssh/id_rsa",
                    "/var/log/syslog"
                ]
            }),
        );

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Deny { .. }),
            "Should deny: array contains path matching /home/*/.ssh/**, got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_regex_across_all_values() {
        // Regex scanning all values for dangerous commands
        let engine = PolicyEngine::new(false);
        let policy = make_wildcard_policy("regex", json!({"pattern": "(?i)rm\\s+-rf"}));

        let action = Action::new(
            "test".to_string(),
            "execute".to_string(),
            json!({
                "task": "cleanup",
                "steps": [
                    { "cmd": "ls -la /tmp" },
                    { "cmd": "rm -rf /" },
                    { "cmd": "echo done" }
                ]
            }),
        );

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Deny { .. }),
            "Should deny: deeply nested value matches rm -rf, got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_no_string_values_on_missing_deny() {
        // Parameters with only numbers/booleans — no string values found
        // Default on_missing=deny → should deny
        let engine = PolicyEngine::new(false);
        let policy = make_wildcard_policy("regex", json!({"pattern": "anything"}));

        let action = Action::new(
            "test".to_string(),
            "call".to_string(),
            json!({
                "count": 42,
                "enabled": true
            }),
        );

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Deny { .. }),
            "Should deny: no string values found (fail-closed), got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_no_string_values_on_missing_skip() {
        // Parameters with only numbers + on_missing=skip → ALL constraints skip → fail-closed DENY
        // This is Exploit #2 fix: when every constraint in a Conditional policy skips
        // because required parameters are missing, the policy must deny (fail-closed),
        // not silently allow.
        let engine = PolicyEngine::new(false);
        let constraint = json!({
            "param": "*",
            "op": "regex",
            "pattern": "anything",
            "on_match": "deny",
            "on_missing": "skip"
        });
        let policy = Policy {
            id: "test:*".to_string(),
            name: "Wildcard skip".to_string(),
            priority: 200,
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [constraint]
                }),
            },
            path_rules: None,
            network_rules: None,
        };

        let action = Action::new(
            "test".to_string(),
            "call".to_string(),
            json!({
                "count": 42,
                "enabled": true
            }),
        );

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Deny { .. }),
            "Should deny: all constraints skipped (fail-closed), got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_deeply_nested_value() {
        // Value buried 5 levels deep
        let engine = PolicyEngine::new(false);
        let policy = make_wildcard_policy("glob", json!({"pattern": "/etc/shadow"}));

        let action = Action::new(
            "test".to_string(),
            "call".to_string(),
            json!({
                "a": {
                    "b": {
                        "c": {
                            "d": {
                                "target": "/etc/shadow"
                            }
                        }
                    }
                }
            }),
        );

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Deny { .. }),
            "Should deny: /etc/shadow found 5 levels deep, got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_require_approval_on_match() {
        // Wildcard with require_approval instead of deny
        let engine = PolicyEngine::new(false);
        let constraint = json!({
            "param": "*",
            "op": "regex",
            "pattern": "(?i)password",
            "on_match": "require_approval"
        });
        let policy = Policy {
            id: "test:*".to_string(),
            name: "Wildcard approval".to_string(),
            priority: 200,
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [constraint]
                }),
            },
            path_rules: None,
            network_rules: None,
        };

        let action = Action::new(
            "test".to_string(),
            "call".to_string(),
            json!({
                "query": "SELECT * FROM users WHERE password = '123'"
            }),
        );

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::RequireApproval { .. }),
            "Should require approval: value contains 'password', got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_combined_with_specific_param() {
        // Both a specific param constraint and a wildcard in the same policy
        let engine = PolicyEngine::new(false);
        let policy = Policy {
            id: "test:*".to_string(),
            name: "Mixed constraints".to_string(),
            priority: 200,
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [
                        {
                            "param": "mode",
                            "op": "eq",
                            "value": "safe",
                            "on_match": "allow"
                        },
                        {
                            "param": "*",
                            "op": "glob",
                            "pattern": "/etc/shadow",
                            "on_match": "deny"
                        }
                    ]
                }),
            },
            path_rules: None,
            network_rules: None,
        };

        // mode=safe fires first → allow
        let action1 = Action::new(
            "test".to_string(),
            "call".to_string(),
            json!({
                "mode": "safe",
                "path": "/etc/shadow"
            }),
        );
        let result1 = engine
            .evaluate_action(&action1, std::slice::from_ref(&policy))
            .unwrap();
        assert!(
            matches!(result1, Verdict::Allow),
            "First constraint (mode=safe→allow) should fire first, got: {:?}",
            result1
        );

        // mode=other → doesn't match eq, wildcard scans and finds /etc/shadow → deny
        let action2 = Action::new(
            "test".to_string(),
            "call".to_string(),
            json!({
                "mode": "other",
                "path": "/etc/shadow"
            }),
        );
        let result2 = engine.evaluate_action(&action2, &[policy]).unwrap();
        assert!(
            matches!(result2, Verdict::Deny { .. }),
            "Wildcard should catch /etc/shadow when first constraint doesn't fire, got: {:?}",
            result2
        );
    }

    #[test]
    fn test_collect_all_string_values_basic() {
        let params = json!({
            "a": "hello",
            "b": 42,
            "c": {
                "d": "world",
                "e": true
            },
            "f": ["x", "y", 3]
        });

        let values = PolicyEngine::collect_all_string_values(&params);
        let string_values: Vec<&str> = values.iter().map(|(_, v)| *v).collect();

        assert!(string_values.contains(&"hello"), "Should contain 'hello'");
        assert!(string_values.contains(&"world"), "Should contain 'world'");
        assert!(string_values.contains(&"x"), "Should contain 'x'");
        assert!(string_values.contains(&"y"), "Should contain 'y'");
        assert_eq!(values.len(), 4, "Should have exactly 4 string values");
    }

    #[test]
    fn test_collect_all_string_values_empty_object() {
        let params = json!({});
        let values = PolicyEngine::collect_all_string_values(&params);
        assert!(values.is_empty(), "Empty object should yield no values");
    }

    #[test]
    fn test_collect_all_string_values_depth_limit() {
        // Build a structure deeper than MAX_JSON_DEPTH
        let mut val = json!("deep_secret");
        for _ in 0..40 {
            val = json!({"nested": val});
        }
        let values = PolicyEngine::collect_all_string_values(&val);
        // The string is at depth 40, but our limit is 32 — it should NOT be found
        assert!(
            values.is_empty(),
            "Values beyond MAX_JSON_DEPTH should not be collected"
        );
    }

    // ═══════════════════════════════════════════════════
    // PRE-COMPILED POLICY TESTS (C-9.2 / C-10.2)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_compiled_with_policies_basic() {
        let policies = vec![
            Policy {
                id: "bash:*".to_string(),
                name: "Block bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let bash_action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
        let verdict = engine.evaluate_action(&bash_action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let safe_action = Action::new("file_system".to_string(), "read".to_string(), json!({}));
        let verdict = engine.evaluate_action(&safe_action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_compiled_glob_constraint() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Block sensitive paths".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/home/*/.aws/**",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with(
            "file",
            "read",
            json!({"path": "/home/user/.aws/credentials"}),
        );
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let safe = action_with(
            "file",
            "read",
            json!({"path": "/home/user/project/main.rs"}),
        );
        let verdict = engine.evaluate_action(&safe, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_compiled_regex_constraint() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Block destructive SQL".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "sql",
                        "op": "regex",
                        "pattern": "(?i)drop\\s+table",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with("db", "query", json!({"sql": "DROP TABLE users;"}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let safe = action_with("db", "query", json!({"sql": "SELECT * FROM users"}));
        let verdict = engine.evaluate_action(&safe, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_compiled_invalid_regex_rejected_at_load_time() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Bad regex".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "x",
                        "op": "regex",
                        "pattern": "(unclosed",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let result = PolicyEngine::with_policies(false, &policies);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].reason.contains("Invalid regex pattern"));
        assert!(errors[0].reason.contains("(unclosed"));
    }

    #[test]
    fn test_compiled_invalid_glob_rejected_at_load_time() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Bad glob".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "[invalid",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let result = PolicyEngine::with_policies(false, &policies);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].reason.contains("Invalid glob pattern"));
    }

    #[test]
    fn test_compiled_multiple_errors_collected() {
        let policies = vec![
            Policy {
                id: "*".to_string(),
                name: "Bad regex policy".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "x",
                            "op": "regex",
                            "pattern": "(unclosed",
                            "on_match": "deny"
                        }]
                    }),
                },
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "tool:*".to_string(),
                name: "Bad glob policy".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "path",
                            "op": "glob",
                            "pattern": "[invalid",
                            "on_match": "deny"
                        }]
                    }),
                },
                priority: 50,
                path_rules: None,
                network_rules: None,
            },
        ];
        let result = PolicyEngine::with_policies(false, &policies);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 2);
        assert!(errors[0].reason.contains("regex"));
        assert!(errors[1].reason.contains("glob"));
    }

    #[test]
    fn test_compiled_validation_error_is_descriptive() {
        let policies = vec![Policy {
            id: "my_tool:my_func".to_string(),
            name: "My Policy Name".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "x",
                        "op": "regex",
                        "pattern": "[bad",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let result = PolicyEngine::with_policies(false, &policies);
        let errors = result.unwrap_err();
        assert_eq!(errors[0].policy_id, "my_tool:my_func");
        assert_eq!(errors[0].policy_name, "My Policy Name");
        let display = format!("{}", errors[0]);
        assert!(display.contains("My Policy Name"));
        assert!(display.contains("my_tool:my_func"));
    }

    #[test]
    fn test_compiled_policies_are_sorted() {
        let policies = vec![
            Policy {
                id: "*".to_string(),
                name: "Low priority allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "High priority deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        // High priority deny should win even though allow was listed first
        let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_compiled_domain_not_in() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Domain allowlist".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "url",
                        "op": "domain_not_in",
                        "patterns": ["api.anthropic.com", "*.github.com"],
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let blocked = action_with("http", "post", json!({"url": "https://evil.com/exfil"}));
        let verdict = engine.evaluate_action(&blocked, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let allowed = action_with(
            "http",
            "get",
            json!({"url": "https://api.anthropic.com/v1/messages"}),
        );
        let verdict = engine.evaluate_action(&allowed, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_compiled_require_approval() {
        let policies = vec![Policy {
            id: "network:*".to_string(),
            name: "Network approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({ "require_approval": true }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = Action::new("network".to_string(), "connect".to_string(), json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    }

    #[test]
    fn test_compiled_forbidden_parameters() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Forbid admin".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "forbidden_parameters": ["admin_override", "sudo"]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with("tool", "func", json!({"admin_override": true}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let safe = action_with("tool", "func", json!({"normal_param": "value"}));
        let verdict = engine.evaluate_action(&safe, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_compiled_not_glob_allowlist() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Path allowlist".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "not_glob",
                        "patterns": ["/home/user/project/**", "/tmp/**"],
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let blocked = action_with("file", "read", json!({"path": "/etc/shadow"}));
        let verdict = engine.evaluate_action(&blocked, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let allowed = action_with(
            "file",
            "read",
            json!({"path": "/home/user/project/src/lib.rs"}),
        );
        let verdict = engine.evaluate_action(&allowed, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_compiled_eq_ne_one_of_none_of() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Value checks".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [
                        { "param": "mode", "op": "eq", "value": "destructive", "on_match": "deny" }
                    ]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let blocked = action_with("tool", "func", json!({"mode": "destructive"}));
        assert!(matches!(
            engine.evaluate_action(&blocked, &[]).unwrap(),
            Verdict::Deny { .. }
        ));

        let allowed = action_with("tool", "func", json!({"mode": "safe"}));
        assert!(matches!(
            engine.evaluate_action(&allowed, &[]).unwrap(),
            Verdict::Allow
        ));
    }

    #[test]
    fn test_compiled_missing_param_fail_closed() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Require path".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/safe/**",
                        "on_match": "allow"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Missing param → deny (fail-closed)
        let action = action_with("file", "read", json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_compiled_on_missing_skip() {
        // Exploit #2 fix: compiled path — all constraints skip → fail-closed → Deny
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Optional path check".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/dangerous/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with("file", "read", json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "All constraints skipped → fail-closed deny, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_compiled_empty_policies_deny() {
        let engine = PolicyEngine::with_policies(false, &[]).unwrap();
        let action = Action::new("any".to_string(), "any".to_string(), json!({}));
        // Empty compiled policies → no matching policy → deny
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_compiled_parity_with_legacy() {
        // Verify compiled path produces same results as legacy path
        let policies = vec![
            Policy {
                id: "bash:*".to_string(),
                name: "Block bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 200,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*".to_string(),
                name: "Domain allowlist".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "url",
                            "op": "domain_not_in",
                            "patterns": ["api.anthropic.com"],
                            "on_match": "deny"
                        }]
                    }),
                },
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        let legacy_engine = PolicyEngine::new(false);
        let compiled_engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let test_cases = vec![
            action_with("bash", "execute", json!({"cmd": "ls"})),
            action_with("http", "get", json!({"url": "https://evil.com/bad"})),
            action_with(
                "http",
                "get",
                json!({"url": "https://api.anthropic.com/v1/messages"}),
            ),
            action_with("file", "read", json!({"path": "/tmp/test"})),
        ];

        for action in &test_cases {
            let legacy = legacy_engine.evaluate_action(action, &policies).unwrap();
            let compiled = compiled_engine.evaluate_action(action, &[]).unwrap();
            assert_eq!(
                std::mem::discriminant(&legacy),
                std::mem::discriminant(&compiled),
                "Parity mismatch for action {}:{} — legacy={:?}, compiled={:?}",
                action.tool,
                action.function,
                legacy,
                compiled,
            );
        }
    }

    #[test]
    fn test_compiled_strict_mode_unknown_key() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Unknown key".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "require_approval": false,
                    "custom_unknown_key": "value"
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let result = PolicyEngine::with_policies(true, &policies);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].reason.contains("Unknown condition key"));
    }

    #[test]
    fn test_compiled_wildcard_scan() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Scan all values".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "domain_match",
                        "pattern": "*.evil.com",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with(
            "tool",
            "func",
            json!({"nested": {"url": "https://sub.evil.com/bad"}}),
        );
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_compiled_unknown_operator_rejected_at_load_time() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Bad op".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "x",
                        "op": "bogus_op",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let result = PolicyEngine::with_policies(false, &policies);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].reason.contains("Unknown constraint operator"));
    }

    #[test]
    fn test_compiled_deep_json_rejected() {
        let mut deep = json!("leaf");
        for _ in 0..15 {
            deep = json!({"nested": deep});
        }
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Deep JSON".to_string(),
            policy_type: PolicyType::Conditional { conditions: deep },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let result = PolicyEngine::with_policies(false, &policies);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].reason.contains("nesting depth"));
    }

    #[test]
    fn test_compile_policies_standalone() {
        let policies = vec![
            Policy {
                id: "bash:*".to_string(),
                name: "Block bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
        ];
        let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
        assert_eq!(compiled.len(), 2);
        // Should be sorted by priority (highest first)
        assert_eq!(compiled[0].policy.name, "Block bash");
        assert_eq!(compiled[1].policy.name, "Allow all");
    }

    #[test]
    fn test_pattern_matcher_variants() {
        assert!(PatternMatcher::Any.matches("anything"));
        assert!(PatternMatcher::Exact("foo".to_string()).matches("foo"));
        assert!(!PatternMatcher::Exact("foo".to_string()).matches("bar"));
        assert!(PatternMatcher::Prefix("pre".to_string()).matches("prefix"));
        assert!(!PatternMatcher::Prefix("pre".to_string()).matches("suffix"));
        assert!(PatternMatcher::Suffix("fix".to_string()).matches("suffix"));
        assert!(!PatternMatcher::Suffix("fix".to_string()).matches("other"));
    }

    #[test]
    fn test_compiled_tool_matcher_variants() {
        let action = Action::new(
            "file_system".to_string(),
            "read_file".to_string(),
            json!({}),
        );

        assert!(CompiledToolMatcher::Universal.matches(&action));

        let exact = CompiledToolMatcher::compile("file_system:read_file");
        assert!(exact.matches(&action));

        let tool_wild = CompiledToolMatcher::compile("file_system:*");
        assert!(tool_wild.matches(&action));

        let func_wild = CompiledToolMatcher::compile("*:read_file");
        assert!(func_wild.matches(&action));

        let no_match = CompiledToolMatcher::compile("bash:execute");
        assert!(!no_match.matches(&action));

        let tool_only = CompiledToolMatcher::compile("file_system");
        assert!(tool_only.matches(&action));
    }

    #[test]
    fn test_compiled_tool_matcher_qualifier_suffix() {
        // Policy IDs with qualifier suffixes: "tool:func:qualifier" should match on tool:func only
        let action = Action::new(
            "file_system".to_string(),
            "read_file".to_string(),
            json!({}),
        );

        // Qualifier suffixes should be ignored for matching
        let qualified = CompiledToolMatcher::compile("*:*:credential-block");
        assert!(
            qualified.matches(&action),
            "Qualified *:*:qualifier should match any action"
        );

        let tool_qualified = CompiledToolMatcher::compile("file_system:*:blocker");
        assert!(
            tool_qualified.matches(&action),
            "tool:*:qualifier should match matching tool"
        );

        let exact_qualified = CompiledToolMatcher::compile("file_system:read_file:my-rule");
        assert!(
            exact_qualified.matches(&action),
            "tool:func:qualifier should match exact tool:func"
        );

        let no_match_qualified = CompiledToolMatcher::compile("bash:execute:dangerous");
        assert!(
            !no_match_qualified.matches(&action),
            "Non-matching tool:func:qualifier should not match"
        );

        // Legacy IDs without qualifier should still work
        let legacy = CompiledToolMatcher::compile("file_system:read_file");
        assert!(legacy.matches(&action));
    }

    #[test]
    fn test_policy_id_qualifier_e2e_credential_block() {
        // End-to-end: policy with qualified ID blocks credential access
        let policies = vec![
            Policy {
                id: "*:*:credential-block".to_string(),
                name: "Block credential access".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "*",
                            "op": "glob",
                            "pattern": "/home/*/.aws/**",
                            "on_match": "deny"
                        }]
                    }),
                },
                priority: 300,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let cred_action = action_with(
            "file_system",
            "read_file",
            json!({"path": "/home/user/.aws/credentials"}),
        );
        let verdict = engine.evaluate_action(&cred_action, &[]).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Qualified policy ID *:*:credential-block must deny credential access, got: {:?}",
            verdict
        );

        let safe_action = action_with(
            "file_system",
            "read_file",
            json!({"path": "/home/user/project/README.md"}),
        );
        let verdict = engine.evaluate_action(&safe_action, &[]).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Safe path must be allowed, got: {:?}",
            verdict
        );
    }

    // ═══════════════════════════════════════════════════
    // ON_NO_MATCH CONTINUATION TESTS (Adversary Phase 5)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_on_no_match_continue_skips_to_next_policy() {
        // A conditional policy with on_no_match="continue" and no matching constraints
        // should skip to the next policy, not return Allow.
        let policies = vec![
            Policy {
                id: "*:*:scan-policy".to_string(),
                name: "Scan all params".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "*",
                            "op": "glob",
                            "pattern": "/home/*/.aws/**",
                            "on_match": "deny",
                            "on_missing": "skip"
                        }],
                        "on_no_match": "continue"
                    }),
                },
                priority: 300,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        // Compiled path
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with(
            "http_request",
            "get",
            json!({"url": "https://safe.example.com"}),
        );
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "on_no_match=continue must skip to next policy (Deny), got: {:?}",
            verdict
        );

        // Legacy path
        let legacy_engine = PolicyEngine::new(false);
        let verdict = legacy_engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Legacy path: on_no_match=continue must skip to next policy (Deny), got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_on_no_match_default_returns_allow() {
        // Without on_no_match="continue", a conditional policy with no matching constraints
        // should return Allow (the historical default behavior).
        let policies = vec![
            Policy {
                id: "*:*".to_string(),
                name: "Scan all params".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "*",
                            "op": "glob",
                            "pattern": "/home/*/.aws/**",
                            "on_match": "deny",
                            "on_missing": "skip"
                        }]
                    }),
                },
                priority: 300,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        // Compiled path: without on_no_match, first policy returns Allow, blocking the Deny.
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with(
            "http_request",
            "get",
            json!({"url": "https://safe.example.com"}),
        );
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Default (no on_no_match) must return Allow from first policy, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_on_no_match_continue_policy_chain() {
        // Three-policy chain demonstrating layered security with on_no_match="continue":
        // 1. High-priority credential blocker (on_no_match=continue)
        // 2. Mid-priority domain blocker (on_no_match=continue)
        // 3. Low-priority default allow
        let policies = vec![
            Policy {
                id: "*:*:credential-block".to_string(),
                name: "Block credential access".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "*",
                            "op": "glob",
                            "pattern": "/home/*/.aws/**",
                            "on_match": "deny",
                            "on_missing": "skip"
                        }],
                        "on_no_match": "continue"
                    }),
                },
                priority: 300,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*:domain-block".to_string(),
                name: "Block evil domains".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "*",
                            "op": "domain_match",
                            "pattern": "*.evil.com",
                            "on_match": "deny",
                            "on_missing": "skip"
                        }],
                        "on_no_match": "continue"
                    }),
                },
                priority: 280,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Credential access → blocked by policy 1
        let cred_action = action_with(
            "file_system",
            "read",
            json!({"path": "/home/user/.aws/credentials"}),
        );
        let v = engine.evaluate_action(&cred_action, &[]).unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Credentials must be denied: {:?}",
            v
        );

        // Evil domain → skips policy 1, blocked by policy 2
        let evil_action = action_with(
            "http_request",
            "get",
            json!({"url": "https://exfil.evil.com/steal"}),
        );
        let v = engine.evaluate_action(&evil_action, &[]).unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Evil domain must be denied: {:?}",
            v
        );

        // Safe action → skips policies 1 and 2, allowed by policy 3
        let safe_action = action_with(
            "file_system",
            "read",
            json!({"path": "/home/user/project/README.md"}),
        );
        let v = engine.evaluate_action(&safe_action, &[]).unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Safe path must be allowed: {:?}",
            v
        );

        // Verify legacy path parity
        let legacy_engine = PolicyEngine::new(false);

        let v = legacy_engine
            .evaluate_action(&cred_action, &policies)
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Legacy: credentials denied: {:?}",
            v
        );

        let v = legacy_engine
            .evaluate_action(&evil_action, &policies)
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Legacy: evil domain denied: {:?}",
            v
        );

        let v = legacy_engine
            .evaluate_action(&safe_action, &policies)
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Legacy: safe path allowed: {:?}",
            v
        );
    }

    #[test]
    fn test_on_no_match_continue_fail_closed_exception() {
        // When ALL constraints are skipped (missing params, on_missing="skip")
        // AND on_no_match="continue", the engine should skip to next policy,
        // NOT deny (fail-closed exception).
        let policies = vec![
            Policy {
                id: "*:*:scan".to_string(),
                name: "Wildcard scan".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "*",
                            "op": "glob",
                            "pattern": "/home/*/.aws/**",
                            "on_match": "deny",
                            "on_missing": "skip"
                        }],
                        "on_no_match": "continue"
                    }),
                },
                priority: 300,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Empty parameters: all constraints skip → on_no_match=continue → skip → Allow
        let action = action_with("file_system", "list", json!({}));
        let v = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Empty params with on_no_match=continue must skip to Allow, got: {:?}",
            v
        );

        // Legacy path parity
        let legacy_engine = PolicyEngine::new(false);
        let v = legacy_engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Legacy: empty params with on_no_match=continue must skip to Allow, got: {:?}",
            v
        );
    }

    #[test]
    fn test_on_no_match_continue_fail_closed_without_flag() {
        // Without on_no_match="continue", ALL constraints skipped → fail-closed Deny.
        // This is the security-critical default behavior.
        let policies = vec![
            Policy {
                id: "*:*".to_string(),
                name: "Wildcard scan (no continue)".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "*",
                            "op": "glob",
                            "pattern": "/home/*/.aws/**",
                            "on_match": "deny",
                            "on_missing": "skip"
                        }]
                    }),
                },
                priority: 300,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Empty parameters without on_no_match: fail-closed Deny
        let action = action_with("file_system", "list", json!({}));
        let v = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Empty params WITHOUT on_no_match=continue must fail-closed Deny, got: {:?}",
            v
        );
    }

    #[test]
    fn test_on_no_match_invalid_value_treated_as_default() {
        // on_no_match with a non-"continue" value (e.g. "allow", "deny", garbage)
        // should behave identically to the default (no on_no_match).
        let policies = vec![
            Policy {
                id: "*:*".to_string(),
                name: "Bad on_no_match".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "path",
                            "op": "glob",
                            "pattern": "/secret/**",
                            "on_match": "deny"
                        }],
                        "on_no_match": "deny"  // Not a valid value, treated as default
                    }),
                },
                priority: 300,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Non-matching path: first policy returns Allow (default), NOT continue
        let action = action_with("file_system", "read", json!({"path": "/safe/file.txt"}));
        let v = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "on_no_match='deny' (invalid) must behave as default (Allow from first policy), got: {:?}",
            v
        );
    }

    #[test]
    fn test_on_no_match_continue_with_require_approval() {
        // on_no_match="continue" must work correctly with require_approval constraints.
        // If a constraint fires require_approval, it takes effect. If no constraints fire,
        // the policy continues to next.
        let policies = vec![
            Policy {
                id: "*:*:dangerous-cmds".to_string(),
                name: "Dangerous commands require approval".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "command",
                            "op": "regex",
                            "pattern": "(?i)rm\\s+-rf",
                            "on_match": "require_approval"
                        }],
                        "on_no_match": "continue"
                    }),
                },
                priority: 200,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Dangerous command: requires approval
        let dangerous = action_with("bash", "execute", json!({"command": "rm -rf /"}));
        let v = engine.evaluate_action(&dangerous, &[]).unwrap();
        assert!(
            matches!(v, Verdict::RequireApproval { .. }),
            "Dangerous command must require approval: {:?}",
            v
        );

        // Safe command: skips policy 1, allowed by policy 2
        let safe = action_with("bash", "execute", json!({"command": "ls -la"}));
        let v = engine.evaluate_action(&safe, &[]).unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Safe command must be allowed: {:?}",
            v
        );

        // No command param: skips policy 1 (on_missing defaults to deny, BUT
        // the param is missing so constraint evaluates with fail-closed...
        // Actually let's check: without on_missing="skip", missing param fails closed)
        let no_params = action_with("bash", "execute", json!({}));
        let v = engine.evaluate_action(&no_params, &[]).unwrap();
        // Missing "command" param → fail-closed Deny (since on_missing not set to "skip")
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Missing param without on_missing=skip must fail-closed: {:?}",
            v
        );
    }

    #[test]
    fn test_on_no_match_continue_traced_evaluation() {
        // Traced evaluation path must also respect on_no_match="continue".
        let policies = vec![
            Policy {
                id: "*:*:scan".to_string(),
                name: "Credential scan".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({
                        "parameter_constraints": [{
                            "param": "*",
                            "op": "glob",
                            "pattern": "/home/*/.ssh/**",
                            "on_match": "deny",
                            "on_missing": "skip"
                        }],
                        "on_no_match": "continue"
                    }),
                },
                priority: 300,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*:*".to_string(),
                name: "Default allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];

        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Safe action with trace enabled
        let safe_action = action_with("editor", "open", json!({"file": "/tmp/test.txt"}));
        let (verdict, trace) = engine.evaluate_action_traced(&safe_action).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Traced: safe action must be allowed: {:?}",
            verdict
        );
        // Verify trace captured the policy evaluation
        assert!(
            !trace.matches.is_empty(),
            "Trace must contain policy match results"
        );
    }

    #[test]
    fn test_on_no_match_continue_strict_mode_accepts_key() {
        // Strict mode must recognize "on_no_match" as a valid condition key.
        let policies = vec![Policy {
            id: "*:*".to_string(),
            name: "Strict scan".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/secret/**",
                        "on_match": "deny"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];

        // Strict mode: should NOT reject on_no_match as unknown key
        let result = PolicyEngine::with_policies(true, &policies);
        assert!(
            result.is_ok(),
            "Strict mode must accept 'on_no_match' as a valid condition key: {:?}",
            result.err()
        );

        // Also test legacy strict mode
        let legacy_engine = PolicyEngine::new(true);
        let action = action_with("file_system", "read", json!({"path": "/safe/file.txt"}));
        let result = legacy_engine.evaluate_action(&action, &policies);
        assert!(
            result.is_ok(),
            "Legacy strict mode must accept 'on_no_match': {:?}",
            result.err()
        );
    }

    // ═══════════════════════════════════════════════════
    // TOOL INDEX TESTS (Phase 10.5)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_tool_index_is_populated() {
        let policies = vec![
            Policy {
                id: "bash:*".to_string(),
                name: "Block bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 200,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "file_system:read_file".to_string(),
                name: "Block file read".to_string(),
                policy_type: PolicyType::Deny,
                priority: 150,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
                path_rules: None,
                network_rules: None,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        assert!(engine.tool_index.contains_key("bash"));
        assert!(engine.tool_index.contains_key("file_system"));
        assert_eq!(engine.tool_index.len(), 2);
        assert_eq!(engine.always_check.len(), 1);
    }

    #[test]
    fn test_tool_index_prefix_goes_to_always_check() {
        let policies = vec![
            Policy {
                id: "file*:read".to_string(),
                name: "Prefix tool".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Exact tool".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        assert!(engine.tool_index.contains_key("bash"));
        assert_eq!(engine.always_check.len(), 1);
    }

    #[test]
    fn test_tool_index_evaluation_matches_linear_scan() {
        let mut policies = Vec::new();
        for i in 0..50 {
            policies.push(Policy {
                id: format!("tool_{}:func", i),
                name: format!("Policy {}", i),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            });
        }
        policies.push(Policy {
            id: "*".to_string(),
            name: "Default allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        });

        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Indexed policy matches → deny
        let action_deny = action_with("tool_5", "func", json!({}));
        assert!(matches!(
            engine.evaluate_action(&action_deny, &[]).unwrap(),
            Verdict::Deny { .. }
        ));

        // No indexed policy matches → falls through to universal allow
        let action_allow = action_with("tool_99", "func", json!({}));
        assert!(matches!(
            engine.evaluate_action(&action_allow, &[]).unwrap(),
            Verdict::Allow
        ));

        // Indexed tool but wrong function → falls through to universal allow
        let action_other = action_with("tool_5", "other_func", json!({}));
        assert!(matches!(
            engine.evaluate_action(&action_other, &[]).unwrap(),
            Verdict::Allow
        ));
    }

    #[test]
    fn test_tool_index_priority_order_preserved() {
        let policies = vec![
            Policy {
                id: "bash:*".to_string(),
                name: "Allow bash".to_string(),
                policy_type: PolicyType::Allow,
                priority: 200,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Deny bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with("bash", "run", json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_tool_index_universal_interleaves_with_indexed() {
        let policies = vec![
            Policy {
                id: "bash:safe".to_string(),
                name: "Allow safe bash".to_string(),
                policy_type: PolicyType::Allow,
                priority: 200,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*".to_string(),
                name: "Universal deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: 150,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Allow all bash".to_string(),
                policy_type: PolicyType::Allow,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // bash:safe → allowed by priority 200 indexed policy
        let safe = action_with("bash", "safe", json!({}));
        assert!(matches!(
            engine.evaluate_action(&safe, &[]).unwrap(),
            Verdict::Allow
        ));

        // bash:run → universal deny at 150 fires before bash:* allow at 100
        let run = action_with("bash", "run", json!({}));
        assert!(matches!(
            engine.evaluate_action(&run, &[]).unwrap(),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_tool_index_empty_policies() {
        let engine = PolicyEngine::with_policies(false, &[]).unwrap();
        assert!(engine.tool_index.is_empty());
        assert!(engine.always_check.is_empty());

        let action = action_with("any", "func", json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    // ═══════════════════════════════════════════════════
    // EVALUATION TRACE TESTS (Phase 10.4)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_traced_allow_simple() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with("bash", "execute", json!({"command": "ls"}));

        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
        assert_eq!(trace.verdict, Verdict::Allow);
        assert_eq!(trace.policies_checked, 1);
        assert_eq!(trace.policies_matched, 1);
        assert_eq!(trace.action_summary.tool, "bash");
        assert_eq!(trace.action_summary.function, "execute");
        assert_eq!(trace.action_summary.param_count, 1);
        assert!(trace
            .action_summary
            .param_keys
            .contains(&"command".to_string()));
        assert_eq!(trace.matches.len(), 1);
        assert_eq!(trace.matches[0].policy_name, "Allow all");
        assert!(trace.matches[0].tool_matched);
    }

    #[test]
    fn test_traced_deny_simple() {
        let policies = vec![Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with("bash", "execute", json!({}));

        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
        assert_eq!(trace.policies_matched, 1);
        assert_eq!(trace.matches[0].policy_type, "deny");
        assert!(trace.matches[0].verdict_contribution.is_some());
    }

    #[test]
    fn test_traced_no_policies() {
        let engine = PolicyEngine::with_policies(false, &[]).unwrap();
        let action = action_with("bash", "execute", json!({}));

        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
        assert_eq!(trace.policies_checked, 0);
        assert_eq!(trace.matches.len(), 0);
    }

    #[test]
    fn test_traced_no_matching_policy() {
        // Use a wildcard-prefix policy so it's in always_check (not skipped by tool index)
        let policies = vec![Policy {
            id: "git*".to_string(),
            name: "Allow git".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with("bash", "execute", json!({}));

        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { reason } if reason == "No matching policy"));
        assert_eq!(trace.policies_checked, 1);
        assert_eq!(trace.policies_matched, 0);
        assert!(!trace.matches[0].tool_matched);
    }

    #[test]
    fn test_traced_forbidden_parameter() {
        let policies = vec![Policy {
            id: "bash:*".to_string(),
            name: "Bash safe".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "forbidden_parameters": ["force", "sudo"]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // With forbidden param present
        let action = action_with("bash", "exec", json!({"command": "ls", "force": true}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
        let constraint_results = &trace.matches[0].constraint_results;
        assert!(!constraint_results.is_empty());
        let forbidden = constraint_results
            .iter()
            .find(|c| c.param == "force")
            .unwrap();
        assert_eq!(forbidden.constraint_type, "forbidden_parameter");
        assert!(
            forbidden.actual.starts_with("present: "),
            "actual should contain type info, got: {}",
            forbidden.actual
        );
        assert!(!forbidden.passed);
    }

    #[test]
    fn test_traced_constraint_result_type_info() {
        let policies = vec![Policy {
            id: "bash:*".to_string(),
            name: "Bash forbidden check".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "forbidden_parameters": ["force"],
                    "required_parameters": ["command"]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Test forbidden parameter with string value
        let action = action_with(
            "bash",
            "exec",
            json!({"command": "ls -la", "force": "please"}),
        );
        let (_verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        let results = &trace.matches[0].constraint_results;
        let forbidden = results.iter().find(|c| c.param == "force").unwrap();
        assert_eq!(forbidden.actual, "present: string(6 chars)");

        // Test forbidden parameter with object value
        let action2 = action_with(
            "bash",
            "exec",
            json!({"command": "ls", "force": {"level": 1, "recursive": true}}),
        );
        let (_verdict2, trace2) = engine.evaluate_action_traced(&action2).unwrap();
        let results2 = &trace2.matches[0].constraint_results;
        let forbidden2 = results2.iter().find(|c| c.param == "force").unwrap();
        assert_eq!(forbidden2.actual, "present: object(2 keys)");

        // Test required parameter present (should have type info too)
        let action3 = action_with("bash", "exec", json!({"command": "ls"}));
        let (_verdict3, trace3) = engine.evaluate_action_traced(&action3).unwrap();
        let results3 = &trace3.matches[0].constraint_results;
        let required = results3
            .iter()
            .find(|c| c.param == "command" && c.constraint_type == "required_parameter")
            .unwrap();
        assert_eq!(required.actual, "present: string(2 chars)");
        assert!(required.passed);

        // Test required parameter absent
        let action4 = action_with("bash", "exec", json!({"other": "value"}));
        let (_verdict4, trace4) = engine.evaluate_action_traced(&action4).unwrap();
        let results4 = &trace4.matches[0].constraint_results;
        // forbidden_parameter "force" should show absent
        let absent = results4
            .iter()
            .find(|c| c.param == "force" && c.constraint_type == "forbidden_parameter")
            .unwrap();
        assert_eq!(absent.actual, "absent");
        assert!(absent.passed);
    }

    #[test]
    fn test_traced_constraint_glob() {
        let policies = vec![Policy {
            id: "file:*".to_string(),
            name: "Allow safe paths".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/etc/**",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with("file", "read", json!({"path": "/etc/passwd"}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let constraint_results = &trace.matches[0].constraint_results;
        let glob_result = constraint_results
            .iter()
            .find(|c| c.constraint_type == "glob")
            .unwrap();
        assert_eq!(glob_result.param, "path");
        assert!(!glob_result.passed);
    }

    #[test]
    fn test_traced_require_approval() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Needs approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({"require_approval": true}),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with("bash", "exec", json!({}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));
        assert_eq!(
            trace.matches[0].constraint_results[0].constraint_type,
            "require_approval"
        );
    }

    #[test]
    fn test_traced_multiple_policies_first_match_wins() {
        let policies = vec![
            Policy {
                id: "bash:*".to_string(),
                name: "Block bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with("bash", "execute", json!({}));

        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
        // Only the matching policy should be in the trace (first match stops)
        assert_eq!(trace.policies_checked, 1);
        assert_eq!(trace.matches.len(), 1);
    }

    #[test]
    fn test_traced_duration_recorded() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with("bash", "execute", json!({}));

        let (_, trace) = engine.evaluate_action_traced(&action).unwrap();
        // Duration should be recorded (at least 0, could be 0 for very fast evaluation)
        assert!(trace.duration_us < 1_000_000); // Should be well under 1 second
    }

    #[test]
    fn test_traced_all_skipped_fail_closed() {
        // Exploit #2 regression: when all constraints skip due to missing params,
        // the traced path should emit an "all_skipped_fail_closed" constraint result.
        let policies = vec![Policy {
            id: "file:*".to_string(),
            name: "Block secrets".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/etc/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Call with NO "path" parameter — all constraints skip
        let action = action_with("file", "read", json!({}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        // Trace should contain the all_skipped_fail_closed constraint
        let constraint_results = &trace.matches[0].constraint_results;
        let fail_closed = constraint_results
            .iter()
            .find(|c| c.constraint_type == "all_skipped_fail_closed");
        assert!(
            fail_closed.is_some(),
            "Trace must include all_skipped_fail_closed constraint when all params missing"
        );
        let fc = fail_closed.unwrap();
        assert!(!fc.passed);
        assert!(fc.actual.contains("skipped"));
    }

    #[test]
    fn test_traced_domain_match_constraint() {
        // Verify domain_match constraint details appear in trace
        let policies = vec![Policy {
            id: "http:*".to_string(),
            name: "Block evil".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "url",
                        "op": "domain_match",
                        "pattern": "evil.com",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with("http", "get", json!({"url": "https://evil.com/exfil"}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let constraint_results = &trace.matches[0].constraint_results;
        let domain_result = constraint_results
            .iter()
            .find(|c| c.constraint_type == "domain_match")
            .expect("Trace must contain domain_match constraint");
        assert_eq!(domain_result.param, "url");
        assert!(!domain_result.passed);
    }

    #[test]
    fn test_traced_verdict_consistency() {
        // The verdict returned from the function must match the verdict in the trace
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with("test", "fn", json!({}));

        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert_eq!(
            format!("{:?}", verdict),
            format!("{:?}", trace.verdict),
            "Returned verdict must match trace verdict"
        );

        // Also test with deny
        let policies_deny = vec![Policy {
            id: "test:*".to_string(),
            name: "Block test".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine_deny = PolicyEngine::with_policies(false, &policies_deny).unwrap();
        let (verdict_d, trace_d) = engine_deny.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict_d, Verdict::Deny { .. }));
        assert!(matches!(trace_d.verdict, Verdict::Deny { .. }));
    }

    /// R17-ENGINE-1: The traced evaluation path must enforce IP rules.
    /// Previously, `apply_compiled_policy_traced_ctx` was missing the
    /// `check_ip_rules` call, allowing `?trace=true` to bypass IP blocking.
    #[test]
    fn test_traced_ip_rules_enforced() {
        use sentinel_types::IpRules;

        let policies = vec![Policy {
            id: "http:*".to_string(),
            name: "Allow with IP block".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: Some(sentinel_types::NetworkRules {
                allowed_domains: vec!["example.com".to_string()],
                blocked_domains: vec![],
                ip_rules: Some(IpRules {
                    block_private: true,
                    allowed_cidrs: vec![],
                    blocked_cidrs: vec![],
                }),
            }),
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Action with a private IP (loopback) that resolves for a domain
        let mut action = action_with("http", "get", json!({}));
        action.target_domains = vec!["example.com".to_string()];
        action.resolved_ips = vec!["127.0.0.1".to_string()];

        // Non-traced path should deny
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Non-traced path must deny private IP. Got: {:?}",
            verdict
        );

        // Traced path must also deny (was previously bypassed)
        let (traced_verdict, _trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(
            matches!(traced_verdict, Verdict::Deny { .. }),
            "Traced path must deny private IP (R17-ENGINE-1 regression). Got: {:?}",
            traced_verdict
        );
    }

    // ═══════════════════════════════════════════════════
    // PATH/NETWORK RULES TESTS (Phase 3E)
    // ═══════════════════════════════════════════════════

    use sentinel_types::{NetworkRules, PathRules};

    fn policy_with_path_rules(
        id: &str,
        name: &str,
        policy_type: PolicyType,
        path_rules: PathRules,
    ) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            policy_type,
            priority: 100,
            path_rules: Some(path_rules),
            network_rules: None,
        }
    }

    fn policy_with_network_rules(
        id: &str,
        name: &str,
        policy_type: PolicyType,
        network_rules: NetworkRules,
    ) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            policy_type,
            priority: 100,
            path_rules: None,
            network_rules: Some(network_rules),
        }
    }

    fn action_with_paths(tool: &str, function: &str, paths: Vec<&str>) -> Action {
        let mut action = Action::new(tool, function, json!({}));
        action.target_paths = paths.into_iter().map(|s| s.to_string()).collect();
        action
    }

    fn action_with_domains(tool: &str, function: &str, domains: Vec<&str>) -> Action {
        let mut action = Action::new(tool, function, json!({}));
        action.target_domains = domains.into_iter().map(|s| s.to_string()).collect();
        action
    }

    #[test]
    fn test_path_rules_blocked_denies() {
        let policies = vec![policy_with_path_rules(
            "file:*",
            "Block sensitive paths",
            PolicyType::Allow,
            PathRules {
                allowed: vec![],
                blocked: vec!["/home/*/.aws/**".to_string(), "/etc/shadow".to_string()],
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_paths("file", "read", vec!["/home/user/.aws/credentials"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked")),
            "Blocked path should deny, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_path_rules_blocked_exact_match_denies() {
        let policies = vec![policy_with_path_rules(
            "file:*",
            "Block etc shadow",
            PolicyType::Allow,
            PathRules {
                allowed: vec![],
                blocked: vec!["/etc/shadow".to_string()],
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_paths("file", "read", vec!["/etc/shadow"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_path_rules_allowed_only_safe_paths() {
        let policies = vec![policy_with_path_rules(
            "file:*",
            "Allow only tmp",
            PolicyType::Allow,
            PathRules {
                allowed: vec!["/tmp/**".to_string()],
                blocked: vec![],
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Allowed path
        let action_ok = action_with_paths("file", "read", vec!["/tmp/safe.txt"]);
        let verdict = engine.evaluate_action(&action_ok, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Path in allowed list should be allowed, got: {:?}",
            verdict
        );

        // Disallowed path
        let action_bad = action_with_paths("file", "read", vec!["/etc/passwd"]);
        let verdict = engine.evaluate_action(&action_bad, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("not in allowed")),
            "Path not in allowed list should deny, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_path_rules_blocked_takes_precedence_over_allowed() {
        let policies = vec![policy_with_path_rules(
            "file:*",
            "Allow tmp but block secrets",
            PolicyType::Allow,
            PathRules {
                allowed: vec!["/tmp/**".to_string()],
                blocked: vec!["/tmp/secrets/**".to_string()],
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_paths("file", "read", vec!["/tmp/secrets/key.pem"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked")),
            "Blocked pattern should take precedence even if path matches allowed, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_path_rules_normalization_prevents_bypass() {
        let policies = vec![policy_with_path_rules(
            "file:*",
            "Block aws creds",
            PolicyType::Allow,
            PathRules {
                allowed: vec![],
                blocked: vec!["/home/*/.aws/**".to_string()],
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        // Attempt traversal bypass
        let action = action_with_paths(
            "file",
            "read",
            vec!["/home/user/docs/../../user/.aws/credentials"],
        );
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Path traversal should be normalized and still blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_path_rules_no_paths_in_action_allows() {
        let policies = vec![policy_with_path_rules(
            "file:*",
            "Block secrets",
            PolicyType::Allow,
            PathRules {
                allowed: vec![],
                blocked: vec!["/etc/shadow".to_string()],
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        // No target_paths in action → path rules don't apply
        let action = action_with("file", "read", json!({"path": "/etc/shadow"}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "With no target_paths, path rules should not block, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_network_rules_blocked_domain_denies() {
        let policies = vec![policy_with_network_rules(
            "http:*",
            "Block evil domains",
            PolicyType::Allow,
            NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec!["evil.com".to_string(), "*.malware.org".to_string()],
                ip_rules: None,
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with_domains("http", "get", vec!["evil.com"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked")),
            "Blocked domain should deny, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_network_rules_blocked_subdomain_denies() {
        let policies = vec![policy_with_network_rules(
            "http:*",
            "Block malware subdomains",
            PolicyType::Allow,
            NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec!["*.malware.org".to_string()],
                ip_rules: None,
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with_domains("http", "get", vec!["data.malware.org"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_network_rules_allowed_only() {
        let policies = vec![policy_with_network_rules(
            "http:*",
            "Only allow trusted domains",
            PolicyType::Allow,
            NetworkRules {
                allowed_domains: vec!["api.example.com".to_string(), "*.trusted.net".to_string()],
                blocked_domains: vec![],
                ip_rules: None,
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Allowed domain
        let action_ok = action_with_domains("http", "get", vec!["api.example.com"]);
        let verdict = engine.evaluate_action(&action_ok, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));

        // Disallowed domain
        let action_bad = action_with_domains("http", "get", vec!["evil.com"]);
        let verdict = engine.evaluate_action(&action_bad, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("not in allowed")),
            "Domain not in allowed list should deny, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_network_rules_no_domains_in_action_allows() {
        let policies = vec![policy_with_network_rules(
            "http:*",
            "Block evil",
            PolicyType::Allow,
            NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec!["evil.com".to_string()],
                ip_rules: None,
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with("http", "get", json!({"url": "https://evil.com/data"}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "With no target_domains, network rules should not block, got: {:?}",
            verdict
        );
    }

    // ═══════════════════════════════════════════════════
    // IP RULES (DNS REBINDING PROTECTION)
    // ═══════════════════════════════════════════════════

    fn policy_with_ip_rules(ip_rules: sentinel_types::IpRules) -> Policy {
        Policy {
            id: "http:*".to_string(),
            name: "IP-controlled policy".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: Some(NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec![],
                ip_rules: Some(ip_rules),
            }),
        }
    }

    fn action_with_resolved_ips(domains: Vec<&str>, ips: Vec<&str>) -> Action {
        let mut action = Action::new("http", "get", json!({}));
        action.target_domains = domains.into_iter().map(|s| s.to_string()).collect();
        action.resolved_ips = ips.into_iter().map(|s| s.to_string()).collect();
        action
    }

    #[test]
    fn test_ip_rules_block_private_loopback() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["127.0.0.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "Loopback 127.0.0.1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_rfc1918() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        for ip in &["10.0.0.1", "172.16.0.1", "192.168.1.1"] {
            let action = action_with_resolved_ips(vec!["example.com"], vec![ip]);
            let verdict = engine.evaluate_action(&action, &policies).unwrap();
            assert!(
                matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
                "RFC 1918 address {} should be blocked, got: {:?}",
                ip,
                verdict
            );
        }
    }

    #[test]
    fn test_ip_rules_block_private_link_local() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["169.254.1.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "Link-local 169.254.x should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv6_loopback() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["::1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "IPv6 loopback ::1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv4_mapped_v6() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["::ffff:127.0.0.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "IPv4-mapped v6 ::ffff:127.0.0.1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv6_ula() {
        // fc00::/7 — Unique Local Address (RFC 4193)
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["fc00::1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "ULA fc00::1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv6_link_local() {
        // fe80::/10 — Link-Local
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["fe80::1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "Link-local fe80::1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv6_multicast() {
        // ff00::/8 — Multicast
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["ff02::1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "Multicast ff02::1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv6_documentation() {
        // 2001:db8::/32 — Documentation
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["2001:db8::1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "Documentation 2001:db8::1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_6to4_embedded() {
        // 2002:c0a8:0101:: embeds 192.168.1.1 (private)
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["2002:c0a8:0101::1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "6to4 with embedded private IP should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_teredo_embedded() {
        // 2001:0000:... with embedded private IPv4 in last 32 bits (XORed)
        // Embedded 192.168.1.1 → XOR 0xFFFF → 3f:57:fe:fe at positions 6-7
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        // Teredo encoding: 192.168.1.1 XOR 0xFFFF each byte → 63.87.254.254
        let action = action_with_resolved_ips(vec!["example.com"], vec!["2001:0000:0000:0000:0000:0000:3f57:fefe"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "Teredo with embedded private IP should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_nat64_embedded() {
        // 64:ff9b::192.168.1.1 — NAT64 with embedded private IPv4
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["64:ff9b::c0a8:0101"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "NAT64 with embedded private IP should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv4_compatible_v6() {
        // SECURITY (R21-ENG-2): ::10.0.0.1 (IPv4-compatible, deprecated) embeds
        // a private IPv4. Must be blocked to prevent DNS rebinding.
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["::10.0.0.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "IPv4-compatible ::10.0.0.1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv4_compatible_loopback() {
        // ::127.0.0.1 is IPv4-compatible loopback — must be blocked
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["::127.0.0.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "IPv4-compatible ::127.0.0.1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_6to4_cgnat() {
        // SECURITY (R22-ENG-2): 6to4 embedding CGNAT address 100.100.1.1
        // 2002:6464:0101:: — previously not blocked because 6to4 only checked
        // is_loopback/is_private/is_link_local (CGNAT is none of those).
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["2002:6464:0101::1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "6to4 with embedded CGNAT should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_nat64_cgnat() {
        // SECURITY (R22-ENG-2): NAT64 embedding CGNAT address 100.100.1.1
        // 64:ff9b::6464:0101
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["64:ff9b::6464:0101"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "NAT64 with embedded CGNAT should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_nat64_local_use() {
        // SECURITY (R25-ENG-2): NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215)
        // with embedded private IPv4 192.168.1.1 = c0a8:0101
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(
            vec!["example.com"],
            vec!["64:ff9b:1:0:0:0:c0a8:0101"],
        );
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "NAT64 local-use with embedded private IPv4 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_allow_nat64_local_use_public() {
        // NAT64 local-use with embedded public IPv4 should be allowed
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(
            vec!["example.com"],
            vec!["64:ff9b:1:0:0:0:0808:0808"], // 8.8.8.8
        );
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "NAT64 local-use with public IPv4 should be allowed, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_teredo_cgnat() {
        // SECURITY (R22-ENG-2): Teredo embedding CGNAT address 100.100.1.1
        // XOR with 0xFF: 100^0xFF=155, 100^0xFF=155, 1^0xFF=254, 1^0xFF=254
        // Embedded in last 32 bits as 0x9b9b:0xfefe
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["2001:0000:0000:0000:0000:0000:9b9b:fefe"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "Teredo with embedded CGNAT should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_private_ipv4_mapped_cgnat() {
        // SECURITY (R22-ENG-2): IPv4-mapped embedding CGNAT address
        // ::ffff:100.100.1.1
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["::ffff:100.100.1.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "IPv4-mapped with embedded CGNAT should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_cgnat_range() {
        // SECURITY (R21-ENG-3): 100.64.0.0/10 (CGNAT, RFC 6598) must be blocked
        // by block_private. In cloud environments this can reach metadata services.
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["100.100.1.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "CGNAT 100.100.1.1 should be blocked by block_private, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_class_e_reserved() {
        // SECURITY (R23-ENG-3): 240.0.0.0/4 (Class E / Reserved) must be blocked
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["240.0.0.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "Class E 240.0.0.1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_6to4_relay_anycast() {
        // SECURITY (R23-ENG-3): 192.88.99.0/24 (deprecated 6to4 relay anycast) must be blocked
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["192.88.99.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "6to4 relay 192.88.99.1 should be blocked, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_block_zero_network() {
        // 0.x.x.x (RFC 1122 "this host on this network") must be blocked
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["0.1.2.3"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "0.1.2.3 should be blocked by block_private, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_allow_public_ip() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["8.8.8.8"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Public IP 8.8.8.8 should be allowed, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_blocked_cidr() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: false,
            blocked_cidrs: vec!["100.64.0.0/10".to_string()],
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // IP in blocked CIDR -> deny
        let action = action_with_resolved_ips(vec!["example.com"], vec!["100.100.1.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked CIDR")),
            "IP in blocked CIDR should be denied, got: {:?}",
            verdict
        );

        // IP outside blocked CIDR -> allow
        let action = action_with_resolved_ips(vec!["example.com"], vec!["8.8.8.8"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "IP outside blocked CIDR should be allowed, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_allowed_cidr() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: false,
            allowed_cidrs: vec!["203.0.113.0/24".to_string()],
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // IP in allowed CIDR -> allow
        let action = action_with_resolved_ips(vec!["example.com"], vec!["203.0.113.50"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "IP in allowed CIDR should pass, got: {:?}",
            verdict
        );

        // IP not in allowed CIDR -> deny
        let action = action_with_resolved_ips(vec!["example.com"], vec!["8.8.8.8"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("not in allowed")),
            "IP outside allowed CIDR should be denied, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_no_resolved_ips_with_domains_denies() {
        // Fail-closed: domains present but no resolved IPs -> deny
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let mut action = Action::new("http", "get", json!({}));
        action.target_domains = vec!["example.com".to_string()];
        // resolved_ips intentionally left empty
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("no resolved IPs")),
            "Missing resolved IPs should fail-closed, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_no_domains_no_resolved_ips_passes() {
        // No targets at all -> IP rules should not interfere
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = Action::new("http", "get", json!({}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "No targets should pass IP rules, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_invalid_cidr_compile_error() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: false,
            blocked_cidrs: vec!["not-a-cidr".to_string()],
            ..Default::default()
        })];
        let result = PolicyEngine::with_policies(false, &policies);
        assert!(
            result.is_err(),
            "Invalid CIDR should cause compile error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_ip_rules_none_skips_check() {
        // No ip_rules -> backward compatible, no IP checking
        let policies = vec![policy_with_network_rules(
            "http:*",
            "Domain only",
            PolicyType::Allow,
            NetworkRules {
                allowed_domains: vec!["example.com".to_string()],
                blocked_domains: vec![],
                ip_rules: None,
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_domains("http", "get", vec!["example.com"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "No ip_rules should not affect domain-only evaluation, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_invalid_resolved_ip_denies() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_resolved_ips(vec!["example.com"], vec!["not-an-ip"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("Invalid resolved IP")),
            "Unparseable IP should be denied, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_ipv4_mapped_v6_blocked_by_v4_cidr() {
        // R24-ENG-1: IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) must be
        // canonicalized to IPv4 before CIDR matching, otherwise an attacker
        // can bypass IPv4 CIDR blocklists by using the mapped form.
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: false,
            blocked_cidrs: vec!["100.64.0.0/10".to_string()],
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // IPv4-mapped IPv6 form of CGNAT address -> should be denied
        let action =
            action_with_resolved_ips(vec!["example.com"], vec!["::ffff:100.100.1.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked CIDR")),
            "IPv4-mapped IPv6 in blocked CIDR should be denied, got: {:?}",
            verdict
        );

        // Regular IPv4 in same CIDR -> also denied (baseline)
        let action = action_with_resolved_ips(vec!["example.com"], vec!["100.100.1.1"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked CIDR")),
            "Plain IPv4 in blocked CIDR should be denied, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_ip_rules_ipv4_mapped_v6_allowed_cidr() {
        // R24-ENG-1: IPv4-mapped IPv6 must also match IPv4 allowed CIDRs
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: false,
            allowed_cidrs: vec!["203.0.113.0/24".to_string()],
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Mapped form of allowed IP -> should pass
        let action =
            action_with_resolved_ips(vec!["example.com"], vec!["::ffff:203.0.113.50"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "IPv4-mapped IPv6 in allowed CIDR should pass, got: {:?}",
            verdict
        );

        // Mapped form of non-allowed IP -> denied
        let action =
            action_with_resolved_ips(vec!["example.com"], vec!["::ffff:8.8.8.8"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("not in allowed")),
            "IPv4-mapped IPv6 outside allowed CIDR should be denied, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_has_ip_rules_returns_true_when_configured() {
        let policies = vec![policy_with_ip_rules(sentinel_types::IpRules {
            block_private: true,
            ..Default::default()
        })];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        assert!(
            engine.has_ip_rules(),
            "Engine with ip_rules should return true"
        );
    }

    #[test]
    fn test_has_ip_rules_returns_false_when_not_configured() {
        let policies = vec![Policy {
            id: "http:*".to_string(),
            name: "No IP rules".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        assert!(
            !engine.has_ip_rules(),
            "Engine without ip_rules should return false"
        );
    }

    #[test]
    fn test_path_rules_with_deny_policy_still_denies() {
        // Even a Deny policy should deny on path rules (path check is pre-dispatch)
        let policies = vec![Policy {
            id: "file:*".to_string(),
            name: "Deny all files".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: Some(PathRules {
                allowed: vec![],
                blocked: vec!["/etc/**".to_string()],
            }),
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_paths("file", "read", vec!["/etc/passwd"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_multiple_paths_one_blocked_denies_all() {
        let policies = vec![policy_with_path_rules(
            "file:*",
            "Block secrets",
            PolicyType::Allow,
            PathRules {
                allowed: vec![],
                blocked: vec!["/etc/shadow".to_string()],
            },
        )];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with_paths("file", "read", vec!["/tmp/safe.txt", "/etc/shadow"]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "If any path is blocked, entire action should be denied, got: {:?}",
            verdict
        );
    }

    #[test]
    fn test_path_and_network_rules_combined() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Combined rules".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: Some(PathRules {
                allowed: vec!["/tmp/**".to_string()],
                blocked: vec![],
            }),
            network_rules: Some(NetworkRules {
                allowed_domains: vec!["api.safe.com".to_string()],
                blocked_domains: vec![],
                ip_rules: None,
            }),
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Bad path, good domain
        let mut action1 = Action::new("tool", "func", json!({}));
        action1.target_paths = vec!["/etc/passwd".to_string()];
        action1.target_domains = vec!["api.safe.com".to_string()];
        let verdict = engine.evaluate_action(&action1, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        // Good path, bad domain
        let mut action2 = Action::new("tool", "func", json!({}));
        action2.target_paths = vec!["/tmp/file.txt".to_string()];
        action2.target_domains = vec!["evil.com".to_string()];
        let verdict = engine.evaluate_action(&action2, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        // Good path, good domain
        let mut action3 = Action::new("tool", "func", json!({}));
        action3.target_paths = vec!["/tmp/file.txt".to_string()];
        action3.target_domains = vec!["api.safe.com".to_string()];
        let verdict = engine.evaluate_action(&action3, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    // ═══════════════════════════════════════════════════
    // PROPERTY-BASED TESTS (proptest)
    // ═══════════════════════════════════════════════════

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        // ── Strategy definitions ──────────────────────────────

        fn arb_tool_name() -> impl Strategy<Value = String> {
            "[a-z_]{1,20}"
        }

        fn arb_function_name() -> impl Strategy<Value = String> {
            "[a-z_]{1,20}"
        }

        fn arb_params() -> impl Strategy<Value = serde_json::Value> {
            proptest::collection::vec(("[a-z_]{1,10}", "[a-zA-Z0-9_]{0,20}"), 0..=5).prop_map(
                |pairs| {
                    let map: serde_json::Map<String, serde_json::Value> = pairs
                        .into_iter()
                        .map(|(k, v)| (k, serde_json::Value::String(v)))
                        .collect();
                    serde_json::Value::Object(map)
                },
            )
        }

        fn arb_action() -> impl Strategy<Value = Action> {
            (arb_tool_name(), arb_function_name(), arb_params())
                .prop_map(|(tool, function, parameters)| Action::new(tool, function, parameters))
        }

        fn arb_path() -> impl Strategy<Value = String> {
            proptest::collection::vec(
                prop_oneof!["[a-z]{1,8}", Just("..".to_string()), Just(".".to_string()),],
                1..=6,
            )
            .prop_map(|segments| format!("/{}", segments.join("/")))
        }

        // ── Core Invariants ──────────────────────────────────

        proptest! {
                    /// evaluate_action called twice on the same input produces the same verdict.
                    #[test]
                    fn prop_evaluate_deterministic(action in arb_action()) {
                        let engine = PolicyEngine::new(false);
                        let policies = vec![
                            Policy {
                                id: "test:*".to_string(),
                                name: "Allow test".to_string(),
                                policy_type: PolicyType::Allow,
                                priority: 100,
                                path_rules: None,
                                network_rules: None,
        },
                        ];
                        let v1 = engine.evaluate_action(&action, &policies).unwrap();
                        let v2 = engine.evaluate_action(&action, &policies).unwrap();
                        prop_assert_eq!(
                            format!("{:?}", v1),
                            format!("{:?}", v2),
                            "evaluate_action must be deterministic"
                        );
                    }

                    /// Compiled path: evaluate_with_compiled called twice produces same verdict.
                    #[test]
                    fn prop_compiled_deterministic(action in arb_action()) {
                        let policies = vec![
                            Policy {
                                id: "*".to_string(),
                                name: "Allow all".to_string(),
                                policy_type: PolicyType::Allow,
                                priority: 50,
                                path_rules: None,
                                network_rules: None,
        },
                        ];
                        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
                        let v1 = engine.evaluate_action(&action, &[]).unwrap();
                        let v2 = engine.evaluate_action(&action, &[]).unwrap();
                        prop_assert_eq!(
                            format!("{:?}", v1),
                            format!("{:?}", v2),
                            "compiled evaluate must be deterministic"
                        );
                    }

                    /// Empty policy set always produces Deny (fail-closed).
                    #[test]
                    fn prop_empty_policies_deny(action in arb_action()) {
                        let engine = PolicyEngine::new(false);
                        let verdict = engine.evaluate_action(&action, &[]).unwrap();
                        prop_assert!(
                            matches!(verdict, Verdict::Deny { .. }),
                            "empty policies must deny, got {:?}",
                            verdict
                        );
                    }

                    /// Non-matching policies produce Deny (fail-closed).
                    #[test]
                    fn prop_no_match_denies(
                        tool in arb_tool_name(),
                        function in arb_function_name(),
                    ) {
                        let engine = PolicyEngine::new(false);
                        let action = Action::new(tool, function, json!({}));
                        // Policy for a tool name that can never match [a-z_]{1,20}
                        let policies = vec![Policy {
                            id: "ZZZZZ-NEVER-MATCHES:nope".to_string(),
                            name: "Unreachable".to_string(),
                            policy_type: PolicyType::Allow,
                            priority: 100,
                            path_rules: None,
                            network_rules: None,
                        }];
                        let verdict = engine.evaluate_action(&action, &policies).unwrap();
                        prop_assert!(
                            matches!(verdict, Verdict::Deny { .. }),
                            "non-matching policies must deny, got {:?}",
                            verdict
                        );
                    }

                    /// Wildcard policy `*` matches any tool/function.
                    #[test]
                    fn prop_wildcard_matches_all(action in arb_action()) {
                        let policies = vec![Policy {
                            id: "*".to_string(),
                            name: "Wildcard".to_string(),
                            policy_type: PolicyType::Allow,
                            priority: 100,
                            path_rules: None,
                            network_rules: None,
        }];
                        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
                        let verdict = engine.evaluate_action(&action, &[]).unwrap();
                        prop_assert!(
                            matches!(verdict, Verdict::Allow),
                            "wildcard policy must allow all, got {:?}",
                            verdict
                        );
                    }
                }

        // ── Priority & Override Rules ────────────────────────

        proptest! {
                    /// Higher-priority Deny overrides lower-priority Allow.
                    #[test]
                    fn prop_higher_priority_deny_wins(
                        tool in arb_tool_name(),
                        function in arb_function_name(),
                    ) {
                        let action = Action::new(tool.clone(), function.clone(), json!({}));
                        let policies = vec![
                            Policy {
                                id: "*".to_string(),
                                name: "Deny all".to_string(),
                                policy_type: PolicyType::Deny,
                                priority: 200,
                                path_rules: None,
                                network_rules: None,
        },
                            Policy {
                                id: "*".to_string(),
                                name: "Allow all".to_string(),
                                policy_type: PolicyType::Allow,
                                priority: 100,
                                path_rules: None,
                                network_rules: None,
        },
                        ];
                        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
                        let verdict = engine.evaluate_action(&action, &[]).unwrap();
                        prop_assert!(
                            matches!(verdict, Verdict::Deny { .. }),
                            "higher priority deny must win, got {:?}",
                            verdict
                        );
                    }

                    /// At equal priority, Deny wins over Allow (deny-overrides).
                    #[test]
                    fn prop_deny_wins_at_equal_priority(
                        tool in arb_tool_name(),
                        function in arb_function_name(),
                    ) {
                        let action = Action::new(tool.clone(), function.clone(), json!({}));
                        let policies = vec![
                            Policy {
                                id: "*".to_string(),
                                name: "Deny all".to_string(),
                                policy_type: PolicyType::Deny,
                                priority: 100,
                                path_rules: None,
                                network_rules: None,
        },
                            Policy {
                                id: "*".to_string(),
                                name: "Allow all".to_string(),
                                policy_type: PolicyType::Allow,
                                priority: 100,
                                path_rules: None,
                                network_rules: None,
        },
                        ];
                        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
                        let verdict = engine.evaluate_action(&action, &[]).unwrap();
                        prop_assert!(
                            matches!(verdict, Verdict::Deny { .. }),
                            "deny must win at equal priority, got {:?}",
                            verdict
                        );
                    }
                }

        // ── Path / Domain Safety ─────────────────────────────

        proptest! {
                    /// normalize_path is idempotent: normalizing twice yields same result.
                    #[test]
                    fn prop_normalize_path_idempotent(path in arb_path()) {
                        match PolicyEngine::normalize_path(&path) {
                            Err(_) => {}
                            Ok(once) => {
                                let twice = PolicyEngine::normalize_path(&once).expect("idempotent");
                                prop_assert_eq!(
                                    &once, &twice,
                                    "normalize_path must be idempotent: '{}' -> '{}' -> '{}'",
                                    path, once, twice
                                );
                            }
                        }
                    }

                    /// normalize_path is idempotent for percent-encoded input.
                    #[test]
                    fn prop_normalize_path_encoded_idempotent(
                        seg in "[a-z]{1,5}",
                    ) {
                        // Encode each character as %XX
                        let encoded: String = seg.bytes()
                            .map(|b| format!("%{:02X}", b))
                            .collect();
                        let input = format!("/{}", encoded);
                        match PolicyEngine::normalize_path(&input) {
                            Err(_) => {}
                            Ok(once) => {
                                let twice = PolicyEngine::normalize_path(&once).expect("idempotent");
                                prop_assert_eq!(
                                    &once, &twice,
                                    "normalize_path must be idempotent on encoded input: '{}' -> '{}' -> '{}'",
                                    input, once, twice
                                );
                            }
                        }
                    }

                    /// normalize_path never returns an empty string.
                    #[test]
                    fn prop_normalize_path_never_empty(path in arb_path()) {
                        if let Ok(ref val) = PolicyEngine::normalize_path(&path) {
                            prop_assert!(
                                !val.is_empty(),
                                "normalize_path must never return empty string for input '{}'",
                                path
                            );
                        }
                    }

                    /// extract_domain always returns a lowercase string.
                    #[test]
                    fn prop_extract_domain_lowercase(
                        scheme in prop_oneof![Just("http"), Just("https"), Just("ftp")],
                        host in "[a-zA-Z]{1,10}(\\.[a-zA-Z]{1,5}){1,3}",
                    ) {
                        let url = format!("{}://{}/path", scheme, host);
                        let domain = PolicyEngine::extract_domain(&url);
                        let lowered = domain.to_lowercase();
                        prop_assert_eq!(
                            &domain, &lowered,
                            "extract_domain must return lowercase for '{}'",
                            url
                        );
                    }

                    /// Blocked glob pattern always produces Deny via not_glob constraint.
                    #[test]
                    fn prop_blocked_glob_always_denies(
                        user in "[a-z]{1,8}",
                        suffix in "[a-z_/.]{0,15}",
                    ) {
                        let path = format!("/home/{}/.aws/{}", user, suffix);
                        let action = Action::new("file_system".to_string(), "read_file".to_string(), json!({ "path": path }));
                        // not_glob denies when the path does NOT match the allowlist.
                        // A path under .aws should NOT be in a project allowlist.
                        let policy = Policy {
                            id: "file_system:read_file".to_string(),
                            name: "Block outside project".to_string(),
                            policy_type: PolicyType::Conditional {
                                conditions: json!({
                                    "parameter_constraints": [
                                        {
                                            "param": "path",
                                            "op": "not_glob",
                                            "patterns": ["/home/*/project/**", "/tmp/**"],
                                            "on_match": "deny"
                                        }
                                    ]
                                }),
                            },
                            priority: 200,
                            path_rules: None,
                            network_rules: None,
        };
                        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
                        let verdict = engine.evaluate_action(&action, &[]).unwrap();
                        prop_assert!(
                            matches!(verdict, Verdict::Deny { .. }),
                            "path '{}' under .aws must be denied, got {:?}",
                            path,
                            verdict
                        );
                    }
                }

        // ── Parameter Resolution ─────────────────────────────

        proptest! {
            /// Ambiguous dotted path (literal key vs nested traversal disagree) returns None.
            #[test]
            fn prop_ambiguous_dotted_path_none(
                key_a in "[a-z]{1,5}",
                key_b in "[a-z]{1,5}",
                val_literal in "[A-Z]{1,5}",
                val_nested in "[0-9]{1,5}",
            ) {
                // Only test when the two values actually differ
                prop_assume!(val_literal != val_nested);
                let dotted = format!("{}.{}", key_a, key_b);
                // Build params with both a literal "a.b" key and a nested a.b path
                let params = json!({
                    dotted.clone(): val_literal,
                    key_a.clone(): { key_b.clone(): val_nested },
                });
                let result = PolicyEngine::get_param_by_path(&params, &dotted);
                prop_assert!(
                    result.is_none(),
                    "ambiguous dotted path '{}' must return None, got {:?}",
                    dotted,
                    result
                );
            }

            /// When literal key and nested traversal agree, resolution succeeds.
            #[test]
            fn prop_same_value_dotted_path_resolves(
                key_a in "[a-z]{1,5}",
                key_b in "[a-z]{1,5}",
                val in "[a-z0-9]{1,10}",
            ) {
                let dotted = format!("{}.{}", key_a, key_b);
                let params = json!({
                    dotted.clone(): val.clone(),
                    key_a.clone(): { key_b.clone(): val.clone() },
                });
                let result = PolicyEngine::get_param_by_path(&params, &dotted);
                prop_assert!(
                    result.is_some(),
                    "agreeing dotted path '{}' must resolve, got None",
                    dotted
                );
                prop_assert_eq!(
                    result.unwrap().as_str().unwrap(),
                    val.as_str(),
                    "resolved value must match"
                );
            }
        }

        // ── Pattern Matching ─────────────────────────────────

        proptest! {
            /// PatternMatcher::Exact compiled from a literal always matches itself.
            #[test]
            fn prop_pattern_matcher_exact_self(s in "[a-z_]{1,20}") {
                let matcher = PatternMatcher::compile(&s);
                prop_assert!(
                    matcher.matches(&s),
                    "PatternMatcher::compile('{}').matches('{}') must be true",
                    s, s
                );
            }
        }
    }

    // ── ReDoS Protection Tests (H2) ─────────────────────

    #[test]
    fn test_redos_nested_quantifiers_rejected() {
        let result = PolicyEngine::validate_regex_safety("(a+)+b");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nested quantifier"));
    }

    #[test]
    fn test_redos_star_star_rejected() {
        let result = PolicyEngine::validate_regex_safety("(a*)*");
        assert!(result.is_err());
    }

    #[test]
    fn test_redos_overlength_rejected() {
        let long_pattern = "a".repeat(1025);
        let result = PolicyEngine::validate_regex_safety(&long_pattern);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("maximum length"));
    }

    #[test]
    fn test_redos_valid_patterns_accepted() {
        assert!(PolicyEngine::validate_regex_safety(r"^/[\w/.\-]+$").is_ok());
        assert!(PolicyEngine::validate_regex_safety(r"[a-z]+").is_ok());
        assert!(PolicyEngine::validate_regex_safety(r"foo|bar|baz").is_ok());
        assert!(PolicyEngine::validate_regex_safety(r"(abc)+").is_ok()); // quantifier on group without inner quantifier
    }

    #[test]
    fn test_redos_compile_constraint_rejects_unsafe_regex() {
        let policy = Policy {
            id: "test:*".to_string(),
            name: "test".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [
                        {"param": "input", "op": "regex", "pattern": "(a+)+b"}
                    ]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].reason.contains("nested quantifier"));
    }

    #[test]
    fn test_redos_legacy_regex_is_match_rejects_unsafe() {
        let engine = PolicyEngine::new(false);
        let result = engine.regex_is_match("(a+)+b", "aaaaab", "test-policy");
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════
    // 6B: DOMAIN SYNTAX VALIDATION (L1)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_validate_domain_pattern_valid() {
        // Simple domains
        assert!(PolicyEngine::validate_domain_pattern("example.com").is_ok());
        assert!(PolicyEngine::validate_domain_pattern("sub.example.com").is_ok());
        assert!(PolicyEngine::validate_domain_pattern("a-b.example.com").is_ok());
        // Wildcard prefix
        assert!(PolicyEngine::validate_domain_pattern("*.example.com").is_ok());
        // Single-label domain
        assert!(PolicyEngine::validate_domain_pattern("localhost").is_ok());
    }

    #[test]
    fn test_validate_domain_pattern_invalid() {
        // Empty string
        assert!(PolicyEngine::validate_domain_pattern("").is_err());

        // Label longer than 63 characters
        let long_label = "a".repeat(64);
        let long_domain = format!("{}.example.com", long_label);
        assert!(
            PolicyEngine::validate_domain_pattern(&long_domain).is_err(),
            "Label > 63 chars should be rejected"
        );

        // Leading hyphen in label
        assert!(
            PolicyEngine::validate_domain_pattern("-example.com").is_err(),
            "Leading hyphen should be rejected"
        );

        // Trailing hyphen in label
        assert!(
            PolicyEngine::validate_domain_pattern("example-.com").is_err(),
            "Trailing hyphen should be rejected"
        );

        // Total domain length > 253 characters
        let labels: Vec<String> = (0..50).map(|i| format!("label{}", i)).collect();
        let huge_domain = labels.join(".");
        assert!(huge_domain.len() > 253);
        assert!(
            PolicyEngine::validate_domain_pattern(&huge_domain).is_err(),
            "Domain > 253 chars should be rejected"
        );

        // Invalid characters (underscore)
        assert!(
            PolicyEngine::validate_domain_pattern("under_score.example.com").is_err(),
            "Underscore in label should be rejected"
        );

        // Invalid characters (space)
        assert!(
            PolicyEngine::validate_domain_pattern("spa ce.example.com").is_err(),
            "Space in label should be rejected"
        );
    }

    #[test]
    fn test_validate_domain_pattern_wildcard_prefix_only() {
        // Valid wildcard at prefix
        assert!(PolicyEngine::validate_domain_pattern("*.example.com").is_ok());

        // Invalid wildcard in middle
        assert!(
            PolicyEngine::validate_domain_pattern("sub.*.example.com").is_err(),
            "Wildcard in middle should be rejected"
        );

        // Invalid wildcard at end
        assert!(
            PolicyEngine::validate_domain_pattern("example.*").is_err(),
            "Wildcard at end should be rejected"
        );

        // Bare wildcard with no domain
        assert!(
            PolicyEngine::validate_domain_pattern("*.").is_err(),
            "Bare '*.' with no domain should be rejected"
        );
    }

    #[test]
    fn test_compile_policy_rejects_invalid_domain_in_network_rules() {
        use sentinel_types::NetworkRules;

        let policy = Policy {
            id: "test:net".to_string(),
            name: "Net policy".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: Some(NetworkRules {
                allowed_domains: vec!["valid.example.com".to_string()],
                blocked_domains: vec!["-invalid.com".to_string()],
                ip_rules: None,
            }),
        };

        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(
            result.is_err(),
            "Policy with invalid domain pattern should fail compilation"
        );
        let errors = result.unwrap_err();
        assert!(
            errors[0].reason.contains("Invalid domain pattern"),
            "Error should mention invalid domain pattern, got: {}",
            errors[0].reason
        );
    }

    // ═══════════════════════════════════════════════════
    // 6D: CONSISTENT JSON DEPTH ENFORCEMENT (L4)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_max_json_depth_constant_value() {
        // Verify the constant is 32 and is used consistently.
        assert_eq!(
            PolicyEngine::MAX_JSON_DEPTH,
            32,
            "MAX_JSON_DEPTH should be 32"
        );
    }

    #[test]
    fn test_json_depth_and_scan_depth_use_same_constant() {
        // The depth check in collect_all_string_values uses `depth >= MAX_JSON_DEPTH`
        // on objects/arrays to stop descending. A string at depth D is collected
        // because strings don't recurse. So a string wrapped in MAX_JSON_DEPTH
        // objects is at depth MAX_JSON_DEPTH and IS collected (the object at
        // depth MAX_JSON_DEPTH - 1 pushes its child string at depth MAX_JSON_DEPTH,
        // and strings are processed without checking depth).
        //
        // A string wrapped in MAX_JSON_DEPTH + 1 objects is NOT collected, because
        // the object at depth MAX_JSON_DEPTH is skipped entirely (depth >= MAX_JSON_DEPTH).

        // Build a structure one level beyond MAX_JSON_DEPTH (should NOT be found)
        let mut val = json!("deep_value");
        for _ in 0..(PolicyEngine::MAX_JSON_DEPTH + 1) {
            val = json!({"nested": val});
        }
        let values = PolicyEngine::collect_all_string_values(&val);
        assert!(
            values.is_empty(),
            "Values beyond MAX_JSON_DEPTH should not be collected"
        );

        // A string at exactly MAX_JSON_DEPTH - 1 nesting should be found
        let mut val2 = json!("shallow_value");
        for _ in 0..(PolicyEngine::MAX_JSON_DEPTH - 1) {
            val2 = json!({"nested": val2});
        }
        let values2 = PolicyEngine::collect_all_string_values(&val2);
        assert!(
            !values2.is_empty(),
            "Values at depth MAX_JSON_DEPTH - 1 should be collected"
        );
    }

    // ═══════════════════════════════════════════════════
    // CONTEXT-AWARE EVALUATION TESTS (C-17.3)
    // ═══════════════════════════════════════════════════

    fn make_context_policy(context_conditions: serde_json::Value) -> Policy {
        Policy {
            id: "read_file:*".to_string(),
            name: "context-test".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "context_conditions": context_conditions,
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }
    }

    fn make_context_engine(policy: Policy) -> PolicyEngine {
        let mut engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        // Enable trusted timestamps for deterministic testing only.
        // In production, trust_context_timestamps is always false.
        engine.set_trust_context_timestamps(true);
        engine
    }

    #[test]
    fn test_context_time_window_allow_during_hours() {
        let policy = make_context_policy(json!([
            {"type": "time_window", "start_hour": 0, "end_hour": 23}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            timestamp: Some("2026-02-04T12:00:00Z".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow));
    }

    #[test]
    fn test_context_time_window_deny_outside_hours() {
        let policy = make_context_policy(json!([
            {"type": "time_window", "start_hour": 9, "end_hour": 17}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            timestamp: Some("2026-02-04T20:00:00Z".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    #[test]
    fn test_context_time_window_midnight_wrap() {
        // 22:00 - 06:00 (overnight window)
        let policy = make_context_policy(json!([
            {"type": "time_window", "start_hour": 22, "end_hour": 6}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));

        // 23:00 should be allowed
        let ctx = EvaluationContext {
            timestamp: Some("2026-02-04T23:00:00Z".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow));

        // 03:00 should be allowed
        let ctx = EvaluationContext {
            timestamp: Some("2026-02-04T03:00:00Z".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow));

        // 10:00 should be denied
        let ctx = EvaluationContext {
            timestamp: Some("2026-02-04T10:00:00Z".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    #[test]
    fn test_context_time_window_day_of_week_filter() {
        // Only allow on Monday (1) and Tuesday (2)
        let policy = make_context_policy(json!([
            {"type": "time_window", "start_hour": 0, "end_hour": 23, "days": [1, 2]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));

        // 2026-02-04 is a Wednesday (day 3), should be denied
        let ctx = EvaluationContext {
            timestamp: Some("2026-02-04T12:00:00Z".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));

        // 2026-02-02 is a Monday (day 1), should be allowed
        let ctx = EvaluationContext {
            timestamp: Some("2026-02-02T12:00:00Z".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow));
    }

    #[test]
    fn test_context_max_calls_under_limit() {
        let policy = make_context_policy(json!([
            {"type": "max_calls", "tool_pattern": "read_file", "max": 5}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let mut counts = HashMap::new();
        counts.insert("read_file".to_string(), 3);
        let ctx = EvaluationContext {
            call_counts: counts,
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow));
    }

    #[test]
    fn test_context_max_calls_at_limit_denies() {
        let policy = make_context_policy(json!([
            {"type": "max_calls", "tool_pattern": "read_file", "max": 5}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let mut counts = HashMap::new();
        counts.insert("read_file".to_string(), 5);
        let ctx = EvaluationContext {
            call_counts: counts,
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    #[test]
    fn test_context_max_calls_wildcard_pattern() {
        let policy = make_context_policy(json!([
            {"type": "max_calls", "tool_pattern": "*", "max": 10}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let mut counts = HashMap::new();
        counts.insert("read_file".to_string(), 5);
        counts.insert("write_file".to_string(), 6);
        let ctx = EvaluationContext {
            call_counts: counts,
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    // === R15-ENG-1 regression: MaxCalls/MaxCallsInWindow must fail-closed
    // when session state is unavailable (empty call_counts/previous_actions).

    #[test]
    fn test_context_max_calls_empty_counts_denies_fail_closed() {
        // SECURITY (R15-ENG-1): If a policy declares MaxCalls but the caller
        // provides empty call_counts (e.g., stateless API), deny rather than
        // silently allowing unlimited calls.
        let policy = make_context_policy(json!([
            {"type": "max_calls", "tool_pattern": "read_file", "max": 5}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            call_counts: HashMap::new(), // empty — no session tracking
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "MaxCalls with empty call_counts must deny (fail-closed), got: {:?}",
            v
        );
    }

    #[test]
    fn test_context_max_calls_wildcard_empty_counts_denies() {
        let policy = make_context_policy(json!([
            {"type": "max_calls", "tool_pattern": "*", "max": 10}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("any_tool", "execute", json!({}));
        let ctx = EvaluationContext {
            call_counts: HashMap::new(),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "MaxCalls wildcard with empty call_counts must deny, got: {:?}",
            v
        );
    }

    #[test]
    fn test_context_max_calls_in_window_empty_history_denies() {
        // SECURITY (R15-ENG-1): MaxCallsInWindow with empty previous_actions
        // and empty call_counts must deny (no session history available).
        let policy = make_context_policy(json!([
            {"type": "max_calls_in_window", "tool_pattern": "write_file", "max": 3, "window": 10}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("write_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: Vec::new(),
            call_counts: HashMap::new(),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "MaxCallsInWindow with empty history must deny (fail-closed), got: {:?}",
            v
        );
    }

    #[test]
    fn test_context_max_calls_in_window_nonempty_counts_empty_history_denies() {
        // SECURITY (R21-ENG-1): MaxCallsInWindow with empty previous_actions
        // but non-empty call_counts must STILL deny. MaxCallsInWindow counts
        // over previous_actions only, so providing call_counts alone cannot
        // satisfy the windowed check.
        let policy = make_context_policy(json!([
            {"type": "max_calls_in_window", "tool_pattern": "write_file", "max": 3, "window": 10}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("write_file", "execute", json!({}));
        let mut counts = HashMap::new();
        counts.insert("write_file".to_string(), 1u64);
        let ctx = EvaluationContext {
            previous_actions: Vec::new(), // empty — no history
            call_counts: counts,          // non-empty — should NOT bypass check
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "R21-ENG-1: MaxCallsInWindow with empty history must deny even if call_counts non-empty, got: {:?}",
            v
        );
    }

    #[test]
    fn test_context_max_calls_with_zero_count_allows() {
        // When call_counts is non-empty but the specific tool has count 0,
        // the rate limit is not yet reached — this should Allow.
        let policy = make_context_policy(json!([
            {"type": "max_calls", "tool_pattern": "read_file", "max": 5}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let mut counts = HashMap::new();
        counts.insert("other_tool".to_string(), 1u64); // non-empty map, but read_file count is 0
        let ctx = EvaluationContext {
            call_counts: counts,
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "MaxCalls with non-empty counts and tool count 0 should allow, got: {:?}",
            v
        );
    }

    #[test]
    fn test_context_agent_id_allowed() {
        let policy = make_context_policy(json!([
            {"type": "agent_id", "allowed": ["agent-a", "agent-b"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_id: Some("agent-a".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow));
    }

    #[test]
    fn test_context_agent_id_blocked() {
        let policy = make_context_policy(json!([
            {"type": "agent_id", "blocked": ["evil-agent"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_id: Some("evil-agent".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    #[test]
    fn test_context_agent_id_missing_fails_closed() {
        let policy = make_context_policy(json!([
            {"type": "agent_id", "allowed": ["agent-a"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext::default(); // No agent_id
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    #[test]
    fn test_context_agent_id_case_insensitive() {
        // SECURITY: Agent IDs must be compared case-insensitively.
        // "Agent-A" should match policy allowing "agent-a".
        let policy = make_context_policy(json!([
            {"type": "agent_id", "allowed": ["Agent-A", "AGENT-B"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));

        // Lowercase variant should be allowed
        let ctx = EvaluationContext {
            agent_id: Some("agent-a".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "lowercase should match: {:?}",
            v
        );

        // Mixed case variant should be allowed
        let ctx = EvaluationContext {
            agent_id: Some("AGENT-A".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "uppercase should match: {:?}",
            v
        );

        // Case variation of blocked agent should be blocked
        let policy2 = make_context_policy(json!([
            {"type": "agent_id", "blocked": ["Evil-Agent"]}
        ]));
        let engine2 = make_context_engine(policy2);
        let ctx = EvaluationContext {
            agent_id: Some("EVIL-AGENT".to_string()),
            ..Default::default()
        };
        let v = engine2
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "case variant of blocked should deny: {:?}",
            v
        );
    }

    #[test]
    fn test_context_require_previous_action_present() {
        let policy = make_context_policy(json!([
            {"type": "require_previous_action", "required_tool": "authenticate"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec!["authenticate".to_string(), "list_files".to_string()],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow));
    }

    #[test]
    fn test_context_require_previous_action_absent() {
        let policy = make_context_policy(json!([
            {"type": "require_previous_action", "required_tool": "authenticate"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec!["list_files".to_string()],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    #[test]
    fn test_context_none_denies_when_conditions_exist() {
        // SECURITY: When context is None but policy has context conditions,
        // the action must be denied (fail-closed). Allowing it would let
        // callers bypass time-window/max-calls/agent-id by omitting context.
        let policy = make_context_policy(json!([
            {"type": "agent_id", "allowed": ["agent-a"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let v = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Expected Deny when context conditions exist but no context provided, got {:?}",
            v
        );
    }

    #[test]
    fn test_context_none_allows_when_no_conditions() {
        // Policies WITHOUT context conditions should still work fine with no context.
        let policy = Policy {
            id: "read_file:*".to_string(),
            name: "allow-read".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        };
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("read_file", "execute", json!({}));
        let v = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(v, Verdict::Allow));
    }

    #[test]
    fn test_context_compile_error_unknown_type() {
        let policy = make_context_policy(json!([
            {"type": "unknown_condition"}
        ]));
        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_compile_error_invalid_time_window() {
        let policy = make_context_policy(json!([
            {"type": "time_window", "start_hour": 25, "end_hour": 10}
        ]));
        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(result.is_err());
    }

    /// SECURITY (R19-TRUNC): Verify that large u64 hour values are rejected
    /// instead of silently truncating to u8 (e.g., 265 → 9).
    #[test]
    fn test_context_compile_error_truncated_hour_value() {
        // 265 as u8 = 9, which would pass > 23 check without the fix
        let policy = make_context_policy(json!([
            {"type": "time_window", "start_hour": 265, "end_hour": 10}
        ]));
        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(
            result.is_err(),
            "Should reject start_hour=265 (would truncate to 9 as u8)"
        );

        // Same for end_hour
        let policy2 = make_context_policy(json!([
            {"type": "time_window", "start_hour": 9, "end_hour": 280}
        ]));
        let result2 = PolicyEngine::with_policies(false, &[policy2]);
        assert!(
            result2.is_err(),
            "Should reject end_hour=280 (would truncate to 24→err, but 256+17=273→17 as u8)"
        );
    }

    /// SECURITY (R19-TRUNC): Verify that large u64 day values are rejected.
    #[test]
    fn test_context_compile_error_truncated_day_value() {
        // 258 as u8 = 2 (Tuesday), which would pass 1..=7 check without the fix
        let policy = make_context_policy(json!([
            {"type": "time_window", "start_hour": 9, "end_hour": 17, "days": [1, 258]}
        ]));
        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(
            result.is_err(),
            "Should reject day=258 (would truncate to 2 as u8)"
        );
    }

    /// SECURITY (R19-WINDOW-EQ): start_hour == end_hour creates a zero-width
    /// window that always denies. Reject at compile time.
    #[test]
    fn test_context_compile_error_zero_width_time_window() {
        let policy = make_context_policy(json!([
            {"type": "time_window", "start_hour": 12, "end_hour": 12}
        ]));
        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(
            result.is_err(),
            "Should reject start_hour == end_hour (zero-width window)"
        );
    }

    #[test]
    fn test_context_traced_with_context() {
        let policy = make_context_policy(json!([
            {"type": "max_calls", "tool_pattern": "read_file", "max": 2}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let mut counts = HashMap::new();
        counts.insert("read_file".to_string(), 5);
        let ctx = EvaluationContext {
            call_counts: counts,
            ..Default::default()
        };
        let (v, _trace) = engine
            .evaluate_action_traced_with_context(&action, Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Deny { .. }));
    }

    // ── Forbidden Previous Action (cross-tool orchestration) ──────────

    #[test]
    fn test_context_forbidden_previous_action_present_denies() {
        let policy = Policy {
            id: "http_request:*".to_string(),
            name: "block-exfil-after-read".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "context_conditions": [
                        {"type": "forbidden_previous_action", "forbidden_tool": "read_file"}
                    ],
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new(
            "http_request",
            "execute",
            json!({"url": "https://evil.com"}),
        );
        let ctx = EvaluationContext {
            previous_actions: vec!["read_file".to_string(), "list_files".to_string()],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Should deny http_request when read_file is in history"
        );
    }

    #[test]
    fn test_context_forbidden_previous_action_absent_allows() {
        let policy = Policy {
            id: "http_request:*".to_string(),
            name: "block-exfil-after-read".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "context_conditions": [
                        {"type": "forbidden_previous_action", "forbidden_tool": "read_file"}
                    ],
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new(
            "http_request",
            "execute",
            json!({"url": "https://api.github.com"}),
        );
        let ctx = EvaluationContext {
            previous_actions: vec!["list_files".to_string()],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Should allow http_request when read_file is NOT in history"
        );
    }

    #[test]
    fn test_context_forbidden_previous_action_empty_history() {
        let policy = Policy {
            id: "http_request:*".to_string(),
            name: "block-exfil-after-read".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "context_conditions": [
                        {"type": "forbidden_previous_action", "forbidden_tool": "read_file"}
                    ],
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("http_request", "execute", json!({}));
        let ctx = EvaluationContext::default();
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Should allow when history is empty"
        );
    }

    // ── Max Calls In Window (sliding-window rate limit) ──────────

    #[test]
    fn test_context_max_calls_in_window_under_limit() {
        let policy = make_context_policy(json!([
            {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 5, "window": 10}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec![
                "read_file".to_string(),
                "read_file".to_string(),
                "list_files".to_string(),
                "read_file".to_string(),
            ],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "3 calls in window of 10 should be under limit of 5"
        );
    }

    #[test]
    fn test_context_max_calls_in_window_at_limit_denies() {
        let policy = make_context_policy(json!([
            {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 3, "window": 10}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec![
                "read_file".to_string(),
                "read_file".to_string(),
                "list_files".to_string(),
                "read_file".to_string(),
            ],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "3 calls at limit of 3 should deny"
        );
    }

    #[test]
    fn test_context_max_calls_in_window_older_calls_outside() {
        let policy = make_context_policy(json!([
            {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 3, "window": 3}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec![
                "read_file".to_string(),  // outside window
                "read_file".to_string(),  // outside window
                "read_file".to_string(),  // inside window
                "list_files".to_string(), // inside window
                "list_files".to_string(), // inside window
            ],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Only 1 read_file in last 3 actions, under limit of 3"
        );
    }

    #[test]
    fn test_context_max_calls_in_window_zero_means_all() {
        let policy = make_context_policy(json!([
            {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 3, "window": 0}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec![
                "read_file".to_string(),
                "read_file".to_string(),
                "read_file".to_string(),
            ],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "window=0 checks entire history, 3 >= max of 3"
        );
    }

    #[test]
    fn test_context_max_calls_in_window_wildcard() {
        let policy = make_context_policy(json!([
            {"type": "max_calls_in_window", "tool_pattern": "*", "max": 5, "window": 5}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            previous_actions: vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
                "e".to_string(),
            ],
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "5 any-tool calls in window of 5, at limit of 5"
        );
    }

    #[test]
    fn test_context_forbidden_previous_compile_error() {
        let policy = make_context_policy(json!([
            {"type": "forbidden_previous_action"}
        ]));
        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(
            result.is_err(),
            "Missing forbidden_tool should fail compilation"
        );
    }

    #[test]
    fn test_context_max_calls_in_window_compile_error() {
        let policy = make_context_policy(json!([
            {"type": "max_calls_in_window", "tool_pattern": "*", "window": 10}
        ]));
        let result = PolicyEngine::with_policies(false, &[policy]);
        assert!(result.is_err(), "Missing max should fail compilation");
    }

    // ═══════════════════════════════════════════════════
    // AGENT IDENTITY ATTESTATION TESTS (OWASP ASI07)
    // ═══════════════════════════════════════════════════

    use sentinel_types::AgentIdentity;

    fn make_test_identity(issuer: &str, subject: &str, role: &str) -> AgentIdentity {
        let mut claims = std::collections::HashMap::new();
        claims.insert("role".to_string(), serde_json::json!(role));
        AgentIdentity {
            issuer: Some(issuer.to_string()),
            subject: Some(subject.to_string()),
            audience: vec!["mcp-server".to_string()],
            claims,
        }
    }

    #[test]
    fn test_agent_identity_required_issuer_match() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "issuer": "https://auth.example.com"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow), "Matching issuer should allow");
    }

    #[test]
    fn test_agent_identity_required_issuer_mismatch() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "issuer": "https://auth.example.com"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://evil.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Mismatched issuer should deny"
        );
    }

    #[test]
    fn test_agent_identity_required_subject_match() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "subject": "agent-123"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow), "Matching subject should allow");
    }

    #[test]
    fn test_agent_identity_required_subject_mismatch() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "subject": "agent-123"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-456",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Mismatched subject should deny"
        );
    }

    #[test]
    fn test_agent_identity_required_audience() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "audience": "mcp-server"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Matching audience should allow"
        );
    }

    #[test]
    fn test_agent_identity_required_audience_mismatch() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "audience": "other-server"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Audience not in list should deny"
        );
    }

    #[test]
    fn test_agent_identity_required_claim_match() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "claims": {"role": "admin"}}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(matches!(v, Verdict::Allow), "Matching claim should allow");
    }

    #[test]
    fn test_agent_identity_required_claim_mismatch() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "claims": {"role": "admin"}}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "user", // Not "admin"
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Mismatched claim should deny"
        );
    }

    #[test]
    fn test_agent_identity_blocked_issuer() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "blocked_issuers": ["https://evil.example.com"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://evil.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Blocked issuer should deny"
        );
    }

    #[test]
    fn test_agent_identity_blocked_issuer_case_insensitive() {
        // SECURITY: Blocked issuers should be case-insensitive
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "blocked_issuers": ["HTTPS://EVIL.EXAMPLE.COM"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://evil.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Blocked issuer should be case-insensitive"
        );
    }

    #[test]
    fn test_agent_identity_blocked_subject() {
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "blocked_subjects": ["malicious-agent"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "malicious-agent",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Blocked subject should deny"
        );
    }

    #[test]
    fn test_agent_identity_missing_fails_closed() {
        // SECURITY: When require_attestation=true (default), missing identity should deny
        let policy = make_context_policy(json!([
            {"type": "agent_identity", "issuer": "https://auth.example.com"}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            // No agent_identity
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Missing identity with require_attestation=true should deny"
        );
    }

    #[test]
    fn test_agent_identity_missing_with_require_attestation_false() {
        // When require_attestation=false, missing identity allows (falls back to agent_id)
        let policy = make_context_policy(json!([
            {
                "type": "agent_identity",
                "issuer": "https://auth.example.com",
                "require_attestation": false
            }
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));
        let ctx = EvaluationContext {
            // No agent_identity, but require_attestation=false
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Missing identity with require_attestation=false should allow"
        );
    }

    #[test]
    fn test_agent_identity_combined_conditions() {
        // Test multiple conditions: issuer + subject + claim
        let policy = make_context_policy(json!([
            {
                "type": "agent_identity",
                "issuer": "https://auth.example.com",
                "subject": "agent-123",
                "claims": {"role": "admin"}
            }
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));

        // All match - should allow
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "All conditions match should allow"
        );

        // Wrong role - should deny
        let ctx_wrong_role = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "user",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx_wrong_role))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Wrong role should deny"
        );
    }

    #[test]
    fn test_agent_identity_fallback_to_agent_id() {
        // Combine agent_identity with agent_id for backwards compatibility
        let policy = make_context_policy(json!([
            {
                "type": "agent_identity",
                "issuer": "https://auth.example.com",
                "require_attestation": false
            },
            {"type": "agent_id", "allowed": ["legacy-agent"]}
        ]));
        let engine = make_context_engine(policy);
        let action = Action::new("read_file", "execute", json!({}));

        // With agent_identity - should be checked
        let ctx = EvaluationContext {
            agent_identity: Some(make_test_identity(
                "https://auth.example.com",
                "agent-123",
                "admin",
            )),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx))
            .unwrap();
        assert!(
            matches!(v, Verdict::Deny { .. }),
            "Must also pass agent_id check if no identity passed"
        );

        // With only legacy agent_id - should also be allowed to pass first check
        let ctx_legacy = EvaluationContext {
            agent_id: Some("legacy-agent".to_string()),
            ..Default::default()
        };
        let v = engine
            .evaluate_action_with_context(&action, &[], Some(&ctx_legacy))
            .unwrap();
        assert!(
            matches!(v, Verdict::Allow),
            "Legacy agent_id should work when require_attestation=false"
        );
    }
}
