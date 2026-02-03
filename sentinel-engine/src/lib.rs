use sentinel_types::{
    Action, ActionSummary, ConstraintResult, EvaluationTrace, Policy, PolicyMatch, PolicyType,
    Verdict,
};
use thiserror::Error;

use globset::{Glob, GlobMatcher};
use regex::Regex;
use std::collections::HashMap;
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
    compiled_policies: Vec<CompiledPolicy>,
    /// Maps exact tool names to sorted indices in `compiled_policies`.
    /// Only policies with an exact tool name pattern are indexed here.
    tool_index: HashMap<String, Vec<usize>>,
    /// Indices of policies that cannot be indexed by tool name
    /// (Universal, prefix, suffix, or Any tool patterns).
    /// Already sorted by position in `compiled_policies` (= priority order).
    always_check: Vec<usize>,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("strict_mode", &self.strict_mode)
            .field("compiled_policies_count", &self.compiled_policies.len())
            .field("indexed_tools", &self.tool_index.len())
            .field("always_check_count", &self.always_check.len())
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
        }
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
        })
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
        ) = match &policy.policy_type {
            PolicyType::Allow | PolicyType::Deny => {
                (false, Vec::new(), Vec::new(), Vec::new(), false)
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

        // Compile path rules
        let compiled_path_rules = policy.path_rules.as_ref().map(|pr| {
            let allowed = pr
                .allowed
                .iter()
                .filter_map(|pattern| {
                    Glob::new(pattern)
                        .ok()
                        .map(|g| (pattern.clone(), g.compile_matcher()))
                })
                .collect();
            let blocked = pr
                .blocked
                .iter()
                .filter_map(|pattern| {
                    Glob::new(pattern)
                        .ok()
                        .map(|g| (pattern.clone(), g.compile_matcher()))
                })
                .collect();
            CompiledPathRules { allowed, blocked }
        });

        // Compile network rules (domain patterns are matched directly, no glob needed)
        let compiled_network_rules = policy
            .network_rules
            .as_ref()
            .map(|nr| CompiledNetworkRules {
                allowed_domains: nr.allowed_domains.clone(),
                blocked_domains: nr.blocked_domains.clone(),
            });

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
        })
    }

    /// Compile condition JSON into pre-parsed fields and compiled constraints.
    ///
    /// Returns: (require_approval, forbidden_parameters, required_parameters, constraints, on_no_match_continue)
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

        // Validate strict mode unknown keys
        if strict_mode {
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
        let on_missing = obj
            .get("on_missing")
            .and_then(|v| v.as_str())
            .unwrap_or("deny")
            .to_string();

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

            // Merge two sorted index slices, iterating in priority order
            let mut ti = 0;
            let mut ai = 0;
            loop {
                let next_idx = match (tool_slice.get(ti), always_slice.get(ai)) {
                    (Some(&t), Some(&a)) => {
                        if t <= a {
                            ti += 1;
                            t
                        } else {
                            ai += 1;
                            a
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

    /// Apply a matched compiled policy to produce a verdict.
    /// Returns `None` when a Conditional policy with `on_no_match: "continue"` has no
    /// constraints fire, signaling the evaluation loop to try the next policy.
    fn apply_compiled_policy(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
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

        match &cp.policy.policy_type {
            PolicyType::Allow => Ok(Some(Verdict::Allow)),
            PolicyType::Deny => Ok(Some(Verdict::Deny {
                reason: cp.deny_reason.clone(),
            })),
            PolicyType::Conditional { .. } => self.evaluate_compiled_conditions(action, cp),
        }
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
            let normalized = Self::normalize_path(raw_path);

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
                let normalized = Self::normalize_path(raw);
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
                let normalized = Self::normalize_path(raw);
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

        let normalized = Self::normalize_path(raw);

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

        let normalized = Self::normalize_path(raw);

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
    pub fn normalize_path(raw: &str) -> String {
        // Reject null bytes — return root instead of empty/raw to prevent bypass
        if raw.contains('\0') {
            return "/".to_string();
        }

        // Phase 4.2: Percent-decode the path before normalization.
        // Decode in a loop until stable to guarantee idempotency:
        //   normalize_path(normalize_path(x)) == normalize_path(x)
        // Without loop decode, inputs like "%2570" produce "%70" on first call,
        // which decodes to "p" on the next call — breaking idempotency.
        // Safety cap at 20 iterations prevents DoS from deeply-nested encodings.
        // If the cap is reached, return "/" (fail-closed).
        //
        // Uses Cow to avoid allocation when no percent sequences are present.
        let mut current = std::borrow::Cow::Borrowed(raw);
        let mut iterations = 0u32;
        loop {
            let decoded = percent_encoding::percent_decode_str(&current).decode_utf8_lossy();
            if decoded.contains('\0') {
                return "/".to_string();
            }
            if decoded.as_ref() == current.as_ref() {
                break; // Stable — no more percent sequences to decode
            }
            iterations += 1;
            if iterations >= 20 {
                // Fail-closed: suspiciously deep encoding, deny by returning root
                return "/".to_string();
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
            return "/".to_string();
        }

        s.into_owned()
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
        let authority = decoded_authority.as_ref();

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
    /// Both domain and pattern are lowercased for case-insensitive comparison.
    /// When called from `extract_domain` (already lowercased), the domain
    /// lowercasing is a no-op. Trailing dots are stripped from both.
    pub fn match_domain_pattern(domain: &str, pattern: &str) -> bool {
        // Normalize domain: lowercase + strip trailing dots.
        // Use Cow to avoid allocation when already lowercase with no trailing dots.
        let dom = Self::normalize_domain_for_match(domain);
        let pat = Self::normalize_domain_for_match(pattern);

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

    /// Lowercase and strip trailing dots from a domain/pattern string.
    /// Returns a Cow::Borrowed when no changes are needed.
    fn normalize_domain_for_match(s: &str) -> std::borrow::Cow<'_, str> {
        let needs_lower = s.bytes().any(|b| b.is_ascii_uppercase());
        let has_trailing_dot = s.ends_with('.');
        if !needs_lower && !has_trailing_dot {
            return std::borrow::Cow::Borrowed(s);
        }
        let mut result = if needs_lower {
            s.to_lowercase()
        } else {
            s.to_string()
        };
        while result.ends_with('.') {
            result.pop();
        }
        std::borrow::Cow::Owned(result)
    }

    /// Compile a regex pattern and test whether it matches the input.
    ///
    /// Legacy path: compiles the pattern on each call (no caching).
    /// For zero-overhead evaluation, use `with_policies()` to pre-compile.
    fn regex_is_match(
        &self,
        pattern: &str,
        input: &str,
        policy_id: &str,
    ) -> Result<bool, EngineError> {
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
    const MAX_SCAN_DEPTH: usize = 32;

    /// Recursively collect all string values from a JSON structure.
    ///
    /// Returns a list of `(path, value)` pairs where `path` is a dot-separated
    /// description of where the value was found (e.g., `"options.target"`).
    /// Uses an iterative approach to avoid stack overflow on deep JSON.
    ///
    /// Bounded by [`MAX_SCAN_VALUES`] total values and [`MAX_SCAN_DEPTH`] nesting depth.
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
                    if depth >= Self::MAX_SCAN_DEPTH {
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
                    if depth >= Self::MAX_SCAN_DEPTH {
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

    /// Collect candidate policy indices in priority order using the tool index.
    fn collect_candidate_indices(&self, action: &Action) -> Vec<usize> {
        if self.tool_index.is_empty() && self.always_check.is_empty() {
            // No index: return all indices in order
            return (0..self.compiled_policies.len()).collect();
        }

        let tool_specific = self.tool_index.get(&action.tool);
        let tool_slice = tool_specific.map(|v| v.as_slice()).unwrap_or(&[]);
        let always_slice = &self.always_check;

        // Merge two sorted index slices
        let mut result = Vec::with_capacity(tool_slice.len() + always_slice.len());
        let mut ti = 0;
        let mut ai = 0;
        loop {
            let next_idx = match (tool_slice.get(ti), always_slice.get(ai)) {
                (Some(&t), Some(&a)) => {
                    if t <= a {
                        ti += 1;
                        t
                    } else {
                        ai += 1;
                        a
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
                    let normalized = Self::normalize_path(s);
                    matcher.is_match(&normalized)
                } else {
                    true // non-string → treated as match (fail-closed)
                }
            }
            CompiledConstraint::NotGlob { matchers, .. } => {
                if let Some(s) = value.as_str() {
                    let normalized = Self::normalize_path(s);
                    !matchers.iter().any(|(_, m)| m.is_match(&normalized))
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
        // Null byte path normalizes to empty, won't match /safe/**
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
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
        assert_eq!(PolicyEngine::normalize_path("/a/b/../c"), "/a/c");
    }

    #[test]
    fn test_normalize_path_resolves_dot() {
        assert_eq!(PolicyEngine::normalize_path("/a/./b/./c"), "/a/b/c");
    }

    #[test]
    fn test_normalize_path_prevents_root_escape() {
        assert_eq!(
            PolicyEngine::normalize_path("/a/../../etc/passwd"),
            "/etc/passwd"
        );
    }

    #[test]
    fn test_normalize_path_root_on_null_byte() {
        // Fix #9: Null byte paths now return "/" instead of empty string or raw input
        assert_eq!(PolicyEngine::normalize_path("/a/b\0/c"), "/");
    }

    #[test]
    fn test_normalize_path_absolute_stays_absolute() {
        assert_eq!(
            PolicyEngine::normalize_path("/usr/local/bin"),
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
        let result = PolicyEngine::normalize_path("/a/b\0/c");
        assert_eq!(
            result, "/",
            "Null-byte path should normalize to root, not raw input"
        );
    }

    #[test]
    fn test_fix9_normalize_path_traversal_only() {
        // A path that is ONLY traversal sequences should normalize to "/"
        // (all components resolve away, leaving nothing)
        let result = PolicyEngine::normalize_path("../../..");
        assert_eq!(result, "/", "Pure traversal path should normalize to root");
    }

    // --- Phase 4.2: Percent-encoding normalization tests ---

    #[test]
    fn test_normalize_path_percent_encoded_filename() {
        // %70 = 'p', so /etc/%70asswd → /etc/passwd
        assert_eq!(PolicyEngine::normalize_path("/etc/%70asswd"), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_percent_encoded_traversal() {
        // %2F = '/', %2E = '.', so /%2E%2E/%2E%2E/etc/passwd → /etc/passwd
        assert_eq!(
            PolicyEngine::normalize_path("/%2E%2E/%2E%2E/etc/passwd"),
            "/etc/passwd"
        );
    }

    #[test]
    fn test_normalize_path_percent_encoded_slash() {
        // %2F = '/' — encoded slashes in a single component
        // After decoding, path should be normalized correctly
        assert_eq!(PolicyEngine::normalize_path("/etc%2Fpasswd"), "/etc/passwd");
    }

    #[test]
    fn test_normalize_path_encoded_null_byte() {
        // %00 = null byte — should be rejected after decoding
        assert_eq!(PolicyEngine::normalize_path("/etc/%00passwd"), "/");
    }

    #[test]
    fn test_normalize_path_double_encoding_fully_decoded() {
        // %2570 = %25 + 70 → first decode: %70 → second decode: p
        // Loop decode ensures idempotency: normalize(normalize(x)) == normalize(x)
        // Full decode is more secure — prevents bypass via multi-layer encoding.
        let result = PolicyEngine::normalize_path("/etc/%2570asswd");
        assert_eq!(
            result, "/etc/passwd",
            "Double-encoded input should be fully decoded for idempotency"
        );
    }

    #[test]
    fn test_normalize_path_mixed_encoded_and_plain() {
        assert_eq!(
            PolicyEngine::normalize_path("/home/%75ser/.aws/credentials"),
            "/home/user/.aws/credentials"
        );
    }

    #[test]
    fn test_normalize_path_fully_encoded_path() {
        // Full path encoded
        assert_eq!(
            PolicyEngine::normalize_path("%2Fetc%2Fshadow"),
            "/etc/shadow"
        );
    }

    #[test]
    fn test_normalize_path_six_level_encoding_decodes_fully() {
        // Build a 6-level encoded 'p': p → %70 → %2570 → %252570 → %25252570 → %2525252570 → %252525252570
        // Previous 5-iteration limit would fail to fully decode this.
        let result = PolicyEngine::normalize_path("/etc/%252525252570asswd");
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
        let result = PolicyEngine::normalize_path(&input);
        assert_eq!(
            result, "/",
            "Encoding requiring >20 decode iterations should fail-closed to root"
        );
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
        // Build a structure deeper than MAX_SCAN_DEPTH
        let mut val = json!("deep_secret");
        for _ in 0..40 {
            val = json!({"nested": val});
        }
        let values = PolicyEngine::collect_all_string_values(&val);
        // The string is at depth 40, but our limit is 32 — it should NOT be found
        assert!(
            values.is_empty(),
            "Values beyond MAX_SCAN_DEPTH should not be collected"
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
                        let once = PolicyEngine::normalize_path(&path);
                        let twice = PolicyEngine::normalize_path(&once);
                        prop_assert_eq!(
                            &once, &twice,
                            "normalize_path must be idempotent: '{}' -> '{}' -> '{}'",
                            path, once, twice
                        );
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
                        let once = PolicyEngine::normalize_path(&input);
                        let twice = PolicyEngine::normalize_path(&once);
                        prop_assert_eq!(
                            &once, &twice,
                            "normalize_path must be idempotent on encoded input: '{}' -> '{}' -> '{}'",
                            input, once, twice
                        );
                    }

                    /// normalize_path never returns an empty string.
                    #[test]
                    fn prop_normalize_path_never_empty(path in arb_path()) {
                        let result = PolicyEngine::normalize_path(&path);
                        prop_assert!(
                            !result.is_empty(),
                            "normalize_path must never return empty string for input '{}'",
                            path
                        );
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
}
