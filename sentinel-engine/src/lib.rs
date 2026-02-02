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
        } else if let Some((tool_pat, func_pat)) = id.split_once(':') {
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
    /// Pre-computed "Denied by policy '<name>'" reason string.
    pub deny_reason: String,
    /// Pre-computed "Approval required by policy '<name>'" reason string.
    pub approval_reason: String,
    /// Pre-computed "Parameter '<p>' is forbidden by policy '<name>'" for each forbidden param.
    pub forbidden_reasons: Vec<String>,
    /// Pre-computed "Required parameter '<p>' missing (policy '<name>')" for each required param.
    pub required_reasons: Vec<String>,
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

        let (require_approval, forbidden_parameters, required_parameters, constraints) =
            match &policy.policy_type {
                PolicyType::Allow | PolicyType::Deny => (false, Vec::new(), Vec::new(), Vec::new()),
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

        Ok(CompiledPolicy {
            policy: policy.clone(),
            tool_matcher,
            require_approval,
            forbidden_parameters,
            required_parameters,
            constraints,
            deny_reason,
            approval_reason,
            forbidden_reasons,
            required_reasons,
        })
    }

    /// Compile condition JSON into pre-parsed fields and compiled constraints.
    ///
    /// Returns: (require_approval, forbidden_parameters, required_parameters, constraints)
    #[allow(clippy::type_complexity)]
    fn compile_conditions(
        policy: &Policy,
        conditions: &serde_json::Value,
        strict_mode: bool,
    ) -> Result<(bool, Vec<String>, Vec<String>, Vec<CompiledConstraint>), PolicyValidationError>
    {
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
    /// slice to [`evaluate_action`] to avoid re-sorting on every evaluation.
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
    /// [`sort_policies`]. If not pre-sorted, this method will sort a temporary
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
                    return self.apply_policy(action, policy);
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
                    return self.apply_policy(action, policy);
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
                    return self.apply_compiled_policy(action, cp);
                }
            }
        } else {
            // No index: linear scan (legacy compiled path)
            for cp in &self.compiled_policies {
                if cp.tool_matcher.matches(action) {
                    return self.apply_compiled_policy(action, cp);
                }
            }
        }

        Ok(Verdict::Deny {
            reason: "No matching policy".to_string(),
        })
    }

    /// Apply a matched compiled policy to produce a verdict.
    fn apply_compiled_policy(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<Verdict, EngineError> {
        match &cp.policy.policy_type {
            PolicyType::Allow => Ok(Verdict::Allow),
            PolicyType::Deny => Ok(Verdict::Deny {
                reason: cp.deny_reason.clone(),
            }),
            PolicyType::Conditional { .. } => self.evaluate_compiled_conditions(action, cp),
        }
    }

    /// Evaluate pre-compiled conditions against an action.
    fn evaluate_compiled_conditions(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<Verdict, EngineError> {
        // Check require_approval first
        if cp.require_approval {
            return Ok(Verdict::RequireApproval {
                reason: cp.approval_reason.clone(),
            });
        }

        // Check forbidden parameters
        for (i, param_str) in cp.forbidden_parameters.iter().enumerate() {
            if action.parameters.get(param_str).is_some() {
                return Ok(Verdict::Deny {
                    reason: cp.forbidden_reasons[i].clone(),
                });
            }
        }

        // Check required parameters
        for (i, param_str) in cp.required_parameters.iter().enumerate() {
            if action.parameters.get(param_str).is_none() {
                return Ok(Verdict::Deny {
                    reason: cp.required_reasons[i].clone(),
                });
            }
        }

        // Evaluate compiled constraints
        for constraint in &cp.constraints {
            if let Some(verdict) =
                self.evaluate_compiled_constraint(action, &cp.policy, constraint)?
            {
                return Ok(verdict);
            }
        }

        Ok(Verdict::Allow)
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

        // Evaluate parameter constraints
        if let Some(constraints) = conditions.get("parameter_constraints") {
            if let Some(arr) = constraints.as_array() {
                if let Some(verdict) = self.evaluate_parameter_constraints(action, policy, arr)? {
                    return Ok(verdict);
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

        // If no conditions triggered denial, allow
        Ok(Verdict::Allow)
    }

    /// Evaluate an array of parameter constraints against the action.
    ///
    /// Returns `Ok(Some(verdict))` if a constraint fires, `Ok(None)` if all pass.
    fn evaluate_parameter_constraints(
        &self,
        action: &Action,
        policy: &Policy,
        constraints: &[serde_json::Value],
    ) -> Result<Option<Verdict>, EngineError> {
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

            if let Some(verdict) =
                self.evaluate_single_constraint(policy, param_name, op, on_match, param_value, obj)?
            {
                return Ok(Some(verdict));
            }
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
        // Max 5 iterations prevents DoS from deeply-nested encodings.
        //
        // Uses Cow to avoid allocation when no percent sequences are present.
        let mut current = std::borrow::Cow::Borrowed(raw);
        for _ in 0..5 {
            let decoded = percent_encoding::percent_decode_str(&current).decode_utf8_lossy();
            if decoded.contains('\0') {
                return "/".to_string();
            }
            if decoded.as_ref() == current.as_ref() {
                break; // Stable — no more percent sequences to decode
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
        let authority = without_scheme.split('/').next().unwrap_or(without_scheme);

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
    /// Returns `None` if any segment along the path is missing or not an object.
    pub fn get_param_by_path<'a>(
        params: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let mut current = params;
        for segment in path.split('.') {
            current = current.get(segment)?;
        }
        Some(current)
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
    /// Opt-in alternative to [`evaluate_action`] that records per-policy match
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
                verdict_contribution: Some(verdict.clone()),
            };
            policy_matches.push(pm);

            if final_verdict.is_none() {
                final_verdict = Some(verdict);
            }
            // First match wins — stop checking further policies
            break;
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
    fn apply_compiled_policy_traced(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<(Verdict, Vec<ConstraintResult>), EngineError> {
        match &cp.policy.policy_type {
            PolicyType::Allow => Ok((Verdict::Allow, Vec::new())),
            PolicyType::Deny => Ok((
                Verdict::Deny {
                    reason: cp.deny_reason.clone(),
                },
                Vec::new(),
            )),
            PolicyType::Conditional { .. } => self.evaluate_compiled_conditions_traced(action, cp),
        }
    }

    /// Evaluate compiled conditions with full constraint tracing.
    fn evaluate_compiled_conditions_traced(
        &self,
        action: &Action,
        cp: &CompiledPolicy,
    ) -> Result<(Verdict, Vec<ConstraintResult>), EngineError> {
        let mut results: Vec<ConstraintResult> = Vec::new();

        // Check require_approval
        if cp.require_approval {
            results.push(ConstraintResult {
                constraint_type: "require_approval".to_string(),
                param: "".to_string(),
                expected: "true".to_string(),
                actual: "true".to_string(),
                passed: false,
            });
            return Ok((
                Verdict::RequireApproval {
                    reason: cp.approval_reason.clone(),
                },
                results,
            ));
        }

        // Check forbidden parameters
        for (i, param_str) in cp.forbidden_parameters.iter().enumerate() {
            let present = action.parameters.get(param_str).is_some();
            results.push(ConstraintResult {
                constraint_type: "forbidden_parameter".to_string(),
                param: param_str.clone(),
                expected: "absent".to_string(),
                actual: if present { "present" } else { "absent" }.to_string(),
                passed: !present,
            });
            if present {
                return Ok((
                    Verdict::Deny {
                        reason: cp.forbidden_reasons[i].clone(),
                    },
                    results,
                ));
            }
        }

        // Check required parameters
        for (i, param_str) in cp.required_parameters.iter().enumerate() {
            let present = action.parameters.get(param_str).is_some();
            results.push(ConstraintResult {
                constraint_type: "required_parameter".to_string(),
                param: param_str.clone(),
                expected: "present".to_string(),
                actual: if present { "present" } else { "absent" }.to_string(),
                passed: present,
            });
            if !present {
                return Ok((
                    Verdict::Deny {
                        reason: cp.required_reasons[i].clone(),
                    },
                    results,
                ));
            }
        }

        // Evaluate compiled constraints
        for constraint in &cp.constraints {
            let (maybe_verdict, constraint_result) =
                self.evaluate_compiled_constraint_traced(action, &cp.policy, constraint)?;
            results.extend(constraint_result);
            if let Some(verdict) = maybe_verdict {
                return Ok((verdict, results));
            }
        }

        Ok((Verdict::Allow, results))
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
        }]
    }

    fn action_with(tool: &str, func: &str, params: serde_json::Value) -> Action {
        Action {
            tool: tool.to_string(),
            function: func.to_string(),
            parameters: params,
        }
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
        assert!(matches!(verdict, Verdict::Allow));
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
        assert!(matches!(verdict, Verdict::Allow));
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
        }
    }

    #[test]
    fn test_wildcard_scan_catches_nested_url() {
        // A dangerous URL buried in nested parameters should be caught
        let engine = PolicyEngine::new(false);
        let policy = make_wildcard_policy("domain_match", json!({"pattern": "*.evil.com"}));

        let action = Action {
            tool: "test".to_string(),
            function: "call".to_string(),
            parameters: json!({
                "options": {
                    "target": "https://data.evil.com/exfil",
                    "retries": 3
                }
            }),
        };

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

        let action = Action {
            tool: "test".to_string(),
            function: "call".to_string(),
            parameters: json!({
                "url": "https://safe.example.com/api",
                "data": "hello world"
            }),
        };

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

        let action = Action {
            tool: "test".to_string(),
            function: "batch_read".to_string(),
            parameters: json!({
                "files": [
                    "/tmp/safe.txt",
                    "/home/user/.ssh/id_rsa",
                    "/var/log/syslog"
                ]
            }),
        };

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

        let action = Action {
            tool: "test".to_string(),
            function: "execute".to_string(),
            parameters: json!({
                "task": "cleanup",
                "steps": [
                    { "cmd": "ls -la /tmp" },
                    { "cmd": "rm -rf /" },
                    { "cmd": "echo done" }
                ]
            }),
        };

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

        let action = Action {
            tool: "test".to_string(),
            function: "call".to_string(),
            parameters: json!({
                "count": 42,
                "enabled": true
            }),
        };

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Deny { .. }),
            "Should deny: no string values found (fail-closed), got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_no_string_values_on_missing_skip() {
        // Parameters with only numbers — but on_missing=skip → should continue
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
        };

        let action = Action {
            tool: "test".to_string(),
            function: "call".to_string(),
            parameters: json!({
                "count": 42,
                "enabled": true
            }),
        };

        let result = engine.evaluate_action(&action, &[policy]).unwrap();
        assert!(
            matches!(result, Verdict::Allow),
            "Should allow: no string values but on_missing=skip, got: {:?}",
            result
        );
    }

    #[test]
    fn test_wildcard_scan_deeply_nested_value() {
        // Value buried 5 levels deep
        let engine = PolicyEngine::new(false);
        let policy = make_wildcard_policy("glob", json!({"pattern": "/etc/shadow"}));

        let action = Action {
            tool: "test".to_string(),
            function: "call".to_string(),
            parameters: json!({
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
        };

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
        };

        let action = Action {
            tool: "test".to_string(),
            function: "call".to_string(),
            parameters: json!({
                "query": "SELECT * FROM users WHERE password = '123'"
            }),
        };

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
        };

        // mode=safe fires first → allow
        let action1 = Action {
            tool: "test".to_string(),
            function: "call".to_string(),
            parameters: json!({
                "mode": "safe",
                "path": "/etc/shadow"
            }),
        };
        let result1 = engine
            .evaluate_action(&action1, std::slice::from_ref(&policy))
            .unwrap();
        assert!(
            matches!(result1, Verdict::Allow),
            "First constraint (mode=safe→allow) should fire first, got: {:?}",
            result1
        );

        // mode=other → doesn't match eq, wildcard scans and finds /etc/shadow → deny
        let action2 = Action {
            tool: "test".to_string(),
            function: "call".to_string(),
            parameters: json!({
                "mode": "other",
                "path": "/etc/shadow"
            }),
        };
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
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let bash_action = Action {
            tool: "bash".to_string(),
            function: "execute".to_string(),
            parameters: json!({}),
        };
        let verdict = engine.evaluate_action(&bash_action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));

        let safe_action = Action {
            tool: "file_system".to_string(),
            function: "read".to_string(),
            parameters: json!({}),
        };
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
            },
            Policy {
                id: "bash:*".to_string(),
                name: "High priority deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
            },
        ];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        // High priority deny should win even though allow was listed first
        let action = Action {
            tool: "bash".to_string(),
            function: "execute".to_string(),
            parameters: json!({}),
        };
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
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = Action {
            tool: "network".to_string(),
            function: "connect".to_string(),
            parameters: json!({}),
        };
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
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        // Missing param → deny (fail-closed)
        let action = action_with("file", "read", json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_compiled_on_missing_skip() {
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
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();

        let action = action_with("file", "read", json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
    }

    #[test]
    fn test_compiled_empty_policies_deny() {
        let engine = PolicyEngine::with_policies(false, &[]).unwrap();
        let action = Action {
            tool: "any".to_string(),
            function: "any".to_string(),
            parameters: json!({}),
        };
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
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
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
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
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
        let action = Action {
            tool: "file_system".to_string(),
            function: "read_file".to_string(),
            parameters: json!({}),
        };

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
            },
            Policy {
                id: "file_system:read_file".to_string(),
                name: "Block file read".to_string(),
                policy_type: PolicyType::Deny,
                priority: 150,
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 1,
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
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Exact tool".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
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
            });
        }
        policies.push(Policy {
            id: "*".to_string(),
            name: "Default allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
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
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Deny bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
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
            },
            Policy {
                id: "*".to_string(),
                name: "Universal deny".to_string(),
                policy_type: PolicyType::Deny,
                priority: 150,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Allow all bash".to_string(),
                policy_type: PolicyType::Allow,
                priority: 100,
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
        assert_eq!(forbidden.actual, "present");
        assert!(!forbidden.passed);
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
            },
            Policy {
                id: "*".to_string(),
                name: "Allow all".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
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
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = action_with("bash", "execute", json!({}));

        let (_, trace) = engine.evaluate_action_traced(&action).unwrap();
        // Duration should be recorded (at least 0, could be 0 for very fast evaluation)
        assert!(trace.duration_us < 1_000_000); // Should be well under 1 second
    }
}
