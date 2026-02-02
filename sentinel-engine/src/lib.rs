use sentinel_types::{Action, Policy, PolicyType, Verdict};
use thiserror::Error;

use globset::Glob;
use regex::Regex;
use std::collections::HashMap;
use std::path::{Component, PathBuf};
use std::sync::Mutex;

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

/// Maximum number of cached compiled regex patterns.
const REGEX_CACHE_MAX: usize = 1000;

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
    regex_cache: Mutex<HashMap<String, Regex>>,
}

impl PolicyEngine {
    /// Create a new policy engine.
    ///
    /// When `strict_mode` is true, the engine applies stricter validation
    /// on conditions and parameters.
    pub fn new(strict_mode: bool) -> Self {
        Self {
            strict_mode,
            regex_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Sort policies by priority (highest first), with deny-overrides at equal priority.
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
            b_deny.cmp(&a_deny)
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
        if policies.is_empty() {
            return Ok(Verdict::Deny {
                reason: "No policies defined".to_string(),
            });
        }

        // Check if already sorted (by priority desc, deny-first at equal priority)
        let is_sorted = policies.windows(2).all(|w| {
            let pri = w[0].priority.cmp(&w[1].priority);
            if pri == std::cmp::Ordering::Equal {
                // At equal priority, deny must come before allow
                let a_deny = matches!(w[0].policy_type, PolicyType::Deny);
                let b_deny = matches!(w[1].policy_type, PolicyType::Deny);
                // OK if first is deny and second isn't, or both same type
                b_deny <= a_deny
            } else {
                // Higher priority must come first
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
        let matcher = Glob::new(pattern_str)
            .map_err(|e| EngineError::InvalidCondition {
                policy_id: policy.id.clone(),
                reason: format!("Invalid glob pattern '{}': {}", pattern_str, e),
            })?
            .compile_matcher();

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
            let matcher = Glob::new(pat_str)
                .map_err(|e| EngineError::InvalidCondition {
                    policy_id: policy.id.clone(),
                    reason: format!("Invalid glob pattern '{}': {}", pat_str, e),
                })?
                .compile_matcher();
            if matcher.is_match(&normalized) {
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
        // This prevents bypass via encoded characters (e.g., /etc/%70asswd → /etc/passwd).
        // Single-pass decode only — double-encoded inputs are left partially encoded,
        // which is intentional to prevent double-decode vulnerabilities.
        let decoded = percent_encoding::percent_decode_str(raw).decode_utf8_lossy();

        // After decoding, check for null bytes again (could have been encoded as %00)
        if decoded.contains('\0') {
            return "/".to_string();
        }

        let path = PathBuf::from(decoded.as_ref());
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
        let s = result.to_string_lossy().to_string();
        if s.is_empty() {
            // Fix #9: Return "/" (root) instead of the raw input when normalization
            // produces an empty string. The raw input contains the traversal sequences
            // that normalization was supposed to remove.
            "/".to_string()
        } else {
            s
        }
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
        decoded_host.to_lowercase()
    }

    /// Match a domain against a pattern like `*.example.com` or `example.com`.
    pub fn match_domain_pattern(domain: &str, pattern: &str) -> bool {
        let domain = domain.to_lowercase();
        let pattern = pattern.to_lowercase();

        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard: domain must end with .suffix or be exactly suffix
            domain == suffix || domain.ends_with(&format!(".{}", suffix))
        } else {
            domain == pattern
        }
    }

    /// Compile and cache a regex pattern, returning whether it matches the input.
    ///
    /// The cache is bounded to [`REGEX_CACHE_MAX`] entries to prevent memory bloat.
    /// When the cache is full, it is cleared before inserting the new pattern.
    fn regex_is_match(
        &self,
        pattern: &str,
        input: &str,
        policy_id: &str,
    ) -> Result<bool, EngineError> {
        let mut cache = self.regex_cache.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(re) = cache.get(pattern) {
            return Ok(re.is_match(input));
        }

        let re = Regex::new(pattern).map_err(|e| EngineError::InvalidCondition {
            policy_id: policy_id.to_string(),
            reason: format!("Invalid regex pattern '{}': {}", pattern, e),
        })?;

        let result = re.is_match(input);

        if cache.len() >= REGEX_CACHE_MAX {
            cache.clear();
        }
        cache.insert(pattern.to_string(), re);

        Ok(result)
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
}
