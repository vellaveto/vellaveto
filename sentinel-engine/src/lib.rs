pub mod behavioral;
pub mod circuit_breaker;
mod compiled;
pub mod deputy;
mod domain;
mod error;
mod ip;
mod matcher;
mod path;

pub use compiled::{
    CompiledConstraint, CompiledContextCondition, CompiledIpRules, CompiledNetworkRules,
    CompiledPathRules, CompiledPolicy,
};
use compiled::CompiledConditions;
pub use error::{EngineError, PolicyValidationError};
pub use matcher::{CompiledToolMatcher, PatternMatcher};
pub use path::DEFAULT_MAX_PATH_DECODE_ITERATIONS;

use sentinel_types::{
    Action, ActionSummary, ConstraintResult, EvaluationContext, EvaluationTrace, Policy,
    PolicyMatch, PolicyType, Verdict,
};

use chrono::{Datelike, Timelike};
use globset::{Glob, GlobMatcher};
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Instant;

/// Maximum number of compiled glob matchers kept in the legacy runtime cache.
const MAX_GLOB_MATCHER_CACHE_ENTRIES: usize = 2048;
/// Maximum number of domain normalization results kept in the runtime cache.
const MAX_DOMAIN_NORM_CACHE_ENTRIES: usize = 4096;

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
    /// Legacy runtime cache for glob matcher compilation.
    ///
    /// This cache is used by `glob_is_match` on the non-precompiled path.
    glob_matcher_cache: RwLock<HashMap<String, GlobMatcher>>,
    /// Runtime cache for domain normalization results.
    ///
    /// Caches both successful normalization (Some) and invalid domains (None)
    /// to avoid repeated IDNA parsing on hot network/domain constraint paths.
    domain_norm_cache: RwLock<HashMap<String, Option<String>>>,
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
            .field(
                "glob_matcher_cache_size",
                &self
                    .glob_matcher_cache
                    .read()
                    .map(|c| c.len())
                    .unwrap_or_default(),
            )
            .field(
                "domain_norm_cache_size",
                &self
                    .domain_norm_cache
                    .read()
                    .map(|c| c.len())
                    .unwrap_or_default(),
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
            glob_matcher_cache: RwLock::new(HashMap::with_capacity(256)),
            domain_norm_cache: RwLock::new(HashMap::with_capacity(
                MAX_DOMAIN_NORM_CACHE_ENTRIES.min(512),
            )),
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
    ///
    /// See [`domain::validate_domain_pattern`] for details.
    pub fn validate_domain_pattern(pattern: &str) -> Result<(), String> {
        domain::validate_domain_pattern(pattern)
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
            glob_matcher_cache: RwLock::new(HashMap::with_capacity(256)),
            domain_norm_cache: RwLock::new(HashMap::with_capacity(
                MAX_DOMAIN_NORM_CACHE_ENTRIES.min(512),
            )),
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
        let mut index: HashMap<String, Vec<usize>> = HashMap::with_capacity(compiled.len());
        let mut always_check = Vec::with_capacity(compiled.len());
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

        let CompiledConditions {
            require_approval,
            forbidden_parameters,
            required_parameters,
            constraints,
            on_no_match_continue,
            context_conditions,
        } = match &policy.policy_type {
            PolicyType::Allow | PolicyType::Deny => CompiledConditions {
                require_approval: false,
                forbidden_parameters: Vec::new(),
                required_parameters: Vec::new(),
                constraints: Vec::new(),
                on_no_match_continue: false,
                context_conditions: Vec::new(),
            },
            PolicyType::Conditional { conditions } => {
                Self::compile_conditions(policy, conditions, strict_mode)?
            }
            // Handle future variants - treat as Allow with no conditions
            _ => CompiledConditions {
                require_approval: false,
                forbidden_parameters: Vec::new(),
                required_parameters: Vec::new(),
                constraints: Vec::new(),
                on_no_match_continue: false,
                context_conditions: Vec::new(),
            },
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
    fn compile_conditions(
        policy: &Policy,
        conditions: &serde_json::Value,
        strict_mode: bool,
    ) -> Result<CompiledConditions, PolicyValidationError> {
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

        let constraints = if let Some(constraint_arr) = conditions.get("parameter_constraints") {
            let arr = constraint_arr
                .as_array()
                .ok_or_else(|| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: "parameter_constraints must be an array".to_string(),
                })?;

            let mut constraints = Vec::with_capacity(arr.len());
            for constraint_val in arr {
                constraints.push(Self::compile_constraint(policy, constraint_val)?);
            }
            constraints
        } else {
            Vec::new()
        };

        // Parse context conditions (session-level checks)
        let context_conditions = if let Some(ctx_arr) = conditions.get("context_conditions") {
            let arr = ctx_arr.as_array().ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "context_conditions must be an array".to_string(),
            })?;

            let mut context_conditions = Vec::with_capacity(arr.len());
            for ctx_val in arr {
                context_conditions.push(Self::compile_context_condition(policy, ctx_val)?);
            }
            context_conditions
        } else {
            Vec::new()
        };

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

        Ok(CompiledConditions {
            require_approval,
            forbidden_parameters,
            required_parameters,
            constraints,
            on_no_match_continue,
            context_conditions,
        })
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
                // R36-ENG-1: lowercase tool_pattern at compile time so
                // PatternMatcher::matches() (case-sensitive) agrees with
                // the lowercased call_count keys built at evaluation time.
                let tool_pattern = obj
                    .get("tool_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_ascii_lowercase();
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
                // R36-ENG-1: lowercase tool_pattern at compile time so
                // PatternMatcher::matches() (case-sensitive) agrees with
                // the lowercased previous_actions built at evaluation time.
                let tool_pattern = obj
                    .get("tool_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_ascii_lowercase();
                let max = obj.get("max").and_then(|v| v.as_u64()).ok_or_else(|| {
                    PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "max_calls_in_window missing 'max' integer".to_string(),
                    }
                })?;
                // SECURITY (R34-ENG-2): Use try_from instead of `as usize` to
                // avoid silent truncation on 32-bit platforms where u64 > usize::MAX.
                let window =
                    usize::try_from(obj.get("window").and_then(|v| v.as_u64()).unwrap_or(0))
                        .unwrap_or(usize::MAX);
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
                // SECURITY (R33-ENG-3): Use try_from instead of `as usize` to
                // avoid silent truncation on 32-bit platforms where u64 > usize::MAX.
                let raw_depth = obj
                    .get("max_depth")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "max_chain_depth missing 'max_depth' integer".to_string(),
                    })?;
                let max_depth = usize::try_from(raw_depth).map_err(|_| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "max_chain_depth value {} exceeds platform maximum",
                        raw_depth
                    ),
                })?;
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
                // SECURITY: Normalize required fields to lowercase for case-insensitive
                // matching, consistent with blocked_issuers/blocked_subjects (R40-ENG-2)
                let required_issuer = obj
                    .get("issuer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase());
                let required_subject = obj
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase());
                let required_audience = obj
                    .get("audience")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase());

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

            // ═══════════════════════════════════════════════════
            // MCP 2025-11-25 CONTEXT CONDITIONS
            // ═══════════════════════════════════════════════════
            "async_task_policy" => {
                // MCP 2025-11-25: Async task lifecycle policy
                let max_concurrent = obj
                    .get("max_concurrent")
                    .and_then(|v| v.as_u64())
                    .map(|v| usize::try_from(v).unwrap_or(usize::MAX))
                    .unwrap_or(0); // 0 = unlimited

                let max_duration_secs = obj
                    .get("max_duration_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0); // 0 = unlimited

                let require_self_cancel = obj
                    .get("require_self_cancel")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true); // Default: only creator can cancel

                let deny_reason =
                    format!("Async task policy violated for policy '{}'", policy.name);

                Ok(CompiledContextCondition::AsyncTaskPolicy {
                    max_concurrent,
                    max_duration_secs,
                    require_self_cancel,
                    deny_reason,
                })
            }

            "resource_indicator" => {
                // RFC 8707: OAuth 2.0 Resource Indicators
                let allowed_resources: Vec<PatternMatcher> = obj
                    .get("allowed_resources")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(PatternMatcher::compile)
                            .collect()
                    })
                    .unwrap_or_default();

                let require_resource = obj
                    .get("require_resource")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let deny_reason = format!(
                    "Resource indicator validation failed for policy '{}'",
                    policy.name
                );

                Ok(CompiledContextCondition::ResourceIndicator {
                    allowed_resources,
                    require_resource,
                    deny_reason,
                })
            }

            "capability_required" => {
                // CIMD: Capability-Indexed Message Dispatch
                let required_capabilities: Vec<String> = obj
                    .get("required_capabilities")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                let blocked_capabilities: Vec<String> = obj
                    .get("blocked_capabilities")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                let deny_reason = format!(
                    "Capability requirement not met for policy '{}'",
                    policy.name
                );

                Ok(CompiledContextCondition::CapabilityRequired {
                    required_capabilities,
                    blocked_capabilities,
                    deny_reason,
                })
            }

            "step_up_auth" => {
                // Step-up authentication
                let required_level_u64 = obj
                    .get("required_level")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "step_up_auth missing 'required_level' integer".to_string(),
                    })?;

                // Validate level is in valid range (0-4)
                if required_level_u64 > 4 {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "step_up_auth required_level must be 0-4, got {}",
                            required_level_u64
                        ),
                    });
                }

                let required_level = required_level_u64 as u8;

                let deny_reason = format!(
                    "Step-up authentication required (level {}) for policy '{}'",
                    required_level, policy.name
                );

                Ok(CompiledContextCondition::StepUpAuth {
                    required_level,
                    deny_reason,
                })
            }

            // ═══════════════════════════════════════════════════
            // PHASE 2: ADVANCED THREAT DETECTION CONDITIONS
            // ═══════════════════════════════════════════════════
            "circuit_breaker" => {
                // OWASP ASI08: Cascading failure protection
                let tool_pattern = obj
                    .get("tool_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_ascii_lowercase();

                let deny_reason = format!(
                    "Circuit breaker open for tool pattern '{}' (policy '{}')",
                    tool_pattern, policy.name
                );

                Ok(CompiledContextCondition::CircuitBreaker {
                    tool_pattern: PatternMatcher::compile(&tool_pattern),
                    deny_reason,
                })
            }

            "deputy_validation" => {
                // OWASP ASI02: Confused deputy prevention
                let require_principal = obj
                    .get("require_principal")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                let max_delegation_depth_u64 = obj
                    .get("max_delegation_depth")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(3);

                // Validate depth is reasonable
                if max_delegation_depth_u64 > 255 {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "deputy_validation max_delegation_depth must be 0-255, got {}",
                            max_delegation_depth_u64
                        ),
                    });
                }

                let max_delegation_depth = max_delegation_depth_u64 as u8;

                let deny_reason = format!("Deputy validation failed for policy '{}'", policy.name);

                Ok(CompiledContextCondition::DeputyValidation {
                    require_principal,
                    max_delegation_depth,
                    deny_reason,
                })
            }

            "shadow_agent_check" => {
                // Shadow agent detection
                let require_known_fingerprint = obj
                    .get("require_known_fingerprint")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let min_trust_level_u64 = obj
                    .get("min_trust_level")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1); // Default: Low trust

                // Validate level is in valid range (0-4)
                if min_trust_level_u64 > 4 {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "shadow_agent_check min_trust_level must be 0-4, got {}",
                            min_trust_level_u64
                        ),
                    });
                }

                let min_trust_level = min_trust_level_u64 as u8;

                let deny_reason = format!("Shadow agent check failed for policy '{}'", policy.name);

                Ok(CompiledContextCondition::ShadowAgentCheck {
                    require_known_fingerprint,
                    min_trust_level,
                    deny_reason,
                })
            }

            "schema_poisoning_check" => {
                // OWASP ASI05: Schema poisoning protection
                let mutation_threshold = obj
                    .get("mutation_threshold")
                    .and_then(|v| v.as_f64())
                    .map(|v| v as f32)
                    .unwrap_or(0.1); // Default: 10% change triggers alert

                // Validate threshold is in valid range
                if !mutation_threshold.is_finite() || !(0.0..=1.0).contains(&mutation_threshold) {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "schema_poisoning_check mutation_threshold must be in [0.0, 1.0], got {}",
                            mutation_threshold
                        ),
                    });
                }

                let deny_reason = format!("Schema poisoning detected for policy '{}'", policy.name);

                Ok(CompiledContextCondition::SchemaPoisoningCheck {
                    mutation_threshold,
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
            // Handle future variants - fail closed (deny)
            _ => Ok(Some(Verdict::Deny {
                reason: format!("Unknown policy type for '{}'", cp.policy.name),
            })),
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
                    // SECURITY (R34-ENG-5): Case-insensitive matching for consistency
                    // with ForbiddenPreviousAction/RequirePreviousAction (R31-ENG-7).
                    let count = if matches!(tool_pattern, PatternMatcher::Any) {
                        context
                            .call_counts
                            .values()
                            .fold(0u64, |acc, v| acc.saturating_add(*v))
                    } else {
                        context
                            .call_counts
                            .iter()
                            .filter(|(name, _)| tool_pattern.matches(&name.to_ascii_lowercase()))
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
                    // SECURITY (R31-ENG-7): Case-insensitive comparison to prevent
                    // bypass via tool name casing variations (e.g., "Read_File" vs "read_file").
                    if !context
                        .previous_actions
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case(required_tool))
                    {
                        return Some(Verdict::Deny {
                            reason: deny_reason.clone(),
                        });
                    }
                }
                CompiledContextCondition::ForbiddenPreviousAction {
                    forbidden_tool,
                    deny_reason,
                } => {
                    // SECURITY (R31-ENG-7): Case-insensitive comparison.
                    if context
                        .previous_actions
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case(forbidden_tool))
                    {
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
                    // SECURITY (R34-ENG-5): Case-insensitive matching for consistency
                    // with ForbiddenPreviousAction/RequirePreviousAction (R31-ENG-7).
                    let count_usize = history
                        .iter()
                        .filter(|a| tool_pattern.matches(&a.to_ascii_lowercase()))
                        .count();
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

                            // Check required issuer (case-insensitive, R40-ENG-2)
                            if let Some(ref req_iss) = required_issuer {
                                match &identity.issuer {
                                    Some(iss) if iss.to_lowercase() == *req_iss => {}
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

                            // Check required subject (case-insensitive, R40-ENG-2)
                            if let Some(ref req_sub) = required_subject {
                                match &identity.subject {
                                    Some(sub) if sub.to_lowercase() == *req_sub => {}
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

                            // Check required audience (case-insensitive, R40-ENG-2)
                            if let Some(ref req_aud) = required_audience {
                                if !identity
                                    .audience
                                    .iter()
                                    .any(|a| a.to_lowercase() == *req_aud)
                                {
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
                            // SECURITY (R38-ENG-1, R39-ENG-1): Even without require_attestation,
                            // deny if specific identity requirements or blocklists are configured.
                            // Otherwise an attacker can bypass issuer/subject/audience/claims
                            // checks — or blocklist enforcement — by simply omitting the
                            // X-Agent-Identity header.
                            if required_issuer.is_some()
                                || required_subject.is_some()
                                || required_audience.is_some()
                                || !required_claims.is_empty()
                                || !blocked_issuers.is_empty()
                                || !blocked_subjects.is_empty()
                            {
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{} (identity restrictions configured but no agent identity header provided)",
                                        deny_reason
                                    ),
                                });
                            }
                            // Fall back to legacy agent_id matching is handled by AgentId condition
                        }
                    }
                }

                // ═══════════════════════════════════════════════════
                // MCP 2025-11-25 CONTEXT CONDITIONS EVALUATION
                // ═══════════════════════════════════════════════════
                CompiledContextCondition::AsyncTaskPolicy {
                    max_concurrent,
                    max_duration_secs: _,
                    require_self_cancel: _,
                    deny_reason: _,
                } => {
                    // MCP 2025-11-25: Async task policy check.
                    // Note: max_concurrent is checked at task creation time via TaskStateManager.
                    // This condition is evaluated here for policy matching, but actual enforcement
                    // happens in the MCP proxy layer when handling tasks/* methods.
                    //
                    // Here we just validate that if max_concurrent is set, we would
                    // log/trace the policy applicability. The actual task count check
                    // happens in sentinel-mcp/src/task_state.rs.
                    if *max_concurrent > 0 {
                        tracing::trace!(
                            policy = %cp.policy.name,
                            max_concurrent = %max_concurrent,
                            "async_task_policy condition active"
                        );
                    }
                    // Continue to next condition - actual enforcement is at task creation
                }

                CompiledContextCondition::ResourceIndicator {
                    allowed_resources,
                    require_resource,
                    deny_reason,
                } => {
                    // RFC 8707: OAuth 2.0 Resource Indicators
                    // The resource indicator should be stored in context by the OAuth layer.
                    // We check for it in agent_identity claims where oauth_resource is set.
                    let resource = context
                        .agent_identity
                        .as_ref()
                        .and_then(|id| id.claim_str("resource"));

                    match resource {
                        Some(res) => {
                            // Check if resource matches any allowed pattern
                            if !allowed_resources.is_empty() {
                                let matches = allowed_resources.iter().any(|p| p.matches(res));
                                if !matches {
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{} (resource '{}' not in allowed list)",
                                            deny_reason, res
                                        ),
                                    });
                                }
                            }
                        }
                        None => {
                            if *require_resource {
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{} (resource indicator required but not present)",
                                        deny_reason
                                    ),
                                });
                            }
                        }
                    }
                }

                CompiledContextCondition::CapabilityRequired {
                    required_capabilities,
                    blocked_capabilities,
                    deny_reason,
                } => {
                    // CIMD: Capability-Indexed Message Dispatch
                    // Capabilities are stored in agent_identity claims as a comma-separated
                    // string or as a JSON array under the "capabilities" claim.
                    let declared_caps: Vec<&str> = context
                        .agent_identity
                        .as_ref()
                        .and_then(|id| {
                            // Try array first, then comma-separated string
                            id.claim_str_array("capabilities")
                                .map(|arr| arr.into_iter().collect())
                                .or_else(|| {
                                    id.claim_str("capabilities")
                                        .map(|s| s.split(',').map(str::trim).collect())
                                })
                        })
                        .unwrap_or_default();

                    // Check blocked capabilities first
                    for blocked in blocked_capabilities {
                        if declared_caps.iter().any(|&c| c == blocked) {
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{} (blocked capability '{}' is declared)",
                                    deny_reason, blocked
                                ),
                            });
                        }
                    }

                    // Check required capabilities
                    for required in required_capabilities {
                        if !declared_caps.iter().any(|&c| c == required) {
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{} (required capability '{}' not declared)",
                                    deny_reason, required
                                ),
                            });
                        }
                    }
                }

                CompiledContextCondition::StepUpAuth {
                    required_level,
                    deny_reason,
                } => {
                    // Step-up authentication check
                    // The current auth level is stored in agent_identity claims as "auth_level"
                    let current_level: u8 = context
                        .agent_identity
                        .as_ref()
                        .and_then(|id| id.claim_str("auth_level"))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0); // Default to None (0)

                    if current_level < *required_level {
                        // Return a special verdict that signals step-up is needed
                        // The proxy layer interprets this and issues an authentication challenge
                        return Some(Verdict::RequireApproval {
                            reason: format!(
                                "{} (current level {}, required {})",
                                deny_reason, current_level, required_level
                            ),
                        });
                    }
                }

                // ═══════════════════════════════════════════════════
                // PHASE 2: ADVANCED THREAT DETECTION CONDITION CHECKS
                // ═══════════════════════════════════════════════════
                CompiledContextCondition::CircuitBreaker {
                    tool_pattern: _,
                    deny_reason: _,
                } => {
                    // OWASP ASI08: Circuit breaker check
                    // Note: Actual circuit breaker state is maintained by CircuitBreakerManager
                    // in sentinel-engine/src/circuit_breaker.rs. This condition is evaluated here
                    // for policy matching, but actual enforcement happens at the integration layer.
                    //
                    // The proxy/server checks CircuitBreakerManager.can_proceed() before evaluation
                    // and calls record_success/record_failure after the tool call completes.
                    //
                    // This condition acts as a marker to indicate circuit breaker applies to this policy.
                    tracing::trace!(
                        policy = %cp.policy.name,
                        "circuit_breaker condition active"
                    );
                    // Continue to next condition - enforcement is in the manager
                }

                CompiledContextCondition::DeputyValidation {
                    require_principal,
                    max_delegation_depth,
                    deny_reason,
                } => {
                    // OWASP ASI02: Confused deputy prevention
                    // Check principal context if available
                    // Principal context is stored in agent_identity claims
                    let has_principal =
                        context.agent_identity.is_some() || context.agent_id.is_some();

                    if *require_principal && !has_principal {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{} (principal required but not identified)",
                                deny_reason
                            ),
                        });
                    }

                    // Check delegation depth from call chain
                    // The call chain represents the delegation chain in multi-agent scenarios
                    let delegation_depth = context.call_chain.len();
                    if delegation_depth > *max_delegation_depth as usize {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{} (delegation depth {} exceeds max {})",
                                deny_reason, delegation_depth, max_delegation_depth
                            ),
                        });
                    }
                }

                CompiledContextCondition::ShadowAgentCheck {
                    require_known_fingerprint: _,
                    min_trust_level: _,
                    deny_reason: _,
                } => {
                    // Shadow agent detection
                    // Note: Actual fingerprint matching is done by ShadowAgentDetector
                    // in sentinel-mcp/src/shadow_agent.rs. This condition is evaluated here
                    // for policy matching, but actual enforcement happens at the integration layer.
                    //
                    // The proxy extracts fingerprint from request context and checks against
                    // known agents before policy evaluation.
                    tracing::trace!(
                        policy = %cp.policy.name,
                        "shadow_agent_check condition active"
                    );
                    // Continue to next condition - enforcement is in the detector
                }

                CompiledContextCondition::SchemaPoisoningCheck {
                    mutation_threshold: _,
                    deny_reason: _,
                } => {
                    // OWASP ASI05: Schema poisoning protection
                    // Note: Actual schema tracking is done by SchemaLineageTracker
                    // in sentinel-mcp/src/schema_poisoning.rs. This condition is evaluated here
                    // for policy matching, but actual enforcement happens at the integration layer.
                    //
                    // The proxy tracks schema observations and checks for mutations
                    // when tools are registered or called.
                    tracing::trace!(
                        policy = %cp.policy.name,
                        "schema_poisoning_check condition active"
                    );
                    // Continue to next condition - enforcement is in the tracker
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
            // SECURITY (R28-ENG-1): When an allowlist is configured but no
            // target paths were extracted, fail-closed. The absence of paths
            // means the extractor could not identify what the tool accesses,
            // so we cannot verify it's within the allowlist.
            if !rules.allowed.is_empty() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "No target paths provided but path allowlist is configured for policy '{}'",
                        cp.policy.name
                    ),
                });
            }
            return None; // Blocklist-only mode: nothing to block
        }

        for raw_path in &action.target_paths {
            let normalized =
                match Self::normalize_path_bounded(raw_path, self.max_path_decode_iterations) {
                    Ok(n) => n,
                    Err(e) => {
                        return Some(Verdict::Deny {
                            reason: format!("Path normalization failed: {}", e),
                        })
                    }
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
            // SECURITY (R28-ENG-1): When an allowed_domains list is configured
            // but no target domains were extracted, fail-closed. The absence of
            // domains means the extractor could not determine where the tool
            // connects, so we cannot verify it's within the allowlist.
            if !rules.allowed_domains.is_empty() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "No target domains provided but domain allowlist is configured for policy '{}'",
                        cp.policy.name
                    ),
                });
            }
            return None; // Blocklist-only mode: nothing to block
        }

        for raw_domain in &action.target_domains {
            let domain = raw_domain.to_lowercase();

            // SECURITY (R30-ENG-2): Fail-closed for non-ASCII domains that fail
            // IDNA normalization. Without this, match_domain_pattern returns false
            // for both allowed and blocked patterns → the domain bypasses blocklists.
            // If IDNA normalization fails for the domain and there are any network
            // rules configured, deny it rather than letting it through unchecked.
            if Self::normalize_domain_for_match(&domain).is_none() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Domain '{}' cannot be normalized (IDNA failure) — blocked by policy '{}'",
                        domain, cp.policy.name
                    ),
                });
            }

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

            // SECURITY (R24-ENG-1, R29-ENG-1): Canonicalize IPv6 transition
            // mechanism addresses to their embedded IPv4 form so that IPv4
            // CIDRs correctly match. This covers: mapped (::ffff:), compatible
            // (::x.x.x.x), 6to4 (2002::), Teredo (2001:0000::), NAT64
            // (64:ff9b::), and NAT64 local-use (64:ff9b:1::).
            let ip = match raw_ip {
                IpAddr::V6(ref v6) => {
                    if let Some(v4) = ip::extract_embedded_ipv4(v6) {
                        IpAddr::V4(v4)
                    } else {
                        raw_ip
                    }
                }
                _ => raw_ip,
            };

            // Check private IP blocking
            if ip_rules.block_private && ip::is_private_ip(ip) {
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
                let normalized =
                    match Self::normalize_path_bounded(raw, self.max_path_decode_iterations) {
                        Ok(n) => n,
                        Err(e) => {
                            return Ok(Some(Verdict::Deny {
                                reason: format!("Path normalization failed: {}", e),
                            }))
                        }
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
                let normalized =
                    match Self::normalize_path_bounded(raw, self.max_path_decode_iterations) {
                        Ok(n) => n,
                        Err(e) => {
                            return Ok(Some(Verdict::Deny {
                                reason: format!("Path normalization failed: {}", e),
                            }))
                        }
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
                // SECURITY (R31-ENG-1): Fail-closed on non-ASCII domains that fail IDNA
                // normalization. Without this, homoglyph domains (e.g., Cyrillic 'a') bypass
                // DomainMatch blocklists because the punycode form doesn't match the pattern.
                // This mirrors the guard in check_network_rules (R30-ENG-2).
                if !domain.is_ascii() && Self::normalize_domain_for_match(&domain).is_none() {
                    return Ok(Some(Self::make_constraint_verdict(
                        "deny",
                        &format!(
                            "Parameter '{}' domain '{}' cannot be normalized (IDNA failure) (policy '{}')",
                            param_name, domain, policy.name
                        ),
                    )?));
                }
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
                // SECURITY (R31-ENG-1): Same IDNA fail-closed guard as DomainMatch above.
                if !domain.is_ascii() && Self::normalize_domain_for_match(&domain).is_none() {
                    return Ok(Some(Self::make_constraint_verdict(
                        "deny",
                        &format!(
                            "Parameter '{}' domain '{}' cannot be normalized (IDNA failure) (policy '{}')",
                            param_name, domain, policy.name
                        ),
                    )?));
                }
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
    ///
    /// SECURITY (P0-FIX): This legacy path now checks path_rules, network_rules, and
    /// ip_rules before returning the verdict, matching the behavior of the compiled
    /// policy path. Previously, these checks were skipped, allowing policy bypass.
    fn apply_policy(
        &self,
        action: &Action,
        policy: &Policy,
    ) -> Result<Option<Verdict>, EngineError> {
        // Check path rules before policy type dispatch (same as compiled path).
        if let Some(denial) = self.check_path_rules_legacy(action, policy)? {
            return Ok(Some(denial));
        }
        // Check network rules before policy type dispatch.
        if let Some(denial) = self.check_network_rules_legacy(action, policy) {
            return Ok(Some(denial));
        }
        // Check IP rules (DNS rebinding protection) after network rules.
        if let Some(denial) = self.check_ip_rules_legacy(action, policy) {
            return Ok(Some(denial));
        }

        match &policy.policy_type {
            PolicyType::Allow => Ok(Some(Verdict::Allow)),
            PolicyType::Deny => Ok(Some(Verdict::Deny {
                reason: format!("Denied by policy '{}'", policy.name),
            })),
            PolicyType::Conditional { conditions } => {
                self.evaluate_conditions(action, policy, conditions)
            }
            // Handle future variants - fail closed (deny)
            _ => Ok(Some(Verdict::Deny {
                reason: format!("Unknown policy type for '{}'", policy.name),
            })),
        }
    }

    /// Check action target_paths against raw path rules (legacy path).
    ///
    /// SECURITY (P0-FIX): This is the legacy equivalent of `check_path_rules()` for
    /// the compiled path. It compiles glob patterns on each call (slower, but correct).
    fn check_path_rules_legacy(
        &self,
        action: &Action,
        policy: &Policy,
    ) -> Result<Option<Verdict>, EngineError> {
        let rules = match &policy.path_rules {
            Some(r) => r,
            None => return Ok(None),
        };

        // If both allowed and blocked are empty, no path rules to check
        if rules.allowed.is_empty() && rules.blocked.is_empty() {
            return Ok(None);
        }

        if action.target_paths.is_empty() {
            // SECURITY (R28-ENG-1): When an allowlist is configured but no
            // target paths were extracted, fail-closed.
            if !rules.allowed.is_empty() {
                return Ok(Some(Verdict::Deny {
                    reason: format!(
                        "No target paths provided but path allowlist is configured for policy '{}'",
                        policy.name
                    ),
                }));
            }
            return Ok(None); // Blocklist-only mode: nothing to block
        }

        for raw_path in &action.target_paths {
            let normalized =
                match Self::normalize_path_bounded(raw_path, self.max_path_decode_iterations) {
                    Ok(n) => n,
                    Err(e) => {
                        return Ok(Some(Verdict::Deny {
                            reason: format!("Path normalization failed: {}", e),
                        }))
                    }
                };

            // Check blocked patterns first (blocked takes precedence)
            for pattern in &rules.blocked {
                // SECURITY: Invalid glob patterns are treated as fail-closed (Deny),
                // not as errors. This ensures malformed policies don't cause 500s.
                match self.glob_is_match(pattern, &normalized, &policy.id) {
                    Ok(true) => {
                        return Ok(Some(Verdict::Deny {
                            reason: format!(
                                "Path '{}' blocked by pattern '{}' in policy '{}'",
                                normalized, pattern, policy.name
                            ),
                        }));
                    }
                    Ok(false) => {}
                    Err(e) => {
                        return Ok(Some(Verdict::Deny {
                            reason: format!(
                                "Invalid glob pattern '{}' in policy '{}': {} (fail-closed)",
                                pattern, policy.name, e
                            ),
                        }));
                    }
                }
            }

            // If allowed list is non-empty, path must match at least one
            if !rules.allowed.is_empty() {
                let mut any_allowed = false;
                for pattern in &rules.allowed {
                    // SECURITY: Invalid glob patterns in allowlist are fail-closed.
                    match self.glob_is_match(pattern, &normalized, &policy.id) {
                        Ok(true) => {
                            any_allowed = true;
                            break;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            return Ok(Some(Verdict::Deny {
                                reason: format!(
                                    "Invalid glob pattern '{}' in policy '{}': {} (fail-closed)",
                                    pattern, policy.name, e
                                ),
                            }));
                        }
                    }
                }
                if !any_allowed {
                    return Ok(Some(Verdict::Deny {
                        reason: format!(
                            "Path '{}' not in allowed paths for policy '{}'",
                            normalized, policy.name
                        ),
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Check action target_domains against raw network rules (legacy path).
    ///
    /// SECURITY (P0-FIX): This is the legacy equivalent of `check_network_rules()` for
    /// the compiled path.
    fn check_network_rules_legacy(&self, action: &Action, policy: &Policy) -> Option<Verdict> {
        let rules = match &policy.network_rules {
            Some(r) => r,
            None => return None,
        };

        // If both allowed and blocked domains are empty, no network rules to check
        if rules.allowed_domains.is_empty() && rules.blocked_domains.is_empty() {
            return None;
        }

        if action.target_domains.is_empty() {
            // SECURITY (R28-ENG-1): When an allowed_domains list is configured
            // but no target domains were extracted, fail-closed.
            if !rules.allowed_domains.is_empty() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "No target domains provided but domain allowlist is configured for policy '{}'",
                        policy.name
                    ),
                });
            }
            return None; // Blocklist-only mode: nothing to block
        }

        for raw_domain in &action.target_domains {
            let domain = raw_domain.to_lowercase();

            // SECURITY (R30-ENG-2): Fail-closed for non-ASCII domains that fail
            // IDNA normalization.
            if Self::normalize_domain_for_match(&domain).is_none() {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Domain '{}' cannot be normalized (IDNA failure) — blocked by policy '{}'",
                        domain, policy.name
                    ),
                });
            }

            // Check blocked domains first
            for pattern in &rules.blocked_domains {
                if Self::match_domain_pattern(&domain, pattern) {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Domain '{}' blocked by pattern '{}' in policy '{}'",
                            domain, pattern, policy.name
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
                        domain, policy.name
                    ),
                });
            }
        }

        None
    }

    /// Check resolved IPs against raw IP rules (legacy path).
    ///
    /// SECURITY (P0-FIX): This is the legacy equivalent of `check_ip_rules()` for
    /// the compiled path.
    fn check_ip_rules_legacy(&self, action: &Action, policy: &Policy) -> Option<Verdict> {
        let network_rules = match &policy.network_rules {
            Some(r) => r,
            None => return None,
        };
        let ip_rules = match &network_rules.ip_rules {
            Some(r) => r,
            None => return None,
        };

        // Fail-closed: if ip_rules are configured but no resolved IPs provided
        // and the action has target domains, deny.
        if action.resolved_ips.is_empty() && !action.target_domains.is_empty() {
            return Some(Verdict::Deny {
                reason: format!(
                    "IP rules configured but no resolved IPs provided for policy '{}'",
                    policy.name
                ),
            });
        }

        for ip_str in &action.resolved_ips {
            // Parse the IP address
            let raw_ip: IpAddr = match ip_str.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Invalid resolved IP '{}' in policy '{}'",
                            ip_str, policy.name
                        ),
                    })
                }
            };

            // SECURITY (R24-ENG-1, R29-ENG-1): Canonicalize IPv6 transition
            // mechanism addresses to their embedded IPv4 form.
            let ip = match raw_ip {
                IpAddr::V6(ref v6) => {
                    if let Some(v4) = ip::extract_embedded_ipv4(v6) {
                        IpAddr::V4(v4)
                    } else {
                        raw_ip
                    }
                }
                _ => raw_ip,
            };

            // Check block_private
            if ip_rules.block_private && ip::is_private_ip(ip) {
                return Some(Verdict::Deny {
                    reason: format!(
                        "Resolved IP '{}' is a private/reserved address (DNS rebinding protection) in policy '{}'",
                        ip, policy.name
                    ),
                });
            }

            // Check blocked_cidrs
            for cidr_str in &ip_rules.blocked_cidrs {
                if let Ok(cidr) = cidr_str.parse::<IpNet>() {
                    if cidr.contains(&ip) {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "Resolved IP '{}' in blocked CIDR '{}' in policy '{}'",
                                ip, cidr_str, policy.name
                            ),
                        });
                    }
                }
            }

            // Check allowed_cidrs (if non-empty, must match at least one)
            if !ip_rules.allowed_cidrs.is_empty() {
                let allowed = ip_rules.allowed_cidrs.iter().any(|cidr_str| {
                    cidr_str
                        .parse::<IpNet>()
                        .map(|cidr| cidr.contains(&ip))
                        .unwrap_or(false)
                });
                if !allowed {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "Resolved IP '{}' not in allowed CIDRs for policy '{}'",
                            ip, policy.name
                        ),
                    });
                }
            }
        }

        None
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
            // SECURITY (R34-ENG-7): Include "context_conditions" to match compiled path.
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
            Err(e) => {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Path normalization failed: {}", e),
                }))
            }
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
            Err(e) => {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Path normalization failed: {}", e),
                }))
            }
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

        // SECURITY (R34-ENG-3): IDNA fail-closed guard matching compiled path (R31-ENG-1).
        if !domain.is_ascii() && Self::normalize_domain_for_match(&domain).is_none() {
            return Ok(Some(Self::make_constraint_verdict(
                "deny",
                &format!(
                    "Parameter '{}' domain '{}' cannot be normalized (IDNA failure) (policy '{}')",
                    param_name, domain, policy.name
                ),
            )?));
        }

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

        // SECURITY (R34-ENG-3): IDNA fail-closed guard matching compiled path (R31-ENG-1).
        if !domain.is_ascii() && Self::normalize_domain_for_match(&domain).is_none() {
            return Ok(Some(Self::make_constraint_verdict(
                "deny",
                &format!(
                    "Parameter '{}' domain '{}' cannot be normalized (IDNA failure) (policy '{}')",
                    param_name, domain, policy.name
                ),
            )?));
        }

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
    /// See [`path::normalize_path`] for details.
    pub fn normalize_path(raw: &str) -> Result<String, EngineError> {
        path::normalize_path(raw)
    }

    /// Normalize a file path with a configurable percent-decoding iteration limit.
    ///
    /// See [`path::normalize_path_bounded`] for details.
    pub fn normalize_path_bounded(raw: &str, max_iterations: u32) -> Result<String, EngineError> {
        path::normalize_path_bounded(raw, max_iterations)
    }

    /// Extract the domain from a URL string.
    ///
    /// See [`domain::extract_domain`] for details.
    pub fn extract_domain(url: &str) -> String {
        domain::extract_domain(url)
    }

    /// Match a domain against a pattern like `*.example.com` or `example.com`.
    ///
    /// See [`domain::match_domain_pattern`] for details.
    pub fn match_domain_pattern(domain_str: &str, pattern: &str) -> bool {
        domain::match_domain_pattern(domain_str, pattern)
    }

    /// Normalize a domain for matching: lowercase, strip trailing dots, apply IDNA.
    ///
    /// See [`domain::normalize_domain_for_match`] for details.
    fn normalize_domain_for_match(s: &str) -> Option<std::borrow::Cow<'_, str>> {
        domain::normalize_domain_for_match(s)
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
        if let Ok(cache) = self.glob_matcher_cache.read() {
            if let Some(matcher) = cache.get(pattern) {
                return Ok(matcher.is_match(input));
            }
        }

        let matcher = Glob::new(pattern)
            .map_err(|e| EngineError::InvalidCondition {
                policy_id: policy_id.to_string(),
                reason: format!("Invalid glob pattern '{}': {}", pattern, e),
            })?
            .compile_matcher();
        let is_match = matcher.is_match(input);

        if let Ok(mut cache) = self.glob_matcher_cache.write() {
            if cache.len() >= MAX_GLOB_MATCHER_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(pattern.to_string(), matcher);
        }

        Ok(is_match)
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
    ///
    /// IMPROVEMENT_PLAN 4.1: Also supports bracket notation for array access:
    /// - `items[0]` — access first element of array "items"
    /// - `config.items[0].path` — traverse nested path with array access
    /// - `matrix[0][1]` — multi-dimensional array access
    pub fn get_param_by_path<'a>(
        params: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let exact_match = params.get(path);

        // For non-dotted paths without brackets, exact match is the only interpretation
        if !path.contains('.') && !path.contains('[') {
            return exact_match;
        }

        // Try dot-split traversal for nested objects with bracket notation support
        let traversal_match = Self::traverse_path(params, path);

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

    /// Traverse a JSON value using a path with dot notation and bracket notation.
    ///
    /// Supports:
    /// - `foo.bar` — nested object access
    /// - `items[0]` — array index access
    /// - `foo.items[0].bar` — mixed traversal
    /// - `matrix[0][1]` — consecutive array access
    fn traverse_path<'a>(
        params: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let mut current = params;

        // Split by dots first, then handle bracket notation within each segment
        for segment in path.split('.') {
            if segment.is_empty() {
                continue;
            }

            // Check for bracket notation: field[index] or just [index]
            if let Some(bracket_pos) = segment.find('[') {
                // Get the field name before the bracket (may be empty for [0][1] style)
                let field_name = &segment[..bracket_pos];

                // If there's a field name, traverse into it first
                if !field_name.is_empty() {
                    current = current.get(field_name)?;
                }

                // Parse all bracket indices in this segment: [0][1][2]...
                let mut rest = &segment[bracket_pos..];
                while rest.starts_with('[') {
                    let close_pos = rest.find(']')?;
                    let index_str = &rest[1..close_pos];
                    let index: usize = index_str.parse().ok()?;

                    // Access array element
                    current = current.get(index)?;

                    // Move past this bracket pair
                    rest = &rest[close_pos + 1..];
                }

                // If there's remaining content after brackets, it's malformed
                if !rest.is_empty() {
                    return None;
                }
            } else {
                // Simple field access
                current = current.get(segment)?;
            }
        }

        Some(current)
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
        // Pre-allocate for typical parameter sizes; bounded by MAX_SCAN_VALUES
        let mut results = Vec::with_capacity(16);
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
        let mut policy_matches: Vec<PolicyMatch> = Vec::with_capacity(indices.len());

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
        let mut policy_matches: Vec<PolicyMatch> = Vec::with_capacity(indices.len());

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
            // Handle future variants - fail closed (deny)
            _ => Ok((
                Some(Verdict::Deny {
                    reason: format!("Unknown policy type for '{}'", cp.policy.name),
                }),
                Vec::new(),
            )),
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
        let mut results = Some(Vec::with_capacity(cp.constraints.len()));
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
            let mut results = Vec::with_capacity(all_values.len());
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
                    // SECURITY (R34-ENG-1): IDNA fail-closed guard matching compiled path.
                    // If domain contains non-ASCII and cannot be normalized, treat as match
                    // (fail-closed: deny) to prevent bypass via unnormalizable domains.
                    if !domain.is_ascii() && Self::normalize_domain_for_match(&domain).is_none() {
                        return true;
                    }
                    Self::match_domain_pattern(&domain, pattern)
                } else {
                    true // non-string → fail-closed
                }
            }
            CompiledConstraint::DomainNotIn { patterns, .. } => {
                if let Some(s) = value.as_str() {
                    let domain = Self::extract_domain(s);
                    // SECURITY (R34-ENG-1): IDNA fail-closed for DomainNotIn.
                    // If domain contains non-ASCII and cannot be normalized, it cannot
                    // be in the allowlist — constraint fires (fail-closed).
                    if !domain.is_ascii() && Self::normalize_domain_for_match(&domain).is_none() {
                        return true;
                    }
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
            // Handle future variants
            _ => "unknown".to_string(),
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


#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
