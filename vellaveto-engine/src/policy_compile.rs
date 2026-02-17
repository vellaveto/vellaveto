//! Policy compilation methods.
//!
//! This module contains methods for compiling policies at load time.
//! Pre-compilation validates all patterns (globs, regexes, domains, CIDRs)
//! and produces [`CompiledPolicy`] objects that enable zero-lock evaluation.

use crate::compiled::{
    CompiledConditions, CompiledConstraint, CompiledContextCondition, CompiledIpRules,
    CompiledNetworkRules, CompiledPathRules, CompiledPolicy,
};
use crate::error::PolicyValidationError;
use crate::matcher::{CompiledToolMatcher, PatternMatcher};
use crate::PolicyEngine;
use globset::Glob;
use ipnet::IpNet;
use vellaveto_types::{Policy, PolicyType};

impl PolicyEngine {
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
        // SECURITY (FIND-R50-065): Validate policy name length to prevent
        // unboundedly large deny_reason strings derived from policy.name.
        const MAX_POLICY_NAME_LEN: usize = 256;
        if policy.name.len() > MAX_POLICY_NAME_LEN {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!(
                    "Policy name is {} bytes, max is {}",
                    policy.name.len(),
                    MAX_POLICY_NAME_LEN
                ),
            });
        }

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
            // SECURITY (FIND-R46-002): Reject unknown policy types at compile time
            // instead of silently treating them as Allow. The #[non_exhaustive]
            // attribute on PolicyType requires this arm, but we fail-closed.
            _ => {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "Unknown policy type variant for policy '{}' — cannot compile",
                        policy.name
                    ),
                });
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

        // SECURITY (FIND-R46-012): Maximum number of parameter constraints per policy.
        const MAX_PARAMETER_CONSTRAINTS: usize = 100;

        let constraints = if let Some(constraint_arr) = conditions.get("parameter_constraints") {
            let arr = constraint_arr
                .as_array()
                .ok_or_else(|| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: "parameter_constraints must be an array".to_string(),
                })?;

            // SECURITY (FIND-R46-012): Reject excessively large constraint arrays
            // to prevent memory exhaustion during policy compilation.
            if arr.len() > MAX_PARAMETER_CONSTRAINTS {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "parameter_constraints has {} entries, max is {}",
                        arr.len(),
                        MAX_PARAMETER_CONSTRAINTS
                    ),
                });
            }

            let mut constraints = Vec::with_capacity(arr.len());
            for constraint_val in arr {
                constraints.push(Self::compile_constraint(policy, constraint_val)?);
            }
            constraints
        } else {
            Vec::new()
        };

        // SECURITY (FIND-R50-060): Maximum number of context conditions per policy.
        const MAX_CONTEXT_CONDITIONS: usize = 50;

        // Parse context conditions (session-level checks)
        let context_conditions = if let Some(ctx_arr) = conditions.get("context_conditions") {
            let arr = ctx_arr.as_array().ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "context_conditions must be an array".to_string(),
            })?;

            // SECURITY (FIND-R50-060): Reject excessively large context condition arrays
            // to prevent memory exhaustion during policy compilation.
            if arr.len() > MAX_CONTEXT_CONDITIONS {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "context_conditions has {} entries, max is {}",
                        arr.len(),
                        MAX_CONTEXT_CONDITIONS
                    ),
                });
            }

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

                // SECURITY (FIND-R46-004): Set explicit DFA size limit to prevent
                // memory exhaustion from regex patterns that compile to large automata.
                let regex = regex::RegexBuilder::new(&pattern_str)
                    .dfa_size_limit(256 * 1024)
                    .size_limit(256 * 1024)
                    .build()
                    .map_err(|e| PolicyValidationError {
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
                // SECURITY (FIND-R46-003): Lowercase at compile time to match the
                // case-insensitive comparison in context_check.rs (R31-ENG-7).
                let required_tool = obj
                    .get("required_tool")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "require_previous_action missing 'required_tool' string"
                            .to_string(),
                    })?
                    .to_lowercase();
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
                // SECURITY (FIND-R46-003): Lowercase at compile time to match the
                // case-insensitive comparison in context_check.rs (R31-ENG-7).
                let forbidden_tool = obj
                    .get("forbidden_tool")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "forbidden_previous_action missing 'forbidden_tool' string"
                            .to_string(),
                    })?
                    .to_lowercase();
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
                // SECURITY (FIND-P2-004, R34-ENG-2): Use try_from instead of `as usize`
                // and return a compilation error if the value overflows usize, instead
                // of silently clamping to usize::MAX.
                let window_raw = obj.get("window").and_then(|v| v.as_u64()).unwrap_or(0);
                let window = usize::try_from(window_raw).map_err(|_| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "max_calls_in_window 'window' value {} exceeds platform maximum ({})",
                        window_raw,
                        usize::MAX
                    ),
                })?;
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
                // SECURITY (FIND-044): Lowercase claim values at compile time for
                // case-insensitive comparison, matching issuer/subject/audience.
                let required_claims = obj
                    .get("claims")
                    .and_then(|v| v.as_object())
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| {
                                v.as_str().map(|s| (k.clone(), s.to_ascii_lowercase()))
                            })
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
                // SECURITY (FIND-R49-005): Warn that this condition is a no-op at the engine level.
                tracing::warn!(
                    policy_id = %policy.id,
                    "Policy condition 'async_task_policy' is not enforced at the engine level; \
                     it requires the MCP proxy layer for enforcement"
                );
                // SECURITY (FIND-P3-015): Return a compilation error if max_concurrent
                // overflows usize, instead of silently clamping to usize::MAX.
                let max_concurrent_raw = obj
                    .get("max_concurrent")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0); // 0 = unlimited
                let max_concurrent = if max_concurrent_raw == 0 {
                    0
                } else {
                    usize::try_from(max_concurrent_raw).map_err(|_| PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "async_task_policy 'max_concurrent' value {} exceeds platform maximum ({})",
                            max_concurrent_raw,
                            usize::MAX
                        ),
                    })?
                };

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
                // SECURITY (FIND-043): Normalize to lowercase at compile time,
                // matching the pattern used by AgentId and MaxCalls.
                let required_capabilities: Vec<String> = obj
                    .get("required_capabilities")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                            .collect()
                    })
                    .unwrap_or_default();

                let blocked_capabilities: Vec<String> = obj
                    .get("blocked_capabilities")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
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
                // SECURITY (FIND-R49-005): Warn that this condition is a no-op at the engine level.
                tracing::warn!(
                    policy_id = %policy.id,
                    "Policy condition 'circuit_breaker' is not enforced at the engine level; \
                     it requires the MCP proxy layer for enforcement"
                );
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
                // SECURITY (FIND-R49-005): Warn that this condition is a no-op at the engine level.
                tracing::warn!(
                    policy_id = %policy.id,
                    "Policy condition 'shadow_agent_check' is not enforced at the engine level; \
                     it requires the MCP proxy layer for enforcement"
                );
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
                // SECURITY (FIND-R49-005): Warn that this condition is a no-op at the engine level.
                tracing::warn!(
                    policy_id = %policy.id,
                    "Policy condition 'schema_poisoning_check' is not enforced at the engine level; \
                     it requires the MCP proxy layer for enforcement"
                );
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

            "require_capability_token" => {
                // Parse required_issuers (optional array of strings)
                let required_issuers = obj
                    .get("required_issuers")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();

                // Parse min_remaining_depth (optional, default 0)
                let min_remaining_depth = obj
                    .get("min_remaining_depth")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if min_remaining_depth > 16 {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "require_capability_token min_remaining_depth must be 0-16, got {}",
                            min_remaining_depth
                        ),
                    });
                }

                let deny_reason = format!("Capability token required for policy '{}'", policy.name);

                Ok(CompiledContextCondition::RequireCapabilityToken {
                    required_issuers,
                    min_remaining_depth: min_remaining_depth as u8,
                    deny_reason,
                })
            }

            "min_verification_tier" => {
                // Parse required_tier as integer or string name
                let required_tier = if let Some(level_val) = obj.get("required_tier") {
                    if let Some(level_u64) = level_val.as_u64() {
                        if level_u64 > 4 {
                            return Err(PolicyValidationError {
                                policy_id: policy.id.clone(),
                                policy_name: policy.name.clone(),
                                reason: format!(
                                    "min_verification_tier required_tier must be 0-4, got {}",
                                    level_u64
                                ),
                            });
                        }
                        level_u64 as u8
                    } else if let Some(name) = level_val.as_str() {
                        vellaveto_types::VerificationTier::from_name(name)
                            .map(|t| t.level())
                            .ok_or_else(|| PolicyValidationError {
                                policy_id: policy.id.clone(),
                                policy_name: policy.name.clone(),
                                reason: format!(
                                    "min_verification_tier unknown tier name '{}'",
                                    name
                                ),
                            })?
                    } else {
                        return Err(PolicyValidationError {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            reason: "min_verification_tier required_tier must be an integer (0-4) or tier name string".to_string(),
                        });
                    }
                } else {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: "min_verification_tier missing 'required_tier' field".to_string(),
                    });
                };

                let deny_reason = format!(
                    "Verification tier below minimum (required level {}) for policy '{}'",
                    required_tier, policy.name
                );

                Ok(CompiledContextCondition::MinVerificationTier {
                    required_tier,
                    deny_reason,
                })
            }

            "session_state_required" => {
                // Parse allowed_states (required array of strings)
                let allowed_states = obj
                    .get("allowed_states")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();

                if allowed_states.is_empty() {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason:
                            "session_state_required must have at least one allowed_states entry"
                                .to_string(),
                    });
                }

                let deny_reason = format!(
                    "Session state not in allowed states for policy '{}'",
                    policy.name
                );

                Ok(CompiledContextCondition::SessionStateRequired {
                    allowed_states,
                    deny_reason,
                })
            }

            // ═══════════════════════════════════════════════════
            // PHASE 40: WORKFLOW-LEVEL POLICY CONSTRAINTS
            // ═══════════════════════════════════════════════════
            "required_action_sequence" => Self::compile_action_sequence(obj, policy, true),

            "forbidden_action_sequence" => Self::compile_action_sequence(obj, policy, false),

            "workflow_template" => Self::compile_workflow_template(obj, policy),

            _ => Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!("Unknown context condition type '{}'", kind),
            }),
        }
    }

    /// Compile a `required_action_sequence` or `forbidden_action_sequence` condition.
    ///
    /// Both share identical parsing; only the resulting variant differs.
    fn compile_action_sequence(
        obj: &serde_json::Map<String, serde_json::Value>,
        policy: &vellaveto_types::Policy,
        is_required: bool,
    ) -> Result<CompiledContextCondition, PolicyValidationError> {
        const MAX_SEQUENCE_STEPS: usize = 20;
        // SECURITY (FIND-R50-051): Bound tool name length in sequences.
        const MAX_TOOL_NAME_LEN: usize = 256;

        let kind = if is_required {
            "required_action_sequence"
        } else {
            "forbidden_action_sequence"
        };

        let arr = obj
            .get("sequence")
            .and_then(|v| v.as_array())
            .ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!("{kind} requires a 'sequence' array"),
            })?;

        if arr.is_empty() {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!("{kind} sequence must not be empty"),
            });
        }

        if arr.len() > MAX_SEQUENCE_STEPS {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!(
                    "{kind} sequence has {} steps (max {MAX_SEQUENCE_STEPS})",
                    arr.len()
                ),
            });
        }

        let mut sequence = Vec::with_capacity(arr.len());
        for (i, val) in arr.iter().enumerate() {
            let s = val.as_str().ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!("{kind} sequence[{i}] must be a string"),
            })?;

            if s.is_empty() {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!("{kind} sequence[{i}] must not be empty"),
                });
            }

            // Reject control characters in tool names.
            if s.chars().any(|c| c.is_control()) {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!("{kind} sequence[{i}] contains control characters"),
                });
            }

            // SECURITY (FIND-R50-051): Reject excessively long tool names.
            if s.len() > MAX_TOOL_NAME_LEN {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "{kind} sequence[{i}] tool name is {} bytes, max is {MAX_TOOL_NAME_LEN}",
                        s.len()
                    ),
                });
            }

            sequence.push(s.to_ascii_lowercase());
        }

        let ordered = obj.get("ordered").and_then(|v| v.as_bool()).unwrap_or(true);

        if is_required {
            let deny_reason = format!(
                "Required action sequence not satisfied for policy '{}'",
                policy.name
            );
            Ok(CompiledContextCondition::RequiredActionSequence {
                sequence,
                ordered,
                deny_reason,
            })
        } else {
            let deny_reason = format!(
                "Forbidden action sequence detected for policy '{}'",
                policy.name
            );
            Ok(CompiledContextCondition::ForbiddenActionSequence {
                sequence,
                ordered,
                deny_reason,
            })
        }
    }

    /// Compile a `workflow_template` condition.
    ///
    /// Parses the `steps` array, computes governed tools, entry points,
    /// and validates acyclicity via Kahn's algorithm.
    fn compile_workflow_template(
        obj: &serde_json::Map<String, serde_json::Value>,
        policy: &vellaveto_types::Policy,
    ) -> Result<CompiledContextCondition, PolicyValidationError> {
        use std::collections::{HashMap, HashSet, VecDeque};

        const MAX_WORKFLOW_STEPS: usize = 50;
        // SECURITY (FIND-R50-061): Maximum successors per workflow step.
        const MAX_SUCCESSORS_PER_STEP: usize = 50;
        // SECURITY (FIND-R50-051): Maximum tool name length in workflows.
        const MAX_TOOL_NAME_LEN: usize = 256;

        let steps =
            obj.get("steps")
                .and_then(|v| v.as_array())
                .ok_or_else(|| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: "workflow_template requires a 'steps' array".to_string(),
                })?;

        if steps.is_empty() {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "workflow_template steps must not be empty".to_string(),
            });
        }

        if steps.len() > MAX_WORKFLOW_STEPS {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!(
                    "workflow_template has {} steps (max {MAX_WORKFLOW_STEPS})",
                    steps.len()
                ),
            });
        }

        let enforce = obj
            .get("enforce")
            .and_then(|v| v.as_str())
            .unwrap_or("strict");

        let strict = match enforce {
            "strict" => true,
            "warn" => false,
            other => {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "workflow_template enforce must be 'strict' or 'warn', got '{other}'"
                    ),
                });
            }
        };

        let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
        let mut governed_tools: HashSet<String> = HashSet::new();
        let mut seen_tools: HashSet<String> = HashSet::new();

        for (i, step) in steps.iter().enumerate() {
            let step_obj = step.as_object().ok_or_else(|| PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: format!("workflow_template steps[{i}] must be an object"),
            })?;

            let tool = step_obj
                .get("tool")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!("workflow_template steps[{i}] requires a 'tool' string"),
                })?;

            if tool.is_empty() {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!("workflow_template steps[{i}].tool must not be empty"),
                });
            }

            if tool.chars().any(|c| c.is_control()) {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "workflow_template steps[{i}].tool contains control characters"
                    ),
                });
            }

            // SECURITY (FIND-R50-051): Reject excessively long tool names.
            if tool.len() > MAX_TOOL_NAME_LEN {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "workflow_template steps[{i}].tool is {} bytes, max is {MAX_TOOL_NAME_LEN}",
                        tool.len()
                    ),
                });
            }

            let tool_lower = tool.to_ascii_lowercase();

            if !seen_tools.insert(tool_lower.clone()) {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!("workflow_template has duplicate step tool '{tool}'"),
                });
            }

            let then_arr = step_obj
                .get("then")
                .and_then(|v| v.as_array())
                .ok_or_else(|| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!("workflow_template steps[{i}] requires a 'then' array"),
                })?;

            // SECURITY (FIND-R50-061): Reject excessively large successor arrays
            // to prevent inflated Kahn's algorithm in-degree computation.
            if then_arr.len() > MAX_SUCCESSORS_PER_STEP {
                return Err(PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!(
                        "workflow_template steps[{i}].then has {} entries, max is {MAX_SUCCESSORS_PER_STEP}",
                        then_arr.len()
                    ),
                });
            }

            let mut successors = Vec::with_capacity(then_arr.len());
            // SECURITY (FIND-R50-068): Track seen successors to deduplicate.
            let mut seen_successors: HashSet<String> = HashSet::new();
            for (j, v) in then_arr.iter().enumerate() {
                let s = v.as_str().ok_or_else(|| PolicyValidationError {
                    policy_id: policy.id.clone(),
                    policy_name: policy.name.clone(),
                    reason: format!("workflow_template steps[{i}].then[{j}] must be a string"),
                })?;

                if s.is_empty() {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!("workflow_template steps[{i}].then[{j}] must not be empty"),
                    });
                }

                if s.chars().any(|c| c.is_control()) {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "workflow_template steps[{i}].then[{j}] contains control characters"
                        ),
                    });
                }

                // SECURITY (FIND-R50-051): Reject excessively long tool names.
                if s.len() > MAX_TOOL_NAME_LEN {
                    return Err(PolicyValidationError {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        reason: format!(
                            "workflow_template steps[{i}].then[{j}] is {} bytes, max is {MAX_TOOL_NAME_LEN}",
                            s.len()
                        ),
                    });
                }

                let lowered = s.to_ascii_lowercase();
                // SECURITY (FIND-R50-068): Silently deduplicate successors to prevent
                // duplicate entries from inflating Kahn's algorithm in-degree counts.
                if seen_successors.insert(lowered.clone()) {
                    successors.push(lowered);
                }
            }

            governed_tools.insert(tool_lower.clone());
            for succ in &successors {
                governed_tools.insert(succ.clone());
            }

            adjacency.insert(tool_lower, successors);
        }

        // Compute entry points: governed tools with no predecessors.
        let mut has_predecessor: HashSet<&str> = HashSet::new();
        for successors in adjacency.values() {
            for succ in successors {
                has_predecessor.insert(succ.as_str());
            }
        }
        // SECURITY (FIND-R50-016): Sort entry points for deterministic ordering
        // across HashSet iterations, ensuring reproducible policy compilation.
        let mut entry_points: Vec<String> = governed_tools
            .iter()
            .filter(|t| !has_predecessor.contains(t.as_str()))
            .cloned()
            .collect();
        entry_points.sort();

        if entry_points.is_empty() {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "workflow_template has no entry points (implies cycle)".to_string(),
            });
        }

        // Cycle detection via Kahn's algorithm (topological sort).
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for tool in &governed_tools {
            in_degree.insert(tool.as_str(), 0);
        }
        for successors in adjacency.values() {
            for succ in successors {
                if let Some(deg) = in_degree.get_mut(succ.as_str()) {
                    *deg = deg.saturating_add(1);
                }
            }
        }

        let mut queue: VecDeque<&str> = VecDeque::new();
        for (tool, deg) in &in_degree {
            if *deg == 0 {
                queue.push_back(tool);
            }
        }

        let mut visited_count: usize = 0;
        while let Some(node) = queue.pop_front() {
            visited_count += 1;
            if let Some(successors) = adjacency.get(node) {
                for succ in successors {
                    if let Some(deg) = in_degree.get_mut(succ.as_str()) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push_back(succ.as_str());
                        }
                    }
                }
            }
        }

        if visited_count < governed_tools.len() {
            return Err(PolicyValidationError {
                policy_id: policy.id.clone(),
                policy_name: policy.name.clone(),
                reason: "workflow_template contains a cycle".to_string(),
            });
        }

        let deny_reason = format!("Workflow template violation for policy '{}'", policy.name);

        Ok(CompiledContextCondition::WorkflowTemplate {
            adjacency,
            governed_tools,
            entry_points,
            strict,
            deny_reason,
        })
    }
}
