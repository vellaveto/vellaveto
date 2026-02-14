//! Compiled constraint evaluation.
//!
//! This module handles evaluation of pre-compiled parameter constraints including:
//! - Glob/regex pattern matching
//! - Numeric comparisons (min, max, exact)
//! - String operations (contains, starts_with, ends_with)
//! - Type checks and enumerations
//! - Path and domain constraints

use crate::compiled::{CompiledConstraint, CompiledPolicy};
use crate::error::EngineError;
use crate::PolicyEngine;
use vellaveto_types::{Action, ConstraintResult, Policy, Verdict};

impl PolicyEngine {
    /// Evaluate pre-compiled conditions against an action (no tracing).
    pub(crate) fn evaluate_compiled_conditions(
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
    pub(crate) fn evaluate_compiled_conditions_core(
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
                    actual: format!("all {total_constraints} constraints skipped (missing params)"),
                    passed: false,
                });
            }
            let policy_name = &cp.policy.name;
            return Ok(Some(Verdict::Deny {
                reason: format!(
                    "All {total_constraints} constraints skipped (parameters missing) in policy '{policy_name}' — fail-closed"
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
    pub(crate) fn evaluate_compiled_constraint_value(
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
                                    "Parameter '{param_name}' is not a string for glob operator"
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
                                reason: format!("Path normalization failed: {e}"),
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
                                reason: format!("Path normalization failed: {e}"),
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
}
