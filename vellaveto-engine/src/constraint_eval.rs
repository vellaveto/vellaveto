// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

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
use crate::verified_constraint_eval;
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
                let (all_values, _truncated) = Self::collect_all_string_values(&action.parameters);
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
        let all_constraints_skipped =
            verified_constraint_eval::all_constraints_skipped(total_constraints, any_evaluated);

        if all_constraints_skipped {
            if verified_constraint_eval::skipped_constraints_verdict(cp.on_no_match_continue)
                == verified_constraint_eval::ConstraintVerdict::Continue
            {
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
        // SECURITY (FIND-R46-005): This behavior is intentionally equivalent to the
        // legacy path in legacy.rs::evaluate_conditions(). Both paths:
        // 1. Return None (skip to next policy) when on_no_match="continue"
        // 2. Return Some(Allow) otherwise (no constraints fired = pass)
        // 3. Return Deny when all constraints are skipped (fail-closed)
        // See test_on_no_match_continue_equivalence_compiled_vs_legacy in engine_tests.rs.
        if verified_constraint_eval::no_match_verdict(cp.on_no_match_continue)
            == verified_constraint_eval::ConstraintVerdict::Continue
        {
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
            let (all_values, truncated) = Self::collect_all_string_values(&action.parameters);
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
            // SECURITY (R234-ENG-4): Fail-closed when scan was truncated and
            // no constraint matched. Unscanned values may contain forbidden patterns.
            if truncated {
                tracing::warn!(
                    "SECURITY: wildcard constraint scan truncated at {} values for policy '{}' — denying (fail-closed)",
                    Self::MAX_SCAN_VALUES,
                    policy.name,
                );
                return Ok(Some(Verdict::Deny {
                    reason: format!(
                        "Parameter scan truncated at {} values — deny (fail-closed) in policy '{}'",
                        Self::MAX_SCAN_VALUES,
                        policy.name,
                    ),
                }));
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
                pattern_str: _,
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
                        // SECURITY (R235-ENG-2): Genericize deny reason — do not echo
                        // user-controlled path value or internal pattern (info disclosure).
                        &format!(
                            "Parameter '{}' path matches constraint (policy '{}')",
                            param_name, policy.name
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
                                    "Parameter '{param_name}' is not a string for not_glob operator"
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
                    // SECURITY (R235-ENG-2): Genericize deny reason.
                    &format!(
                        "Parameter '{}' path not in allowlist (policy '{}')",
                        param_name, policy.name
                    ),
                )?))
            }
            CompiledConstraint::Regex {
                regex,
                pattern_str: _,
                ..
            } => {
                let raw = match value.as_str() {
                    Some(s) => s,
                    None => {
                        if self.strict_mode {
                            return Err(EngineError::InvalidCondition {
                                policy_id: policy.id.clone(),
                                reason: format!(
                                    "Parameter '{param_name}' is not a string for regex operator"
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
                // SECURITY (R237-ENG-2): Normalize path input before regex matching,
                // consistent with Glob/NotGlob. Prevents percent-encoded traversal
                // (e.g., /safe/%2e%2e/etc/passwd) from bypassing regex path patterns.
                //
                // SECURITY (R255-ENG-1): Match against BOTH the raw value AND the
                // normalized value. Path normalization can mangle non-path strings
                // (e.g., "rm -rf /" becomes "/rm -rf " because the trailing slash is
                // consumed as a path separator). Matching the raw value first ensures
                // shell command patterns still trigger, while normalized matching
                // preserves the R237-ENG-2 percent-decode evasion defense.
                if regex.is_match(raw) {
                    return Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        // SECURITY (R235-ENG-2): Genericize deny reason.
                        &format!(
                            "Parameter '{}' matches constraint (policy '{}')",
                            param_name, policy.name
                        ),
                    )?));
                }
                let normalized =
                    match Self::normalize_path_bounded(raw, self.max_path_decode_iterations) {
                        Ok(n) => n,
                        Err(e) => {
                            return Ok(Some(Verdict::Deny {
                                reason: format!("Path normalization failed: {e}"),
                            }))
                        }
                    };
                if normalized != raw && regex.is_match(&normalized) {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        // SECURITY (R235-ENG-2): Genericize deny reason.
                        &format!(
                            "Parameter '{}' matches constraint (policy '{}')",
                            param_name, policy.name
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
                                    "Parameter '{param_name}' is not a string for domain_match operator"
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
                        // SECURITY (R235-ENG-2): Genericize deny reason.
                        &format!(
                            "Parameter '{}' domain cannot be normalized (IDNA failure) (policy '{}')",
                            param_name, policy.name
                        ),
                    )?));
                }
                if Self::match_domain_pattern(&domain, pattern) {
                    Ok(Some(Self::make_constraint_verdict(
                        on_match,
                        // SECURITY (R235-ENG-2): Genericize deny reason.
                        &format!(
                            "Parameter '{}' domain matches constraint (policy '{}')",
                            param_name, policy.name
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
                                    "Parameter '{param_name}' is not a string for domain_not_in operator"
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
                        // SECURITY (R235-ENG-2): Genericize deny reason.
                        &format!(
                            "Parameter '{}' domain cannot be normalized (IDNA failure) (policy '{}')",
                            param_name, policy.name
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
                    // SECURITY (R235-ENG-2): Genericize deny reason.
                    &format!(
                        "Parameter '{}' domain not in allowlist (policy '{}')",
                        param_name, policy.name
                    ),
                )?))
            }
            // SECURITY (R242-ENG-1): Normalize string operands via normalize_full()
            // before comparison, matching the ABAC engine pattern (R237-ENG-3/5).
            // Without this, Cyrillic/fullwidth/NFKC variants bypass Eq/Ne/OneOf/NoneOf.
            CompiledConstraint::Eq {
                value: expected, ..
            } => {
                let matches = match (value.as_str(), expected.as_str()) {
                    (Some(a), Some(b)) => {
                        crate::normalize::normalize_full(a) == crate::normalize::normalize_full(b)
                    }
                    _ => value == expected,
                };
                if matches {
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
                let matches = match (value.as_str(), expected.as_str()) {
                    (Some(a), Some(b)) => {
                        crate::normalize::normalize_full(a) != crate::normalize::normalize_full(b)
                    }
                    _ => value != expected,
                };
                if matches {
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
                let matches = match value.as_str() {
                    Some(val_str) => {
                        let norm_val = crate::normalize::normalize_full(val_str);
                        values.iter().any(|v| match v.as_str() {
                            Some(s) => crate::normalize::normalize_full(s) == norm_val,
                            None => v == value,
                        })
                    }
                    None => values.contains(value),
                };
                if matches {
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
                let matches = match value.as_str() {
                    Some(val_str) => {
                        let norm_val = crate::normalize::normalize_full(val_str);
                        values.iter().any(|v| match v.as_str() {
                            Some(s) => crate::normalize::normalize_full(s) == norm_val,
                            None => v == value,
                        })
                    }
                    None => values.contains(value),
                };
                if !matches {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vellaveto_types::PolicyType;

    fn make_conditional_policy(name: &str, conditions: serde_json::Value) -> Policy {
        Policy {
            id: "*".to_string(),
            name: name.to_string(),
            policy_type: PolicyType::Conditional { conditions },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }
    }

    // ---- require_approval tests ----

    #[test]
    fn test_evaluate_compiled_conditions_require_approval() {
        let policy = make_conditional_policy("approval", json!({ "require_approval": true }));
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({}));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::RequireApproval { .. }));
    }

    // ---- forbidden_parameters tests ----

    #[test]
    fn test_evaluate_compiled_conditions_forbidden_param_present_deny() {
        let policy =
            make_conditional_policy("no-secret", json!({ "forbidden_parameters": ["secret"] }));
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "secret": "value" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => {
                assert!(reason.contains("forbidden"));
            }
            _ => panic!("Expected Deny for forbidden parameter"),
        }
    }

    #[test]
    fn test_evaluate_compiled_conditions_forbidden_param_absent_allow() {
        let policy =
            make_conditional_policy("no-secret", json!({ "forbidden_parameters": ["secret"] }));
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "name": "safe" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Allow));
    }

    // ---- required_parameters tests ----

    #[test]
    fn test_evaluate_compiled_conditions_required_param_missing_deny() {
        let policy =
            make_conditional_policy("need-token", json!({ "required_parameters": ["token"] }));
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({}));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => {
                assert!(reason.contains("missing"));
            }
            _ => panic!("Expected Deny for missing required parameter"),
        }
    }

    #[test]
    fn test_evaluate_compiled_conditions_required_param_present_allow() {
        let policy =
            make_conditional_policy("need-token", json!({ "required_parameters": ["token"] }));
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "token": "abc123" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Allow));
    }

    // ---- on_no_match_continue tests ----

    #[test]
    fn test_evaluate_compiled_conditions_on_no_match_continue_returns_none() {
        let policy = make_conditional_policy(
            "continue-test",
            json!({
                "on_no_match": "continue",
                "parameter_constraints": [
                    { "param": "nonexistent", "op": "eq", "value": "x", "on_missing": "skip" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({}));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        // on_no_match=continue -> returns None
        assert!(result.is_none());
    }

    // ---- fail-closed when all constraints skipped ----

    #[test]
    fn test_evaluate_compiled_conditions_all_skipped_fail_closed() {
        // When all constraints skip due to missing params and on_no_match is NOT continue,
        // the engine should fail-closed with Deny.
        let policy = make_conditional_policy(
            "fail-closed",
            json!({
                "parameter_constraints": [
                    { "param": "missing1", "op": "eq", "value": "x", "on_missing": "skip" },
                    { "param": "missing2", "op": "eq", "value": "y", "on_missing": "skip" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({}));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => {
                assert!(reason.contains("constraints skipped"));
            }
            _ => panic!("Expected Deny for all-skipped fail-closed"),
        }
    }

    // ---- Eq constraint tests ----

    #[test]
    fn test_evaluate_compiled_constraint_eq_match() {
        let policy = make_conditional_policy(
            "eq-test",
            json!({
                "parameter_constraints": [
                    { "param": "mode", "op": "eq", "value": "danger", "on_match": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "mode": "danger" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Deny { .. }));
    }

    #[test]
    fn test_evaluate_compiled_constraint_eq_no_match() {
        let policy = make_conditional_policy(
            "eq-no-match",
            json!({
                "parameter_constraints": [
                    { "param": "mode", "op": "eq", "value": "danger", "on_match": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "mode": "safe" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        // No constraint fired -> Allow (default for no constraints firing)
        assert!(matches!(result.unwrap(), Verdict::Allow));
    }

    #[test]
    fn test_evaluate_compiled_constraint_eq_normalizes_unicode_strings() {
        let policy = make_conditional_policy(
            "eq-normalized",
            json!({
                "parameter_constraints": [
                    { "param": "role", "op": "eq", "value": "admin", "on_match": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "role": "аdmin" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(matches!(result, Some(Verdict::Deny { .. })));
    }

    // ---- Ne constraint tests ----

    #[test]
    fn test_evaluate_compiled_constraint_ne_match() {
        let policy = make_conditional_policy(
            "ne-test",
            json!({
                "parameter_constraints": [
                    { "param": "level", "op": "ne", "value": 0, "on_match": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "level": 5 }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Deny { .. }));
    }

    // ---- OneOf constraint tests ----

    #[test]
    fn test_evaluate_compiled_constraint_one_of_match() {
        let policy = make_conditional_policy(
            "one-of-test",
            json!({
                "parameter_constraints": [
                    { "param": "env", "op": "one_of", "values": ["prod", "staging"], "on_match": "allow" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "env": "prod" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Allow));
    }

    #[test]
    fn test_evaluate_compiled_constraint_one_of_no_match() {
        let policy = make_conditional_policy(
            "one-of-miss",
            json!({
                "parameter_constraints": [
                    { "param": "env", "op": "one_of", "values": ["prod", "staging"], "on_match": "allow" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "env": "dev" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        // env="dev" not in [prod, staging], so one_of doesn't fire -> Allow (no constraints fired)
        assert!(matches!(result.unwrap(), Verdict::Allow));
    }

    #[test]
    fn test_evaluate_compiled_constraint_one_of_normalizes_unicode_strings() {
        let policy = make_conditional_policy(
            "one-of-normalized",
            json!({
                "parameter_constraints": [
                    { "param": "env", "op": "one_of", "values": ["prod"], "on_match": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "env": "ＰＲＯＤ" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(matches!(result, Some(Verdict::Deny { .. })));
    }

    // ---- NoneOf constraint tests ----

    #[test]
    fn test_evaluate_compiled_constraint_none_of_match() {
        let policy = make_conditional_policy(
            "none-of-test",
            json!({
                "parameter_constraints": [
                    { "param": "action", "op": "none_of", "values": ["delete", "drop"], "on_match": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        // "read" is NOT in [delete, drop], so none_of fires
        let action = Action::new("tool", "func", json!({ "action": "read" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Deny { .. }));
    }

    #[test]
    fn test_evaluate_compiled_constraint_none_of_no_match() {
        let policy = make_conditional_policy(
            "none-of-no-match",
            json!({
                "parameter_constraints": [
                    { "param": "action", "op": "none_of", "values": ["delete", "drop"], "on_match": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        // "delete" IS in [delete, drop], so none_of does NOT fire
        let action = Action::new("tool", "func", json!({ "action": "delete" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), Verdict::Allow));
    }

    #[test]
    fn test_evaluate_compiled_constraint_none_of_normalized_member_does_not_fire() {
        let policy = make_conditional_policy(
            "none-of-normalized",
            json!({
                "parameter_constraints": [
                    { "param": "role", "op": "none_of", "values": ["admin"], "on_match": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({ "role": "аdmin" }));
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(matches!(result, Some(Verdict::Allow)));
    }

    // ---- Missing param with on_missing=deny (fail-closed default) ----

    #[test]
    fn test_evaluate_compiled_constraint_missing_param_deny() {
        let policy = make_conditional_policy(
            "missing-deny",
            json!({
                "parameter_constraints": [
                    { "param": "path", "op": "glob", "pattern": "/safe/**", "on_match": "allow", "on_missing": "deny" }
                ]
            }),
        );
        let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        let action = Action::new("tool", "func", json!({})); // no "path" param
        let cp = &engine.compiled_policies[0];
        let result = engine.evaluate_compiled_conditions(&action, cp).unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            Verdict::Deny { reason } => {
                assert!(reason.contains("missing"));
            }
            _ => panic!("Expected Deny for missing param with on_missing=deny"),
        }
    }
}
