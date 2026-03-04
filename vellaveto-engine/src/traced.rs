// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Traced policy evaluation methods.
//!
//! This module provides evaluation methods that record detailed per-policy
//! match information for OPA-style decision explanations. Use these methods
//! when `?trace=true` is requested - they have ~20% allocation overhead
//! compared to the non-traced hot path.

use crate::compiled::{CompiledConstraint, CompiledPolicy};
use crate::error::EngineError;
use crate::PolicyEngine;
use std::time::Instant;
use vellaveto_types::{
    Action, ActionSummary, ConstraintResult, EvaluationContext, EvaluationTrace, Policy,
    PolicyMatch, PolicyType, Verdict,
};

impl PolicyEngine {
    /// Evaluate an action with full decision trace.
    ///
    /// Opt-in alternative to [`Self::evaluate_action`] that records per-policy match
    /// details for OPA-style decision explanations. Has ~20% allocation overhead
    /// compared to the non-traced hot path, so use only when `?trace=true`.
    #[must_use = "security verdicts must not be discarded"]
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

        // Topology pre-filter: check if the tool exists in the topology graph.
        #[cfg(feature = "discovery")]
        if let Some(deny) = self.check_topology(action) {
            let trace = EvaluationTrace {
                action_summary,
                policies_checked: 0,
                policies_matched: 0,
                matches: vec![],
                verdict: deny.clone(),
                duration_us: start.elapsed().as_micros() as u64,
            };
            return Ok((deny, trace));
        }

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

        // SECURITY (FIND-R206-001): Normalize tool/function names through homoglyph
        // normalization before policy matching. This prevents fullwidth/Cyrillic/Greek
        // characters from bypassing exact-match Deny policies. Patterns are normalized
        // at compile time; input must be normalized at evaluation time for consistency.
        // Matches the normalization in evaluate_with_compiled().
        let norm_tool = crate::normalize::normalize_full(&action.tool);
        let norm_func = crate::normalize::normalize_full(&action.function);

        // Walk compiled policies using the tool index (same order as evaluate_with_compiled)
        let indices = self.collect_candidate_indices_normalized(&norm_tool);
        let mut policy_matches: Vec<PolicyMatch> = Vec::with_capacity(indices.len());

        for idx in &indices {
            let cp = &self.compiled_policies[*idx];
            policies_checked += 1;

            let tool_matched = cp.tool_matcher.matches_normalized(&norm_tool, &norm_func);
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
    pub(crate) fn evaluate_action_traced_ctx(
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

        // SECURITY (R230-ENG-5): Topology pre-filter must run on ALL traced paths.
        #[cfg(feature = "discovery")]
        if let Some(deny) = self.check_topology(action) {
            let trace = EvaluationTrace {
                action_summary,
                policies_checked: 0,
                policies_matched: 0,
                matches: vec![],
                verdict: deny.clone(),
                duration_us: start.elapsed().as_micros() as u64,
            };
            return Ok((deny, trace));
        }

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

        // SECURITY (FIND-R206-001): Normalize for homoglyph-safe matching.
        let norm_tool = crate::normalize::normalize_full(&action.tool);
        let norm_func = crate::normalize::normalize_full(&action.function);

        let indices = self.collect_candidate_indices_normalized(&norm_tool);
        let mut policy_matches: Vec<PolicyMatch> = Vec::with_capacity(indices.len());

        for idx in &indices {
            let cp = &self.compiled_policies[*idx];
            policies_checked += 1;

            let tool_matched = cp.tool_matcher.matches_normalized(&norm_tool, &norm_func);
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

    /// Collect candidate policy indices using a pre-normalized tool name.
    ///
    /// SECURITY (FIND-R206-001): Uses the normalized tool name for index lookup,
    /// ensuring homoglyph-normalized tool names match the normalized index keys.
    fn collect_candidate_indices_normalized(&self, norm_tool: &str) -> Vec<usize> {
        if self.tool_index.is_empty() && self.always_check.is_empty() {
            // No index: return all indices in order
            return (0..self.compiled_policies.len()).collect();
        }

        let tool_specific = self.tool_index.get(norm_tool);
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
                    // SECURITY (R231-ENG-3): Normalize tool name before context
                    // conditions (mirrors lib.rs).
                    let norm_tool = crate::normalize::normalize_full(&action.tool);
                    if let Some(denial) = self.check_context_conditions(ctx, cp, &norm_tool) {
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
    pub(crate) fn evaluate_compiled_constraint_traced(
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
    pub(crate) fn describe_value(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Null => "null".to_string(),
            serde_json::Value::Bool(b) => format!("bool({})", b),
            serde_json::Value::Number(n) => format!("number({})", n),
            serde_json::Value::String(s) => format!("string({} chars)", s.len()),
            serde_json::Value::Array(arr) => format!("array({} items)", arr.len()),
            serde_json::Value::Object(obj) => format!("object({} keys)", obj.len()),
        }
    }

    /// Maximum nesting depth limit for JSON depth calculation.
    /// Returns this limit when exceeded rather than continuing traversal.
    const MAX_JSON_DEPTH_LIMIT: usize = 128;

    /// Maximum number of nodes to visit during JSON depth calculation.
    /// Prevents OOM from extremely wide JSON (e.g., objects with 100K keys).
    const MAX_JSON_DEPTH_NODES: usize = 10_000;

    /// Calculate the nesting depth of a JSON value using an iterative approach.
    /// Avoids stack overflow on adversarially deep JSON (e.g., 10,000+ levels).
    ///
    /// SECURITY (FIND-R46-005): Bounded by [`MAX_JSON_DEPTH_LIMIT`] (128) for
    /// depth and [`MAX_JSON_DEPTH_NODES`] (10,000) for total nodes visited.
    /// Returns the depth limit when either bound is exceeded, ensuring the
    /// caller's depth check triggers a reject.
    pub(crate) fn json_depth(value: &serde_json::Value) -> usize {
        let mut max_depth: usize = 0;
        let mut nodes_visited: usize = 0;
        // Stack of (value, current_depth) to process iteratively
        let mut stack: Vec<(&serde_json::Value, usize)> = vec![(value, 0)];

        while let Some((val, depth)) = stack.pop() {
            nodes_visited = nodes_visited.saturating_add(1); // FIND-R58-ENG-007: Trap 9
            if depth > max_depth {
                max_depth = depth;
            }
            // Early termination: if we exceed depth limit or node budget, stop
            if max_depth > Self::MAX_JSON_DEPTH_LIMIT || nodes_visited > Self::MAX_JSON_DEPTH_NODES
            {
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

    // ---- describe_value tests ----

    #[test]
    fn test_describe_value_null() {
        assert_eq!(PolicyEngine::describe_value(&json!(null)), "null");
    }

    #[test]
    fn test_describe_value_bool_true() {
        assert_eq!(PolicyEngine::describe_value(&json!(true)), "bool(true)");
    }

    #[test]
    fn test_describe_value_bool_false() {
        assert_eq!(PolicyEngine::describe_value(&json!(false)), "bool(false)");
    }

    #[test]
    fn test_describe_value_number_integer() {
        assert_eq!(PolicyEngine::describe_value(&json!(42)), "number(42)");
    }

    #[test]
    fn test_describe_value_number_float() {
        assert_eq!(PolicyEngine::describe_value(&json!(2.71)), "number(2.71)");
    }

    #[test]
    fn test_describe_value_string_empty() {
        assert_eq!(PolicyEngine::describe_value(&json!("")), "string(0 chars)");
    }

    #[test]
    fn test_describe_value_string_nonempty() {
        assert_eq!(
            PolicyEngine::describe_value(&json!("hello")),
            "string(5 chars)"
        );
    }

    #[test]
    fn test_describe_value_array_empty() {
        assert_eq!(
            PolicyEngine::describe_value(&json!([])),
            "array(0 items)"
        );
    }

    #[test]
    fn test_describe_value_array_nonempty() {
        assert_eq!(
            PolicyEngine::describe_value(&json!([1, 2, 3])),
            "array(3 items)"
        );
    }

    #[test]
    fn test_describe_value_object_empty() {
        assert_eq!(
            PolicyEngine::describe_value(&json!({})),
            "object(0 keys)"
        );
    }

    #[test]
    fn test_describe_value_object_nonempty() {
        assert_eq!(
            PolicyEngine::describe_value(&json!({"a": 1, "b": 2})),
            "object(2 keys)"
        );
    }

    // ---- json_depth tests ----

    #[test]
    fn test_json_depth_scalar_zero() {
        assert_eq!(PolicyEngine::json_depth(&json!(42)), 0);
        assert_eq!(PolicyEngine::json_depth(&json!("hello")), 0);
        assert_eq!(PolicyEngine::json_depth(&json!(null)), 0);
        assert_eq!(PolicyEngine::json_depth(&json!(true)), 0);
    }

    #[test]
    fn test_json_depth_flat_array() {
        assert_eq!(PolicyEngine::json_depth(&json!([1, 2, 3])), 1);
    }

    #[test]
    fn test_json_depth_flat_object() {
        assert_eq!(PolicyEngine::json_depth(&json!({"a": 1, "b": 2})), 1);
    }

    #[test]
    fn test_json_depth_nested_objects() {
        let nested = json!({"a": {"b": {"c": 1}}});
        assert_eq!(PolicyEngine::json_depth(&nested), 3);
    }

    #[test]
    fn test_json_depth_nested_arrays() {
        let nested = json!([[[1]]]);
        assert_eq!(PolicyEngine::json_depth(&nested), 3);
    }

    #[test]
    fn test_json_depth_mixed_nesting() {
        let mixed = json!({"a": [{"b": [1]}]});
        assert_eq!(PolicyEngine::json_depth(&mixed), 4);
    }

    #[test]
    fn test_json_depth_empty_containers() {
        assert_eq!(PolicyEngine::json_depth(&json!([])), 0);
        assert_eq!(PolicyEngine::json_depth(&json!({})), 0);
    }

    #[test]
    fn test_json_depth_wide_object() {
        // A wide but shallow object (many keys at depth 1)
        let mut obj = serde_json::Map::new();
        for i in 0..100 {
            obj.insert(format!("key_{}", i), json!(i));
        }
        let value = serde_json::Value::Object(obj);
        assert_eq!(PolicyEngine::json_depth(&value), 1);
    }

    // ---- policy_type_str tests ----

    #[test]
    fn test_policy_type_str_allow() {
        assert_eq!(PolicyEngine::policy_type_str(&PolicyType::Allow), "allow");
    }

    #[test]
    fn test_policy_type_str_deny() {
        assert_eq!(PolicyEngine::policy_type_str(&PolicyType::Deny), "deny");
    }

    #[test]
    fn test_policy_type_str_conditional() {
        let pt = PolicyType::Conditional {
            conditions: json!({}),
        };
        assert_eq!(PolicyEngine::policy_type_str(&pt), "conditional");
    }

    // ---- constraint_type_str tests ----

    #[test]
    fn test_constraint_type_str_all_variants() {
        use crate::compiled::CompiledConstraint;

        let glob = globset::GlobBuilder::new("*.txt")
            .literal_separator(true)
            .build()
            .unwrap()
            .compile_matcher();
        let c = CompiledConstraint::Glob {
            param: "p".to_string(),
            matcher: glob,
            pattern_str: "*.txt".to_string(),
            on_match: "deny".to_string(),
            on_missing: "skip".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "glob");

        let c = CompiledConstraint::Eq {
            param: "p".to_string(),
            value: json!(1),
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "eq");

        let c = CompiledConstraint::Ne {
            param: "p".to_string(),
            value: json!(1),
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "ne");

        let c = CompiledConstraint::OneOf {
            param: "p".to_string(),
            values: vec![],
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "one_of");

        let c = CompiledConstraint::NoneOf {
            param: "p".to_string(),
            values: vec![],
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "none_of");

        let c = CompiledConstraint::DomainMatch {
            param: "p".to_string(),
            pattern: "example.com".to_string(),
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "domain_match");

        let c = CompiledConstraint::DomainNotIn {
            param: "p".to_string(),
            patterns: vec![],
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "domain_not_in");

        let c = CompiledConstraint::Regex {
            param: "p".to_string(),
            regex: regex::Regex::new(".*").unwrap(),
            pattern_str: ".*".to_string(),
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "regex");

        let c = CompiledConstraint::NotGlob {
            param: "p".to_string(),
            matchers: vec![],
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_type_str(&c), "not_glob");
    }

    // ---- constraint_expected_str tests ----

    #[test]
    fn test_constraint_expected_str_eq() {
        let c = CompiledConstraint::Eq {
            param: "p".to_string(),
            value: json!("hello"),
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(
            PolicyEngine::constraint_expected_str(&c),
            "equals \"hello\""
        );
    }

    #[test]
    fn test_constraint_expected_str_ne() {
        let c = CompiledConstraint::Ne {
            param: "p".to_string(),
            value: json!(42),
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(PolicyEngine::constraint_expected_str(&c), "not equal 42");
    }

    #[test]
    fn test_constraint_expected_str_domain_match() {
        let c = CompiledConstraint::DomainMatch {
            param: "url".to_string(),
            pattern: "*.evil.com".to_string(),
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(
            PolicyEngine::constraint_expected_str(&c),
            "domain matches '*.evil.com'"
        );
    }

    #[test]
    fn test_constraint_expected_str_domain_not_in() {
        let c = CompiledConstraint::DomainNotIn {
            param: "url".to_string(),
            patterns: vec!["a.com".to_string(), "b.com".to_string()],
            on_match: "deny".to_string(),
            on_missing: "deny".to_string(),
        };
        assert_eq!(
            PolicyEngine::constraint_expected_str(&c),
            "domain not in [a.com, b.com]"
        );
    }

    // ---- evaluate_action_traced tests ----

    #[test]
    fn test_evaluate_action_traced_no_policies_deny() {
        let engine = PolicyEngine::new(false);
        let action = Action::new("tool", "func", json!({}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
        assert_eq!(trace.policies_checked, 0);
        assert_eq!(trace.policies_matched, 0);
        assert!(matches!(trace.verdict, Verdict::Deny { .. }));
    }

    #[test]
    fn test_evaluate_action_traced_allow_policy() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "allow-all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = Action::new("tool", "func", json!({}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Allow));
        assert!(trace.policies_checked >= 1);
        assert!(trace.policies_matched >= 1);
        assert!(trace.duration_us < 10_000_000); // sanity: should complete in <10s
    }

    #[test]
    fn test_evaluate_action_traced_deny_policy() {
        let policies = vec![Policy {
            id: "bash:*".to_string(),
            name: "block-bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = Action::new("bash", "execute", json!({}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
        assert_eq!(trace.action_summary.tool, "bash");
        assert_eq!(trace.action_summary.function, "execute");
    }

    #[test]
    fn test_evaluate_action_traced_action_summary_param_count() {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "allow-all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = Action::new("tool", "func", json!({"a": 1, "b": 2, "c": 3}));
        let (_, trace) = engine.evaluate_action_traced(&action).unwrap();
        assert_eq!(trace.action_summary.param_count, 3);
        assert_eq!(trace.action_summary.param_keys.len(), 3);
    }

    #[test]
    fn test_evaluate_action_traced_no_match_deny() {
        let policies = vec![Policy {
            id: "other_tool:*".to_string(),
            name: "allow-other".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = Action::new("bash", "execute", json!({}));
        let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
        // No matching policy -> deny
        assert!(matches!(verdict, Verdict::Deny { .. }));
        assert_eq!(trace.policies_matched, 0);
    }

    #[test]
    fn test_evaluate_action_traced_conditional_require_approval() {
        let policies = vec![Policy {
            id: "network:*".to_string(),
            name: "net-approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({ "require_approval": true }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = Action::new("network", "connect", json!({}));
        let (verdict, _trace) = engine.evaluate_action_traced(&action).unwrap();
        assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    }
}
