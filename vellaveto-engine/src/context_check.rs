// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Context condition evaluation.
//!
//! This module handles evaluation of context-aware policy conditions including:
//! - Time windows (hour of day, day of week)
//! - Per-session call limits
//! - Action sequence restrictions
//! - Agent ID matching
//! - Async task policies
//! - Circuit breaker integration

use crate::compiled::{CompiledContextCondition, CompiledPolicy};
use crate::matcher::PatternMatcher;
use crate::normalize::normalize_full;
use crate::verified_capability_context;
use crate::verified_capability_delegation_context;
use crate::verified_context_delegation;
use crate::PolicyEngine;
use chrono::{Datelike, Timelike};
use vellaveto_types::{sanitize_for_log, EvaluationContext, Verdict};

#[derive(Clone, Copy)]
struct CombinedDelegatedCapabilityConditions<'a> {
    require_principal: bool,
    max_delegation_depth: u8,
    min_remaining_depth: u8,
    deputy_deny_reason: &'a str,
    capability_deny_reason: &'a str,
}

fn combined_delegated_capability_conditions<'a>(
    conditions: &'a [CompiledContextCondition],
) -> Option<CombinedDelegatedCapabilityConditions<'a>> {
    let mut deputy: Option<(&'a bool, &'a u8, &'a str)> = None;
    let mut capability: Option<(&'a u8, &'a str)> = None;

    for cond in conditions {
        match cond {
            CompiledContextCondition::DeputyValidation {
                require_principal,
                max_delegation_depth,
                deny_reason,
            } => {
                if deputy.is_some() {
                    return None;
                }
                deputy = Some((require_principal, max_delegation_depth, deny_reason));
            }
            CompiledContextCondition::RequireCapabilityToken {
                min_remaining_depth,
                deny_reason,
                ..
            } => {
                if capability.is_some() {
                    return None;
                }
                capability = Some((min_remaining_depth, deny_reason));
            }
            _ => {}
        }
    }

    match (deputy, capability) {
        (
            Some((require_principal, max_delegation_depth, deputy_deny_reason)),
            Some((min_remaining_depth, capability_deny_reason)),
        ) => Some(CombinedDelegatedCapabilityConditions {
            require_principal: *require_principal,
            max_delegation_depth: *max_delegation_depth,
            min_remaining_depth: *min_remaining_depth,
            deputy_deny_reason,
            capability_deny_reason,
        }),
        _ => None,
    }
}

impl PolicyEngine {
    // VERIFIED [S6]: Context fail-closed — missing context data produces Deny (MCPPolicyEngine.tla S6)
    /// Evaluate context conditions against session state.
    ///
    /// Returns `Some(Deny)` if any context condition fails, `None` if all pass.
    pub(crate) fn check_context_conditions(
        &self,
        context: &EvaluationContext,
        cp: &CompiledPolicy,
        current_tool: &str,
    ) -> Option<Verdict> {
        let combined_conditions = combined_delegated_capability_conditions(&cp.context_conditions);
        if let Some(combined) = combined_conditions {
            const MAX_CLAIM_DISPLAY_LEN: usize = 128;
            let principal_present = verified_context_delegation::identified_principal_present(
                context.agent_identity.is_some(),
                context.agent_id.is_some(),
            );
            let capability_token_present = context.capability_token.is_some();
            let holder_matches_agent = context
                .capability_token
                .as_ref()
                .zip(context.agent_id.as_ref())
                .is_some_and(|(token, agent_id)| {
                    let holder_norm = normalize_full(&token.holder);
                    let agent_norm = normalize_full(agent_id);
                    holder_norm == agent_norm
                });
            let remaining_depth = context
                .capability_token
                .as_ref()
                .map_or(0, |token| token.remaining_depth);
            let delegation_depth = context.call_chain.len();

            if !verified_capability_delegation_context::delegated_capability_context_valid(
                combined.require_principal,
                context.agent_identity.is_some(),
                context.agent_id.is_some(),
                capability_token_present,
                holder_matches_agent,
                delegation_depth,
                combined.max_delegation_depth,
                remaining_depth,
                combined.min_remaining_depth,
            ) {
                if !verified_capability_delegation_context::delegated_capability_principal_and_holder_valid(
                    combined.require_principal,
                    context.agent_identity.is_some(),
                    context.agent_id.is_some(),
                    capability_token_present,
                    holder_matches_agent,
                ) {
                    if !verified_context_delegation::principal_requirement_satisfied(
                        combined.require_principal,
                        principal_present,
                    ) {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{} (principal required but not identified)",
                                combined.deputy_deny_reason
                            ),
                        });
                    }

                    if !capability_token_present {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{} (no capability token in context — fail-closed)",
                                combined.capability_deny_reason
                            ),
                        });
                    }

                    if let Some(agent_id) = &context.agent_id {
                        let safe_holder = context
                            .capability_token
                            .as_ref()
                            .map(|token| sanitize_for_log(&token.holder, MAX_CLAIM_DISPLAY_LEN))
                            .unwrap_or_else(|| "<none>".to_string());
                        let safe_agent = sanitize_for_log(agent_id, MAX_CLAIM_DISPLAY_LEN);
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{} (token holder '{safe_holder}' does not match agent_id '{safe_agent}')",
                                combined.capability_deny_reason
                            ),
                        });
                    }

                    return Some(Verdict::Deny {
                        reason: format!(
                            "{} (no agent_id in context — cannot verify token holder binding)",
                            combined.capability_deny_reason
                        ),
                    });
                }

                if !verified_context_delegation::delegation_depth_within_limit(
                    delegation_depth,
                    combined.max_delegation_depth,
                ) {
                    return Some(Verdict::Deny {
                        reason: format!(
                            "{} (delegation depth {delegation_depth} exceeds max {})",
                            combined.deputy_deny_reason, combined.max_delegation_depth
                        ),
                    });
                }

                return Some(Verdict::Deny {
                    reason: format!(
                        "{} (remaining depth {} below required {})",
                        combined.capability_deny_reason,
                        remaining_depth,
                        combined.min_remaining_depth
                    ),
                });
            }
        }

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
                                "{deny_reason} (no session call counts available — fail-closed)"
                            ),
                        });
                    }

                    // SECURITY (R8-6): Use saturating_add to prevent u64 overflow
                    // which could wrap to 0, bypassing rate limits.
                    // SECURITY (R34-ENG-5): Case-insensitive matching for consistency
                    // with ForbiddenPreviousAction/RequirePreviousAction (R31-ENG-7).
                    // SECURITY (FIND-R209-003): Normalize homoglyphs on call_counts
                    // keys before pattern matching, consistent with MaxCallsInWindow
                    // which already normalizes. Without this, an attacker can bypass
                    // rate limits by using Cyrillic/fullwidth tool name variants that
                    // don't match the pattern but invoke the same tool.
                    let count = if matches!(tool_pattern, PatternMatcher::Any) {
                        context
                            .call_counts
                            .values()
                            .fold(0u64, |acc, v| acc.saturating_add(*v))
                    } else {
                        context
                            .call_counts
                            .iter()
                            .filter(|(name, _)| {
                                let norm = normalize_full(name);
                                tool_pattern.matches_normalized(&norm)
                            })
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
                            // SECURITY (FIND-R209-002): Normalize homoglyphs to prevent
                            // Cyrillic/Greek/fullwidth characters from bypassing
                            // agent_id blocklists/allowlists.
                            let id_lower = normalize_full(id);
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
                    // SECURITY (FIND-R206-008): Homoglyph normalization on history entries
                    // to prevent Cyrillic/Greek/fullwidth characters from causing false denials.
                    if !context.previous_actions.iter().any(|a| {
                        let norm = normalize_full(a);
                        norm == *required_tool
                    }) {
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
                    // SECURITY (FIND-R206-007): Homoglyph normalization on history entries
                    // to prevent Cyrillic/Greek/fullwidth bypasses of forbidden action checks.
                    if context.previous_actions.iter().any(|a| {
                        let norm = normalize_full(a);
                        norm == *forbidden_tool
                    }) {
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
                    // SECURITY (FIND-R46-006): An empty previous_actions vec is valid
                    // state for the first request in a session — count is zero.
                    // Previously this fail-closed on empty, blocking the very first
                    // request even when max >= 1. Zero matching actions in the window
                    // is a valid count; only deny if count >= max.

                    let history = if *window > 0 {
                        let start = context.previous_actions.len().saturating_sub(*window);
                        &context.previous_actions[start..]
                    } else {
                        &context.previous_actions[..]
                    };
                    // SECURITY (R26-ENG-3): Fail-closed on count overflow.
                    // SECURITY (R34-ENG-5): Case-insensitive matching for consistency
                    // with ForbiddenPreviousAction/RequirePreviousAction (R31-ENG-7).
                    // SECURITY (FIND-R206-004): Homoglyph normalization on history entries
                    // to prevent rate limit bypass via Cyrillic/fullwidth variants.
                    let count_usize = history
                        .iter()
                        .filter(|a| {
                            let norm = normalize_full(a);
                            tool_pattern.matches_normalized(&norm)
                        })
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
                    // SECURITY (FIND-R110-002): Use > so that max_depth=0 means
                    // "direct calls only" (empty chain allowed) as documented in compiled.rs.
                    // max_depth is the exclusive upper bound: deny when len > max_depth.
                    if !verified_context_delegation::chain_depth_within_limit(
                        context.call_chain.len(),
                        *max_depth,
                    ) {
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
                    //
                    // SECURITY (FIND-R203-001): JWT claim values (issuer, subject, custom claims)
                    // are attacker-controlled strings. Before echoing them into denial reasons,
                    // sanitize via `sanitize_for_log()` (strips control chars + Unicode format
                    // chars) and truncate to 128 chars to prevent log injection and overly
                    // verbose denial reasons.
                    const MAX_CLAIM_DISPLAY_LEN: usize = 128;
                    match &context.agent_identity {
                        Some(identity) => {
                            // Check blocked issuers first (case-insensitive + homoglyph-normalized)
                            // SECURITY (FIND-R211-002): Normalize homoglyphs to prevent
                            // Cyrillic/fullwidth characters from bypassing blocked issuer checks.
                            if let Some(ref iss) = identity.issuer {
                                if blocked_issuers.contains(&normalize_full(iss)) {
                                    let safe_iss = sanitize_for_log(iss, MAX_CLAIM_DISPLAY_LEN);
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{deny_reason} (blocked issuer: {safe_iss})"
                                        ),
                                    });
                                }
                            }

                            // Check blocked subjects (case-insensitive + homoglyph-normalized)
                            // SECURITY (FIND-R211-002): Normalize homoglyphs to prevent
                            // Cyrillic/fullwidth characters from bypassing blocked subject checks.
                            if let Some(ref sub) = identity.subject {
                                if blocked_subjects.contains(&normalize_full(sub)) {
                                    let safe_sub = sanitize_for_log(sub, MAX_CLAIM_DISPLAY_LEN);
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{deny_reason} (blocked subject: {safe_sub})"
                                        ),
                                    });
                                }
                            }

                            // Check required issuer (case-insensitive + homoglyph-normalized, R40-ENG-2)
                            // SECURITY (FIND-R211-002): Normalize homoglyphs for consistency
                            // with blocked_issuers/blocked_subjects normalization.
                            if let Some(ref req_iss) = required_issuer {
                                match &identity.issuer {
                                    Some(iss) if normalize_full(iss) == *req_iss => {}
                                    _ => {
                                        let safe_got = identity
                                            .issuer
                                            .as_deref()
                                            .map(|s| sanitize_for_log(s, MAX_CLAIM_DISPLAY_LEN))
                                            .unwrap_or_else(|| "<none>".to_string());
                                        // SECURITY (FIND-R216-009): Truncate expected value in
                                        // denial reason to prevent oversized responses.
                                        let safe_expected =
                                            sanitize_for_log(req_iss, MAX_CLAIM_DISPLAY_LEN);
                                        return Some(Verdict::Deny {
                                            reason: format!(
                                                "{deny_reason} (issuer mismatch: expected '{safe_expected}', got '{safe_got}')"
                                            ),
                                        });
                                    }
                                }
                            }

                            // Check required subject (case-insensitive + homoglyph-normalized, R40-ENG-2)
                            // SECURITY (FIND-R211-002): Normalize homoglyphs for consistency.
                            if let Some(ref req_sub) = required_subject {
                                match &identity.subject {
                                    Some(sub) if normalize_full(sub) == *req_sub => {}
                                    _ => {
                                        let safe_got = identity
                                            .subject
                                            .as_deref()
                                            .map(|s| sanitize_for_log(s, MAX_CLAIM_DISPLAY_LEN))
                                            .unwrap_or_else(|| "<none>".to_string());
                                        let safe_expected =
                                            sanitize_for_log(req_sub, MAX_CLAIM_DISPLAY_LEN);
                                        return Some(Verdict::Deny {
                                            reason: format!(
                                                "{deny_reason} (subject mismatch: expected '{safe_expected}', got '{safe_got}')"
                                            ),
                                        });
                                    }
                                }
                            }

                            // Check required audience (case-insensitive + homoglyph-normalized, R40-ENG-2)
                            // SECURITY (FIND-R205-004): Sanitize audience values before
                            // including in denial reason — audience comes from JWT claims
                            // and is attacker-controlled. Bound displayed entries to 10.
                            // SECURITY (FIND-R211-002): Normalize homoglyphs for consistency.
                            if let Some(ref req_aud) = required_audience {
                                if !identity
                                    .audience
                                    .iter()
                                    .any(|a| normalize_full(a) == *req_aud)
                                {
                                    let safe_audiences: Vec<String> = identity
                                        .audience
                                        .iter()
                                        .take(10)
                                        .map(|a| sanitize_for_log(a, MAX_CLAIM_DISPLAY_LEN))
                                        .collect();
                                    let safe_expected =
                                        sanitize_for_log(req_aud, MAX_CLAIM_DISPLAY_LEN);
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{deny_reason} (audience mismatch: '{safe_expected}' not in {safe_audiences:?})"
                                        ),
                                    });
                                }
                            }

                            // Check required custom claims
                            // SECURITY (FIND-044): Case-insensitive comparison,
                            // matching issuer/subject/audience behavior.
                            // SECURITY (FIND-R203-001): Sanitize attacker-controlled
                            // actual claim values before including in denial reasons.
                            // SECURITY (IMP-R216-006): Apply homoglyph normalization
                            // to claim values for parity with issuer/subject checks.
                            // SECURITY (FIND-R218-001/005): Apply NFKC + full Unicode
                            // to_lowercase for consistency with issuer/subject/audience.
                            for (claim_key, expected_value) in required_claims {
                                match identity.claim_str(claim_key) {
                                    Some(actual) if normalize_full(actual) == *expected_value => {}
                                    actual => {
                                        let safe_actual = actual
                                            .map(|s| sanitize_for_log(s, MAX_CLAIM_DISPLAY_LEN))
                                            .unwrap_or_else(|| "<none>".to_string());
                                        return Some(Verdict::Deny {
                                            reason: format!(
                                                "{deny_reason} (claim '{claim_key}' mismatch: expected '{expected_value}', got '{safe_actual}')"
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
                                        "{deny_reason} (X-Agent-Identity header required but not provided)"
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
                                        "{deny_reason} (identity restrictions configured but no agent identity header provided)"
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
                    // SECURITY (FIND-P2-005): Log at warn level so operators know this
                    // condition is a no-op at the engine layer and enforcement happens
                    // elsewhere. Previously trace-level, which was invisible in production.
                    if *max_concurrent > 0 {
                        tracing::error!(
                            policy = %cp.policy.name,
                            max_concurrent = %max_concurrent,
                            "SECURITY: AsyncTaskPolicy condition is NOT enforced at the engine level. \
                             Enforcement requires the MCP proxy layer. Configure the proxy for task limits."
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
                            // SECURITY (R231-ENG-2): Normalize resource claim via
                            // normalize_full() before matching, consistent with all
                            // other context conditions (AgentId, CapabilityRequired, etc.).
                            let res_norm = crate::normalize::normalize_full(res);
                            // Check if resource matches any allowed pattern
                            if !allowed_resources.is_empty() {
                                let matches = allowed_resources
                                    .iter()
                                    .any(|p| p.matches_normalized(&res_norm));
                                if !matches {
                                    // SECURITY (FIND-R215-001): Sanitize JWT claim value
                                    // before interpolation into denial reason to prevent
                                    // log injection via attacker-controlled resource claims.
                                    const MAX_CLAIM_DISPLAY_LEN: usize = 128;
                                    let safe_res = sanitize_for_log(res, MAX_CLAIM_DISPLAY_LEN);
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{deny_reason} (resource '{safe_res}' not in allowed list)"
                                        ),
                                    });
                                }
                            }
                        }
                        None => {
                            // SECURITY (FIND-048): Fail-closed when allowed_resources
                            // is configured but no resource indicator is present.
                            // The presence of allowed_resources implies the admin
                            // intends to restrict by resource. Without this guard,
                            // omitting identity bypasses the allowlist.
                            if *require_resource || !allowed_resources.is_empty() {
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{deny_reason} (resource indicator required but not present)"
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
                    // SECURITY (FIND-045): Fail-closed when identity is missing but
                    // capabilities are configured. Matches the guard in AgentId and
                    // AgentIdentityMatch. Without this, omitting the identity header
                    // bypasses blocked_capabilities checks entirely.
                    if context.agent_identity.is_none()
                        && (!required_capabilities.is_empty() || !blocked_capabilities.is_empty())
                    {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{deny_reason} (no agent identity for capability check)"
                            ),
                        });
                    }

                    // CIMD: Capability-Indexed Message Dispatch
                    // Capabilities are stored in agent_identity claims as a comma-separated
                    // string or as a JSON array under the "capabilities" claim.
                    // SECURITY (FIND-043): Lowercase declared caps to match the
                    // compile-time normalization of required/blocked lists.
                    // SECURITY (FIND-R111-007): Limit the number of declared capabilities
                    // extracted from CSV or array claims to prevent OOM via a maliciously
                    // crafted capabilities string with thousands of comma-separated values.
                    const MAX_DECLARED_CAPABILITIES: usize = 256;

                    // SECURITY (FIND-R215-002): Apply normalize_homoglyphs() after
                    // to_ascii_lowercase() for parity with AgentId, AgentIdentityMatch,
                    // MaxCalls, RequireCapabilityToken. Without this, Cyrillic/fullwidth
                    // characters in declared capabilities bypass blocked/required checks.
                    let declared_caps: Vec<String> = context
                        .agent_identity
                        .as_ref()
                        .and_then(|id| {
                            // Try array first, then comma-separated string
                            id.claim_str_array("capabilities")
                                .map(|arr| {
                                    arr.into_iter()
                                        .take(MAX_DECLARED_CAPABILITIES)
                                        .map(normalize_full)
                                        .collect()
                                })
                                .or_else(|| {
                                    id.claim_str("capabilities").map(|s| {
                                        s.split(',')
                                            .take(MAX_DECLARED_CAPABILITIES)
                                            .map(|p| normalize_full(p.trim()))
                                            .collect()
                                    })
                                })
                        })
                        .unwrap_or_default();

                    // Check blocked capabilities first
                    for blocked in blocked_capabilities {
                        if declared_caps.iter().any(|c| c == blocked) {
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{deny_reason} (blocked capability '{blocked}' is declared)"
                                ),
                            });
                        }
                    }

                    // Check required capabilities
                    for required in required_capabilities {
                        if !declared_caps.iter().any(|c| c == required) {
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{deny_reason} (required capability '{required}' not declared)"
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
                    let raw_level = context
                        .agent_identity
                        .as_ref()
                        .and_then(|id| id.claim_str("auth_level"));
                    let current_level: u8 = match raw_level {
                        Some(s) => match s.parse() {
                            Ok(v) => v,
                            Err(_) => {
                                // SECURITY (FIND-046): Log unparseable auth_level rather than
                                // silently defaulting to 0. Still fail-closed (level 0).
                                tracing::warn!(
                                    auth_level = %s,
                                    "auth_level claim is not a valid u8, defaulting to 0"
                                );
                                0
                            }
                        },
                        None => 0,
                    };

                    if current_level < *required_level {
                        // Return a special verdict that signals step-up is needed
                        // The proxy layer interprets this and issues an authentication challenge
                        return Some(Verdict::RequireApproval {
                            reason: format!(
                                "{deny_reason} (current level {current_level}, required {required_level})"
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
                    // in vellaveto-engine/src/circuit_breaker.rs. This condition is evaluated here
                    // for policy matching, but actual enforcement happens at the integration layer.
                    //
                    // SECURITY (FIND-P2-005): Log at warn level so operators know this
                    // condition is a no-op at the engine layer and enforcement happens
                    // elsewhere. Previously trace-level, which was invisible in production.
                    tracing::warn!(
                        policy = %cp.policy.name,
                        "circuit_breaker condition is a no-op in engine — enforcement is in CircuitBreakerManager"
                    );
                    // Continue to next condition - enforcement is in the manager
                }

                CompiledContextCondition::DeputyValidation {
                    require_principal,
                    max_delegation_depth,
                    deny_reason,
                } => {
                    if combined_conditions.is_some() {
                        continue;
                    }
                    // OWASP ASI02: Confused deputy prevention
                    // Check principal context if available
                    // Principal context is stored in agent_identity claims
                    let has_principal = verified_context_delegation::identified_principal_present(
                        context.agent_identity.is_some(),
                        context.agent_id.is_some(),
                    );

                    if !verified_context_delegation::principal_requirement_satisfied(
                        *require_principal,
                        has_principal,
                    ) {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{deny_reason} (principal required but not identified)"
                            ),
                        });
                    }

                    // Check delegation depth from call chain
                    // The call chain represents the delegation chain in multi-agent scenarios
                    let delegation_depth = context.call_chain.len();
                    if !verified_context_delegation::delegation_depth_within_limit(
                        delegation_depth,
                        *max_delegation_depth,
                    ) {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{deny_reason} (delegation depth {delegation_depth} exceeds max {max_delegation_depth})"
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
                    // in vellaveto-mcp/src/shadow_agent.rs. This condition is evaluated here
                    // for policy matching, but actual enforcement happens at the integration layer.
                    //
                    // SECURITY (FIND-P2-005): Log at warn level so operators know this
                    // condition is a no-op at the engine layer and enforcement happens
                    // elsewhere. Previously trace-level, which was invisible in production.
                    tracing::warn!(
                        policy = %cp.policy.name,
                        "shadow_agent_check condition is a no-op in engine — enforcement is in ShadowAgentDetector"
                    );
                    // Continue to next condition - enforcement is in the detector
                }

                CompiledContextCondition::SchemaPoisoningCheck {
                    mutation_threshold: _,
                    deny_reason: _,
                } => {
                    // OWASP ASI05: Schema poisoning protection
                    // Note: Actual schema tracking is done by SchemaLineageTracker
                    // in vellaveto-mcp/src/schema_poisoning.rs. This condition is evaluated here
                    // for policy matching, but actual enforcement happens at the integration layer.
                    //
                    // SECURITY (FIND-P2-005): Log at warn level so operators know this
                    // condition is a no-op at the engine layer and enforcement happens
                    // elsewhere. Previously trace-level, which was invisible in production.
                    tracing::warn!(
                        policy = %cp.policy.name,
                        "schema_poisoning_check condition is a no-op in engine — enforcement is in SchemaLineageTracker"
                    );
                    // Continue to next condition - enforcement is in the tracker
                }

                CompiledContextCondition::MinVerificationTier {
                    required_tier,
                    deny_reason,
                } => {
                    // Identity verification tier enforcement.
                    // SECURITY: Fail-closed when verification_tier is None — if the
                    // proxy/caller did not populate the tier, we cannot verify it,
                    // so we must deny rather than silently allowing.
                    match &context.verification_tier {
                        Some(tier) => {
                            if tier.level() < *required_tier {
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{} (current tier '{}' level {}, required level {})",
                                        deny_reason,
                                        tier,
                                        tier.level(),
                                        required_tier
                                    ),
                                });
                            }
                        }
                        None => {
                            // Fail-closed: no verification tier in context
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{deny_reason} (no verification tier in context — fail-closed)"
                                ),
                            });
                        }
                    }
                }

                CompiledContextCondition::RequireCapabilityToken {
                    required_issuers,
                    min_remaining_depth,
                    deny_reason,
                } => {
                    // Capability-based delegation token enforcement.
                    // SECURITY: Fail-closed when capability_token is None.
                    const MAX_CLAIM_DISPLAY_LEN: usize = 128;
                    match &context.capability_token {
                        Some(token) => {
                            if combined_conditions.is_none() {
                                // Check holder matches agent_id (prevents token theft).
                                // SECURITY (FIND-R111-001): Fail-closed when agent_id is absent —
                                // a stolen capability token cannot be used by a caller that omits
                                // the agent_id field, which would otherwise bypass holder binding.
                                let holder_matches_agent =
                                    context.agent_id.as_ref().is_some_and(|agent_id| {
                                        // SECURITY (FIND-R213-001): Normalize homoglyphs on both
                                        // token.holder and agent_id before comparison. The previous
                                        // eq_ignore_ascii_case was insufficient — Cyrillic/Greek/
                                        // fullwidth characters that visually resemble Latin chars
                                        // would bypass holder binding, allowing token theft by an
                                        // agent with a homoglyph-variant name.
                                        let holder_norm = normalize_full(&token.holder);
                                        let agent_norm = normalize_full(agent_id);
                                        holder_norm == agent_norm
                                    });
                                if !verified_capability_context::capability_holder_binding_valid(
                                    context.agent_id.is_some(),
                                    holder_matches_agent,
                                ) {
                                    if let Some(agent_id) = &context.agent_id {
                                        // SECURITY (IMP-R218-007): Sanitize attacker-controlled
                                        // holder and agent_id before embedding in denial reason.
                                        let safe_holder =
                                            sanitize_for_log(&token.holder, MAX_CLAIM_DISPLAY_LEN);
                                        let safe_agent =
                                            sanitize_for_log(agent_id, MAX_CLAIM_DISPLAY_LEN);
                                        return Some(Verdict::Deny {
                                            reason: format!(
                                                "{deny_reason} (token holder '{safe_holder}' does not match agent_id '{safe_agent}')"
                                            ),
                                        });
                                    }
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{deny_reason} (no agent_id in context — cannot verify token holder binding)"
                                        ),
                                    });
                                }
                            }

                            // Check issuer allowlist
                            // SECURITY (IMP-R216-005): Apply homoglyph normalization
                            // for parity with agent_identity issuer checks.
                            // SECURITY (FIND-R218-001): Apply NFKC for circled/math letter coverage.
                            let required_issuers_empty = required_issuers.is_empty();
                            let issuer_lower = normalize_full(&token.issuer);
                            let issuer_allowed = required_issuers.contains(&issuer_lower);
                            if !verified_capability_context::capability_issuer_allowed(
                                required_issuers_empty,
                                issuer_allowed,
                            ) {
                                // SECURITY (IMP-R218-007): Sanitize attacker-controlled
                                // issuer before embedding in denial reason.
                                let safe_issuer =
                                    sanitize_for_log(&token.issuer, MAX_CLAIM_DISPLAY_LEN);
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{deny_reason} (issuer '{safe_issuer}' not in allowed list)"
                                    ),
                                });
                            }

                            // Check remaining delegation depth
                            if combined_conditions.is_none() {
                                // Check remaining delegation depth
                                if !verified_capability_context::capability_remaining_depth_sufficient(
                                    token.remaining_depth,
                                    *min_remaining_depth,
                                ) {
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{} (remaining depth {} below required {})",
                                            deny_reason, token.remaining_depth, min_remaining_depth
                                        ),
                                    });
                                }
                            }
                        }
                        None => {
                            // Fail-closed: no capability token in context
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{deny_reason} (no capability token in context — fail-closed)"
                                ),
                            });
                        }
                    }
                }

                CompiledContextCondition::SessionStateRequired {
                    allowed_states,
                    deny_reason,
                } => {
                    // Session state guard enforcement (Phase 23.5).
                    // SECURITY: Fail-closed when session_state is None.
                    match &context.session_state {
                        Some(state) => {
                            // SECURITY (FIND-R215-003): Apply normalize_homoglyphs()
                            // after to_ascii_lowercase() for parity with other conditions.
                            let state_lower = normalize_full(state);
                            if !allowed_states.contains(&state_lower) {
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{deny_reason} (session state '{state}' not in allowed states: {allowed_states:?})"
                                    ),
                                });
                            }
                        }
                        None => {
                            // Fail-closed: no session state in context
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{deny_reason} (no session state in context — fail-closed)"
                                ),
                            });
                        }
                    }
                }

                // ═══════════════════════════════════════════════════
                // PHASE 40: WORKFLOW-LEVEL POLICY CONSTRAINTS
                // ═══════════════════════════════════════════════════

                // VERIFIED [S8]: Workflow predecessor — a governed tool is only allowed if
                // it's a valid successor of the most recent governed tool (WorkflowConstraint.tla S8)
                CompiledContextCondition::RequiredActionSequence {
                    sequence,
                    ordered,
                    deny_reason,
                } => {
                    let history = &context.previous_actions;

                    // Fail-closed: history must have at least as many entries as the sequence.
                    if history.len() < sequence.len() {
                        return Some(Verdict::Deny {
                            reason: deny_reason.clone(),
                        });
                    }

                    if *ordered {
                        // Ordered subsequence match: greedy left-to-right scan.
                        // Advance sequence pointer each time a history entry matches.
                        // SECURITY (FIND-R206-005): Homoglyph normalization on history
                        // entries to prevent bypass via Cyrillic/fullwidth variants.
                        let mut seq_idx = 0;
                        for h in history {
                            if seq_idx < sequence.len() {
                                let norm = normalize_full(h);
                                if norm == sequence[seq_idx] {
                                    seq_idx += 1;
                                }
                            }
                        }
                        if seq_idx < sequence.len() {
                            return Some(Verdict::Deny {
                                reason: deny_reason.clone(),
                            });
                        }
                    } else {
                        // Unordered: every tool in sequence must appear somewhere in history.
                        // SECURITY (FIND-R50-011): Track matched indices to handle
                        // duplicate tools correctly. Without this, sequence ["a", "a"]
                        // would be satisfied by a single "a" in history.
                        // SECURITY (FIND-R206-005): Homoglyph normalization.
                        let mut used = vec![false; history.len()];
                        for required in sequence {
                            let found = history.iter().enumerate().position(|(i, h)| {
                                if used[i] {
                                    return false;
                                }
                                let norm = normalize_full(h);
                                norm == *required
                            });
                            match found {
                                Some(i) => used[i] = true,
                                None => {
                                    return Some(Verdict::Deny {
                                        reason: deny_reason.clone(),
                                    });
                                }
                            }
                        }
                    }
                }

                CompiledContextCondition::ForbiddenActionSequence {
                    sequence,
                    ordered,
                    deny_reason,
                } => {
                    let history = &context.previous_actions;

                    // SECURITY (FIND-CREATIVE-004): Warn when history is at capacity.
                    // If previous_actions has been truncated to MAX_PREVIOUS_ACTIONS,
                    // earlier entries may have been evicted, meaning a forbidden prefix
                    // could have aged out of the retained window. This is a false-negative
                    // risk — the forbidden sequence may not be detected because the
                    // attacker's earlier actions are no longer in history.
                    if history.len() >= vellaveto_types::EvaluationContext::MAX_PREVIOUS_ACTIONS {
                        tracing::warn!(
                            policy = %cp.policy.name,
                            history_len = history.len(),
                            max = vellaveto_types::EvaluationContext::MAX_PREVIOUS_ACTIONS,
                            "ForbiddenActionSequence check on truncated history — \
                             earlier actions may have been evicted, risk of false negatives"
                        );
                    }

                    // SECURITY (FIND-R50-010): Include current_tool in the effective
                    // history for forbidden sequence matching. Without this, a two-step
                    // exfiltration like [read_secret, http_request] is only detected
                    // AFTER http_request has been forwarded (one step too late).
                    // SECURITY (FIND-R206-005): Homoglyph normalization on current_tool
                    // and history entries to prevent bypass via Cyrillic/fullwidth variants.
                    let current_norm = normalize_full(current_tool);

                    if *ordered {
                        // Ordered subsequence match over history + current_tool.
                        let mut seq_idx = 0;
                        for h in history
                            .iter()
                            .map(|s| normalize_full(s))
                            .chain(std::iter::once(current_norm.clone()))
                        {
                            if seq_idx < sequence.len() && h == sequence[seq_idx] {
                                seq_idx += 1;
                            }
                        }
                        if seq_idx >= sequence.len() {
                            return Some(Verdict::Deny {
                                reason: deny_reason.clone(),
                            });
                        }
                    } else {
                        // Unordered: if all tools present in history + current_tool → Deny.
                        // SECURITY (FIND-R50-012): Track matched indices to handle
                        // duplicate tools correctly (don't double-count same entry).
                        // SECURITY (FIND-R206-005): Homoglyph normalization.
                        let effective: Vec<String> = history
                            .iter()
                            .map(|s| normalize_full(s))
                            .chain(std::iter::once(current_norm.clone()))
                            .collect();
                        let mut used = vec![false; effective.len()];
                        let all_present = sequence.iter().all(|required| {
                            effective.iter().enumerate().any(|(i, h)| {
                                if !used[i] && h == required {
                                    used[i] = true;
                                    true
                                } else {
                                    false
                                }
                            })
                        });
                        if all_present {
                            return Some(Verdict::Deny {
                                reason: deny_reason.clone(),
                            });
                        }
                    }
                }

                CompiledContextCondition::WorkflowTemplate {
                    adjacency,
                    governed_tools,
                    entry_points,
                    strict,
                    deny_reason,
                } => {
                    // SECURITY (FIND-R206-005): Homoglyph normalization on workflow tools.
                    let tool_norm = normalize_full(current_tool);

                    // Non-governed tools pass through — no restriction.
                    if !governed_tools.contains(&tool_norm) {
                        // Continue to next condition.
                    } else {
                        let history = &context.previous_actions;

                        // Find the most recent governed tool in history (reverse scan).
                        // SECURITY (FIND-R50-019): governed_tools contains lowercase strings.
                        // SECURITY (FIND-R206-005): Homoglyph normalization on history entries.
                        let last_governed = history
                            .iter()
                            .rev()
                            .find(|h| {
                                let norm = normalize_full(h);
                                governed_tools.contains(&norm)
                            })
                            .map(|h| normalize_full(h));

                        let violation = match last_governed {
                            None => {
                                // No previous governed tool: current must be an entry point.
                                !entry_points.iter().any(|ep| ep == &tool_norm)
                            }
                            Some(ref prev) => {
                                // Current must be a valid successor of the previous governed tool.
                                match adjacency.get(prev.as_str()) {
                                    Some(successors) => !successors.iter().any(|s| s == &tool_norm),
                                    None => {
                                        // Previous tool is a terminal node (no successors).
                                        // Current governed tool has no valid predecessor → violation.
                                        true
                                    }
                                }
                            }
                        };

                        if violation {
                            if *strict {
                                return Some(Verdict::Deny {
                                    reason: deny_reason.clone(),
                                });
                            }
                            // SECURITY (R231-ENG-6): Sanitize current_tool before
                            // logging to prevent log injection via control/format chars.
                            tracing::warn!(
                                policy = %cp.policy.name,
                                tool = %vellaveto_types::sanitize_for_log(current_tool, 128),
                                "workflow template violation (warn mode): {}",
                                deny_reason
                            );
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use vellaveto_types::{
        Action, AgentIdentity, CallChainEntry, EvaluationContext, Policy, PolicyType, Verdict,
    };

    // ── helpers ──────────────────────────────────────────────────────────

    fn ctx_policy(id: &str, context_conditions: serde_json::Value) -> Policy {
        Policy {
            id: id.to_string(),
            name: "ctx-test".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({ "context_conditions": context_conditions }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }
    }

    fn ctx_engine(policy: Policy) -> PolicyEngine {
        let mut engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
        engine.set_trust_context_timestamps(true);
        engine
    }

    #[allow(deprecated)] // evaluate_action_with_context is the only API accepting context
    fn eval(engine: &PolicyEngine, tool: &str, ctx: &EvaluationContext) -> Verdict {
        engine
            .evaluate_action_with_context(
                &Action::new(tool.to_string(), "execute".to_string(), json!({})),
                &[],
                Some(ctx),
            )
            .unwrap()
    }

    // ── 1. Time window checks ────────────────────────────────────────────

    #[test]
    fn test_time_window_hour_boundary_start_allow() {
        // Exactly at start_hour should be allowed (>= start_hour)
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "time_window", "start_hour": 9, "end_hour": 17}]),
        ));
        let ctx = EvaluationContext {
            timestamp: Some("2026-03-04T09:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_time_window_hour_boundary_end_deny() {
        // Exactly at end_hour should be denied (< end_hour, not <=)
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "time_window", "start_hour": 9, "end_hour": 17}]),
        ));
        let ctx = EvaluationContext {
            timestamp: Some("2026-03-04T17:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_time_window_midnight_wrap_allow_before_midnight() {
        // 22-6 overnight window: 23:00 is within window
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "time_window", "start_hour": 22, "end_hour": 6}]),
        ));
        let ctx = EvaluationContext {
            timestamp: Some("2026-03-04T23:30:00Z".to_string()),
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_time_window_midnight_wrap_allow_after_midnight() {
        // 22-6 overnight window: 03:00 is within window
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "time_window", "start_hour": 22, "end_hour": 6}]),
        ));
        let ctx = EvaluationContext {
            timestamp: Some("2026-03-05T03:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_time_window_midnight_wrap_deny_midday() {
        // 22-6 overnight window: 12:00 is outside window
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "time_window", "start_hour": 22, "end_hour": 6}]),
        ));
        let ctx = EvaluationContext {
            timestamp: Some("2026-03-04T12:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_time_window_day_of_week_deny_wrong_day() {
        // 2026-03-04 is Wednesday (day 3). Policy only allows Monday (1).
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "time_window", "start_hour": 0, "end_hour": 23, "days": [1]}]),
        ));
        let ctx = EvaluationContext {
            timestamp: Some("2026-03-04T10:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_time_window_day_of_week_allow_correct_day() {
        // 2026-03-04 is Wednesday (day 3). Policy allows Wednesday.
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "time_window", "start_hour": 0, "end_hour": 23, "days": [3]}]),
        ));
        let ctx = EvaluationContext {
            timestamp: Some("2026-03-04T10:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    // ── 2. Call limit enforcement ────────────────────────────────────────

    #[test]
    fn test_max_calls_empty_call_counts_fail_closed() {
        // MaxCalls with empty call_counts should fail-closed
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_calls", "tool_pattern": "read_file", "max": 5}]),
        ));
        let ctx = EvaluationContext {
            call_counts: HashMap::new(),
            ..Default::default()
        };
        let v = eval(&engine, "read_file", &ctx);
        assert!(matches!(v, Verdict::Deny { .. }));
        if let Verdict::Deny { reason } = v {
            assert!(reason.contains("fail-closed"));
        }
    }

    #[test]
    fn test_max_calls_under_limit_allow() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_calls", "tool_pattern": "read_file", "max": 5}]),
        ));
        let mut cc = HashMap::new();
        cc.insert("read_file".to_string(), 3u64);
        let ctx = EvaluationContext {
            call_counts: cc,
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_max_calls_at_limit_deny() {
        // count >= max triggers denial (>= not >)
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_calls", "tool_pattern": "read_file", "max": 5}]),
        ));
        let mut cc = HashMap::new();
        cc.insert("read_file".to_string(), 5u64);
        let ctx = EvaluationContext {
            call_counts: cc,
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_max_calls_wildcard_aggregates_all_tools() {
        // PatternMatcher::Any aggregates all tools
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_calls", "tool_pattern": "*", "max": 10}]),
        ));
        let mut cc = HashMap::new();
        cc.insert("read_file".to_string(), 4u64);
        cc.insert("write_file".to_string(), 4u64);
        cc.insert("delete_file".to_string(), 3u64);
        // Total = 11, exceeds max 10
        let ctx = EvaluationContext {
            call_counts: cc,
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    // ── 3. Previous action requirements ──────────────────────────────────

    #[test]
    fn test_require_previous_action_present_allow() {
        let engine = ctx_engine(ctx_policy(
            "deploy:*",
            json!([{"type": "require_previous_action", "required_tool": "review"}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec!["review".to_string()],
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "deploy", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_require_previous_action_missing_deny() {
        let engine = ctx_engine(ctx_policy(
            "deploy:*",
            json!([{"type": "require_previous_action", "required_tool": "review"}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec!["other_action".to_string()],
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "deploy", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_require_previous_action_case_insensitive() {
        // RequirePreviousAction should match case-insensitively via normalize_full
        let engine = ctx_engine(ctx_policy(
            "deploy:*",
            json!([{"type": "require_previous_action", "required_tool": "review"}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec!["REVIEW".to_string()],
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "deploy", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_forbidden_previous_action_present_deny() {
        let engine = ctx_engine(ctx_policy(
            "http_request:*",
            json!([{"type": "forbidden_previous_action", "forbidden_tool": "read_secret"}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec!["read_secret".to_string()],
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "http_request", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_forbidden_previous_action_absent_allow() {
        let engine = ctx_engine(ctx_policy(
            "http_request:*",
            json!([{"type": "forbidden_previous_action", "forbidden_tool": "read_secret"}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec!["list_files".to_string()],
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "http_request", &ctx),
            Verdict::Allow
        ));
    }

    #[test]
    fn test_forbidden_previous_action_case_insensitive() {
        // "READ_SECRET" in history should match "read_secret" forbidden tool
        let engine = ctx_engine(ctx_policy(
            "http_request:*",
            json!([{"type": "forbidden_previous_action", "forbidden_tool": "read_secret"}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec!["READ_SECRET".to_string()],
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "http_request", &ctx),
            Verdict::Deny { .. }
        ));
    }

    // ── 4. Agent ID matching ─────────────────────────────────────────────

    #[test]
    fn test_agent_id_allowed_list_match_allow() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "agent_id", "allowed": ["agent-alpha"]}]),
        ));
        let ctx = EvaluationContext {
            agent_id: Some("agent-alpha".to_string()),
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_agent_id_allowed_list_no_match_deny() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "agent_id", "allowed": ["agent-alpha"]}]),
        ));
        let ctx = EvaluationContext {
            agent_id: Some("agent-beta".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_agent_id_blocked_list_deny() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "agent_id", "blocked": ["rogue-agent"]}]),
        ));
        let ctx = EvaluationContext {
            agent_id: Some("rogue-agent".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_agent_id_missing_with_allowed_list_fail_closed() {
        // No agent_id but allowed list is non-empty: fail-closed
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "agent_id", "allowed": ["agent-alpha"]}]),
        ));
        let ctx = EvaluationContext {
            agent_id: None,
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_agent_id_case_insensitive_normalization() {
        // Agent ID matching should be case-insensitive via normalize_full
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "agent_id", "allowed": ["agent-alpha"]}]),
        ));
        let ctx = EvaluationContext {
            agent_id: Some("AGENT-ALPHA".to_string()),
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    // ── 5. Max chain depth ───────────────────────────────────────────────

    #[test]
    fn test_max_chain_depth_within_limit_allow() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_chain_depth", "max_depth": 2}]),
        ));
        let entry = CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "t".to_string(),
            function: "f".to_string(),
            timestamp: "2026-03-04T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        };
        let ctx = EvaluationContext {
            call_chain: vec![entry],
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_max_chain_depth_exceeds_limit_deny() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_chain_depth", "max_depth": 1}]),
        ));
        let mk_entry = |id: &str| CallChainEntry {
            agent_id: id.to_string(),
            tool: "t".to_string(),
            function: "f".to_string(),
            timestamp: "2026-03-04T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        };
        let ctx = EvaluationContext {
            call_chain: vec![mk_entry("a1"), mk_entry("a2")],
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_max_chain_depth_zero_allows_empty_chain() {
        // max_depth=0 means only direct calls (empty chain) allowed
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_chain_depth", "max_depth": 0}]),
        ));
        let ctx = EvaluationContext {
            call_chain: vec![],
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    // ── 6. Session state required ────────────────────────────────────────

    #[test]
    fn test_session_state_required_matching_allow() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "session_state_required", "allowed_states": ["active", "init"]}]),
        ));
        let ctx = EvaluationContext {
            session_state: Some("active".to_string()),
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_session_state_required_missing_fail_closed() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "session_state_required", "allowed_states": ["active"]}]),
        ));
        let ctx = EvaluationContext {
            session_state: None,
            ..Default::default()
        };
        let v = eval(&engine, "read_file", &ctx);
        assert!(matches!(v, Verdict::Deny { .. }));
        if let Verdict::Deny { reason } = v {
            assert!(reason.contains("fail-closed"));
        }
    }

    #[test]
    fn test_session_state_required_wrong_state_deny() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "session_state_required", "allowed_states": ["active"]}]),
        ));
        let ctx = EvaluationContext {
            session_state: Some("suspended".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    // ── 7. MaxCallsInWindow ──────────────────────────────────────────────

    #[test]
    fn test_max_calls_in_window_under_limit_allow() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 3, "window": 5}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec![
                "read_file".to_string(),
                "other".to_string(),
                "read_file".to_string(),
            ],
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_max_calls_in_window_at_limit_deny() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 2, "window": 5}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec![
                "read_file".to_string(),
                "other".to_string(),
                "read_file".to_string(),
            ],
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_max_calls_in_window_zero_window_uses_full_history() {
        // window=0 means entire history
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 3, "window": 0}]),
        ));
        let ctx = EvaluationContext {
            previous_actions: vec![
                "read_file".to_string(),
                "read_file".to_string(),
                "read_file".to_string(),
            ],
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    // ── 8. Fail-closed: empty conditions / missing fields ────────────────

    #[test]
    fn test_empty_context_conditions_allow() {
        // No context conditions means all pass -> Allow
        let engine = ctx_engine(ctx_policy("read_file:*", json!([])));
        let ctx = EvaluationContext::default();
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_min_verification_tier_missing_fail_closed() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "min_verification_tier", "required_tier": 2}]),
        ));
        let ctx = EvaluationContext {
            verification_tier: None,
            ..Default::default()
        };
        let v = eval(&engine, "read_file", &ctx);
        assert!(matches!(v, Verdict::Deny { .. }));
        if let Verdict::Deny { reason } = v {
            assert!(reason.contains("fail-closed"));
        }
    }

    #[test]
    fn test_min_verification_tier_sufficient_allow() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "min_verification_tier", "required_tier": 2}]),
        ));
        let ctx = EvaluationContext {
            verification_tier: Some(vellaveto_types::VerificationTier::DidVerified), // level 3
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }

    #[test]
    fn test_min_verification_tier_insufficient_deny() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "min_verification_tier", "required_tier": 3}]),
        ));
        let ctx = EvaluationContext {
            verification_tier: Some(vellaveto_types::VerificationTier::EmailVerified), // level 1
            ..Default::default()
        };
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    // ── 9. Deputy validation / delegation depth ──────────────────────────

    #[test]
    fn test_deputy_validation_require_principal_missing_deny() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "deputy_validation", "require_principal": true, "max_delegation_depth": 3}]),
        ));
        // No agent_identity, no agent_id -> no principal
        let ctx = EvaluationContext::default();
        assert!(matches!(
            eval(&engine, "read_file", &ctx),
            Verdict::Deny { .. }
        ));
    }

    #[test]
    fn test_deputy_validation_delegation_depth_exceeded_deny() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "deputy_validation", "require_principal": false, "max_delegation_depth": 1}]),
        ));
        let mk_entry = |id: &str| CallChainEntry {
            agent_id: id.to_string(),
            tool: "t".to_string(),
            function: "f".to_string(),
            timestamp: "2026-03-04T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        };
        let ctx = EvaluationContext {
            call_chain: vec![mk_entry("a1"), mk_entry("a2")],
            ..Default::default()
        };
        let v = eval(&engine, "read_file", &ctx);
        assert!(matches!(v, Verdict::Deny { .. }));
        if let Verdict::Deny { reason } = v {
            assert!(reason.contains("delegation depth"));
        }
    }

    // ── 10. Step-up auth ─────────────────────────────────────────────────

    #[test]
    fn test_step_up_auth_insufficient_level_require_approval() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "step_up_auth", "required_level": 3}]),
        ));
        // auth_level=1 < required_level=3 -> RequireApproval
        let ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity {
                claims: {
                    let mut m = HashMap::new();
                    m.insert("auth_level".to_string(), json!("1"));
                    m
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let v = eval(&engine, "read_file", &ctx);
        assert!(
            matches!(v, Verdict::RequireApproval { .. }),
            "Expected RequireApproval, got {v:?}"
        );
    }

    #[test]
    fn test_step_up_auth_sufficient_level_allow() {
        let engine = ctx_engine(ctx_policy(
            "read_file:*",
            json!([{"type": "step_up_auth", "required_level": 2}]),
        ));
        let ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity {
                claims: {
                    let mut m = HashMap::new();
                    m.insert("auth_level".to_string(), json!("3"));
                    m
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(eval(&engine, "read_file", &ctx), Verdict::Allow));
    }
}
