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
use crate::PolicyEngine;
use chrono::{Datelike, Timelike};
use vellaveto_types::{EvaluationContext, Verdict};

impl PolicyEngine {
    /// Evaluate context conditions against session state.
    ///
    /// Returns `Some(Deny)` if any context condition fails, `None` if all pass.
    pub(crate) fn check_context_conditions(
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
                                "{deny_reason} (no session call counts available — fail-closed)"
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
                                "{deny_reason} (no session history available — fail-closed)"
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
                                        reason: format!("{deny_reason} (blocked issuer: {iss})"),
                                    });
                                }
                            }

                            // Check blocked subjects (case-insensitive)
                            if let Some(ref sub) = identity.subject {
                                if blocked_subjects.contains(&sub.to_lowercase()) {
                                    return Some(Verdict::Deny {
                                        reason: format!("{deny_reason} (blocked subject: {sub})"),
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
                            // SECURITY (FIND-044): Case-insensitive comparison,
                            // matching issuer/subject/audience behavior.
                            for (claim_key, expected_value) in required_claims {
                                match identity.claim_str(claim_key) {
                                    Some(actual)
                                        if actual.to_ascii_lowercase() == *expected_value => {}
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
                    // Here we just validate that if max_concurrent is set, we would
                    // log/trace the policy applicability. The actual task count check
                    // happens in vellaveto-mcp/src/task_state.rs.
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
                            // SECURITY (FIND-048): Fail-closed when allowed_resources
                            // is configured but no resource indicator is present.
                            // The presence of allowed_resources implies the admin
                            // intends to restrict by resource. Without this guard,
                            // omitting identity bypasses the allowlist.
                            if *require_resource || !allowed_resources.is_empty() {
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
                    // SECURITY (FIND-045): Fail-closed when identity is missing but
                    // capabilities are configured. Matches the guard in AgentId and
                    // AgentIdentityMatch. Without this, omitting the identity header
                    // bypasses blocked_capabilities checks entirely.
                    if context.agent_identity.is_none()
                        && (!required_capabilities.is_empty() || !blocked_capabilities.is_empty())
                    {
                        return Some(Verdict::Deny {
                            reason: format!(
                                "{} (no agent identity for capability check)",
                                deny_reason
                            ),
                        });
                    }

                    // CIMD: Capability-Indexed Message Dispatch
                    // Capabilities are stored in agent_identity claims as a comma-separated
                    // string or as a JSON array under the "capabilities" claim.
                    // SECURITY (FIND-043): Lowercase declared caps to match the
                    // compile-time normalization of required/blocked lists.
                    let declared_caps: Vec<String> = context
                        .agent_identity
                        .as_ref()
                        .and_then(|id| {
                            // Try array first, then comma-separated string
                            id.claim_str_array("capabilities")
                                .map(|arr| {
                                    arr.into_iter().map(|s| s.to_ascii_lowercase()).collect()
                                })
                                .or_else(|| {
                                    id.claim_str("capabilities").map(|s| {
                                        s.split(',')
                                            .map(|p| p.trim().to_ascii_lowercase())
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
                                    "{} (blocked capability '{}' is declared)",
                                    deny_reason, blocked
                                ),
                            });
                        }
                    }

                    // Check required capabilities
                    for required in required_capabilities {
                        if !declared_caps.iter().any(|c| c == required) {
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
                    // in vellaveto-engine/src/circuit_breaker.rs. This condition is evaluated here
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
                    // in vellaveto-mcp/src/shadow_agent.rs. This condition is evaluated here
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
                    // in vellaveto-mcp/src/schema_poisoning.rs. This condition is evaluated here
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
                                    "{} (no verification tier in context — fail-closed)",
                                    deny_reason
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
                    match &context.capability_token {
                        Some(token) => {
                            // Check holder matches agent_id (prevents token theft)
                            if let Some(ref agent_id) = context.agent_id {
                                if !token.holder.eq_ignore_ascii_case(agent_id) {
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{} (token holder '{}' does not match agent_id '{}')",
                                            deny_reason, token.holder, agent_id
                                        ),
                                    });
                                }
                            }

                            // Check issuer allowlist
                            if !required_issuers.is_empty() {
                                let issuer_lower = token.issuer.to_ascii_lowercase();
                                if !required_issuers.contains(&issuer_lower) {
                                    return Some(Verdict::Deny {
                                        reason: format!(
                                            "{} (issuer '{}' not in allowed list)",
                                            deny_reason, token.issuer
                                        ),
                                    });
                                }
                            }

                            // Check remaining delegation depth
                            if token.remaining_depth < *min_remaining_depth {
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{} (remaining depth {} below required {})",
                                        deny_reason, token.remaining_depth, min_remaining_depth
                                    ),
                                });
                            }
                        }
                        None => {
                            // Fail-closed: no capability token in context
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{} (no capability token in context — fail-closed)",
                                    deny_reason
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
                            let state_lower = state.to_ascii_lowercase();
                            if !allowed_states.contains(&state_lower) {
                                return Some(Verdict::Deny {
                                    reason: format!(
                                        "{} (session state '{}' not in allowed states: {:?})",
                                        deny_reason, state, allowed_states
                                    ),
                                });
                            }
                        }
                        None => {
                            // Fail-closed: no session state in context
                            return Some(Verdict::Deny {
                                reason: format!(
                                    "{} (no session state in context — fail-closed)",
                                    deny_reason
                                ),
                            });
                        }
                    }
                }
            }
        }
        None
    }
}
