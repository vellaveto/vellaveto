//! Pre-compiled policy types.
//!
//! This module contains the pre-compiled policy types that are created at policy
//! load time. Pre-compilation allows policy evaluation to be performed without
//! any runtime pattern compilation or lock contention.

use crate::matcher::{CompiledToolMatcher, PatternMatcher};
use globset::GlobMatcher;
use ipnet::IpNet;
use regex::Regex;
use sentinel_types::Policy;
use std::collections::HashMap;

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
    pub(crate) fn param(&self) -> &str {
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

    pub(crate) fn on_match(&self) -> &str {
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

    pub(crate) fn on_missing(&self) -> &str {
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

/// Pre-compiled IP access control rules for DNS rebinding protection.
///
/// CIDRs are parsed at policy compile time so evaluation is a fast
/// prefix-length comparison with no parsing overhead.
#[derive(Debug, Clone)]
pub struct CompiledIpRules {
    pub block_private: bool,
    pub blocked_cidrs: Vec<IpNet>,
    pub allowed_cidrs: Vec<IpNet>,
}

/// A pre-compiled context condition for session-level policy evaluation.
///
/// Context conditions are checked after tool match and path/network rules,
/// but before policy type dispatch. They require an [`EvaluationContext`]
/// to evaluate — when no context is provided, all context conditions are skipped.
#[derive(Debug, Clone)]
pub enum CompiledContextCondition {
    /// Allow tool calls only within a time window.
    TimeWindow {
        start_hour: u8,
        end_hour: u8,
        /// ISO weekday numbers (1=Mon, 7=Sun). Empty = all days.
        days: Vec<u8>,
        deny_reason: String,
    },
    /// Limit how many times a tool (or tool pattern) can be called per session.
    MaxCalls {
        tool_pattern: PatternMatcher,
        max: u64,
        deny_reason: String,
    },
    /// Restrict which agent identities can use this policy.
    AgentId {
        allowed: Vec<String>,
        blocked: Vec<String>,
        deny_reason: String,
    },
    /// Require that a specific tool was called earlier in the session.
    RequirePreviousAction {
        required_tool: String,
        deny_reason: String,
    },
    /// Deny if a specific tool was called earlier in the session.
    ///
    /// Inverse of `RequirePreviousAction` — detects forbidden sequences like
    /// read-then-exfiltrate (if `read_file` was called, deny `http_request`).
    ForbiddenPreviousAction {
        /// Tool name that, if present in session history, triggers denial.
        forbidden_tool: String,
        deny_reason: String,
    },
    /// Deny if a tool pattern appears more than `max` times in the last `window`
    /// entries of the session history.
    ///
    /// Provides sliding-window rate limiting without requiring wall-clock
    /// timestamps. A `window` of 0 means the entire session history.
    MaxCallsInWindow {
        tool_pattern: PatternMatcher,
        max: u64,
        /// Number of most-recent history entries to consider. 0 = all.
        window: usize,
        deny_reason: String,
    },
    /// OWASP ASI08: Limit the depth of multi-agent call chains.
    ///
    /// In multi-hop MCP scenarios, an agent can request another agent to perform
    /// actions on its behalf. This condition limits how deep such chains can go
    /// to prevent privilege escalation through agent chaining.
    MaxChainDepth {
        /// Maximum allowed chain depth. A value of 0 means no multi-hop is allowed
        /// (direct calls only). A value of 1 allows one upstream agent, etc.
        max_depth: usize,
        deny_reason: String,
    },
    /// OWASP ASI07: Match on cryptographically attested agent identity claims.
    ///
    /// Requires a valid `X-Agent-Identity` JWT header. Policies can match on:
    /// - `issuer`: Required JWT issuer (`iss` claim)
    /// - `subject`: Required JWT subject (`sub` claim)
    /// - `audience`: Required audience (`aud` claim must contain this value)
    /// - `claims.<key>`: Custom claim matching (e.g., `claims.role == "admin"`)
    ///
    /// Unlike `AgentId` which matches on a simple string, this condition provides
    /// cryptographic attestation of the agent's identity via JWT signature verification.
    AgentIdentityMatch {
        /// Required JWT issuer. If set, the identity's `iss` claim must match.
        required_issuer: Option<String>,
        /// Required JWT subject. If set, the identity's `sub` claim must match.
        required_subject: Option<String>,
        /// Required audience. If set, the identity's `aud` claim must contain this value.
        required_audience: Option<String>,
        /// Required custom claims. All specified claims must match.
        /// Keys are claim names, values are expected string values.
        required_claims: HashMap<String, String>,
        /// Blocked issuers. If the identity's `iss` matches any, deny.
        blocked_issuers: Vec<String>,
        /// Blocked subjects. If the identity's `sub` matches any, deny.
        blocked_subjects: Vec<String>,
        /// When true, fail-closed if no agent_identity is present.
        /// When false, fall back to legacy agent_id matching.
        require_attestation: bool,
        deny_reason: String,
    },

    // ═══════════════════════════════════════════════════
    // MCP 2025-11-25 CONTEXT CONDITIONS
    // ═══════════════════════════════════════════════════
    /// MCP 2025-11-25: Async task lifecycle policy.
    ///
    /// Controls the creation and cancellation of async MCP tasks. Policies can:
    /// - Limit maximum concurrent tasks per session/agent
    /// - Set maximum task duration before automatic expiry
    /// - Restrict task cancellation to the creating agent only
    AsyncTaskPolicy {
        /// Maximum number of concurrent active tasks. 0 = unlimited.
        max_concurrent: usize,
        /// Maximum task duration in seconds. 0 = unlimited.
        max_duration_secs: u64,
        /// When true, only the agent that created a task can cancel it.
        require_self_cancel: bool,
        deny_reason: String,
    },

    /// RFC 8707: OAuth 2.0 Resource Indicator validation.
    ///
    /// Validates that OAuth tokens include the expected resource indicators.
    /// Resource indicators prevent token replay attacks by binding tokens
    /// to specific API endpoints or resource servers.
    ResourceIndicator {
        /// Patterns for allowed resource URIs. Supports glob patterns.
        /// If non-empty, at least one pattern must match the token's resource.
        allowed_resources: Vec<PatternMatcher>,
        /// When true, deny if the token has no resource indicator.
        require_resource: bool,
        deny_reason: String,
    },

    /// CIMD: Capability-Indexed Message Dispatch.
    ///
    /// MCP 2025-11-25 introduces capability negotiation. This condition
    /// checks that the client has declared the required capabilities
    /// and has not declared any blocked capabilities.
    CapabilityRequired {
        /// Capabilities that must be declared by the client.
        /// All listed capabilities must be present.
        required_capabilities: Vec<String>,
        /// Capabilities that must NOT be declared by the client.
        /// If any listed capability is present, deny.
        blocked_capabilities: Vec<String>,
        deny_reason: String,
    },

    /// Step-up authentication trigger.
    ///
    /// When the current authentication level is below the required level,
    /// the policy triggers a step-up authentication challenge instead of
    /// denying outright. This allows sensitive operations to require
    /// stronger authentication without blocking the session.
    StepUpAuth {
        /// Required authentication level (maps to AuthLevel enum).
        /// 0=None, 1=Basic, 2=OAuth, 3=OAuthMfa, 4=HardwareKey
        required_level: u8,
        deny_reason: String,
    },

    // ═══════════════════════════════════════════════════
    // PHASE 2: ADVANCED THREAT DETECTION CONDITIONS
    // ═══════════════════════════════════════════════════
    /// Circuit breaker check (OWASP ASI08).
    ///
    /// Prevents cascading failures by temporarily blocking requests to
    /// tools that have been failing. The circuit breaker pattern has
    /// three states: Closed (normal), Open (blocking), HalfOpen (testing).
    CircuitBreaker {
        /// Pattern to match tool names for circuit breaker tracking.
        tool_pattern: PatternMatcher,
        deny_reason: String,
    },

    /// Confused deputy validation (OWASP ASI02).
    ///
    /// Validates that the current principal is authorized to perform
    /// the requested action, preventing confused deputy attacks where
    /// a privileged agent is tricked into acting on behalf of an
    /// unprivileged attacker.
    DeputyValidation {
        /// When true, a principal must be identified in the context.
        require_principal: bool,
        /// Maximum allowed delegation depth. 0 = direct only.
        max_delegation_depth: u8,
        deny_reason: String,
    },

    /// Shadow agent detection.
    ///
    /// Detects when an unknown agent claims to be a known agent,
    /// indicating potential impersonation or shadow agent attack.
    /// Fingerprints agents based on JWT claims, client ID, and IP.
    ShadowAgentCheck {
        /// When true, require the fingerprint to match a known agent.
        require_known_fingerprint: bool,
        /// Minimum trust level required (0-4).
        /// 0=Unknown, 1=Low, 2=Medium, 3=High, 4=Verified
        min_trust_level: u8,
        deny_reason: String,
    },

    /// Schema poisoning protection (OWASP ASI05).
    ///
    /// Tracks tool schema changes over time and alerts or blocks
    /// when schemas change beyond the configured threshold.
    /// Prevents rug-pull attacks where tool behavior changes maliciously.
    SchemaPoisoningCheck {
        /// Schema similarity threshold (0.0-1.0). Changes above this trigger denial.
        mutation_threshold: f32,
        deny_reason: String,
    },
}

/// Pre-parsed fields extracted from a policy's `conditions` JSON.
///
/// Returned by [`PolicyEngine::compile_conditions`] to avoid a complex tuple return type.
#[derive(Debug, Clone)]
pub(crate) struct CompiledConditions {
    pub require_approval: bool,
    pub forbidden_parameters: Vec<String>,
    pub required_parameters: Vec<String>,
    pub constraints: Vec<CompiledConstraint>,
    pub on_no_match_continue: bool,
    pub context_conditions: Vec<CompiledContextCondition>,
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
    /// Pre-compiled IP access control rules (DNS rebinding protection).
    pub compiled_ip_rules: Option<CompiledIpRules>,
    /// Pre-compiled context conditions (from conditions JSON `context_conditions` key).
    pub context_conditions: Vec<CompiledContextCondition>,
}
