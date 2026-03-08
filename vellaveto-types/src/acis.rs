// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Agent-Consumer Interaction Surface (ACIS) decision envelope.
//!
//! Every side-effecting runtime decision — policy evaluation, approval gate,
//! DLP finding, injection block — emits one [`AcisDecisionEnvelope`].  This is
//! the normalized contract shared by every enforcement path (stdio, HTTP,
//! WebSocket, gRPC, shield) and consumed by audit, metrics, and external
//! integrations.
//!
//! # Design constraints
//!
//! - **Fail-closed defaults:** [`DecisionKind::Deny`] is the default.
//! - **No secrets in fingerprints:** `action_fingerprint` hashes tool, function,
//!   and targets — never parameters.
//! - **Transport-agnostic:** Serializable via JSON across all surfaces.
//! - **Bounded fields:** All strings and collections are length-validated.

use serde::{Deserialize, Serialize};

use crate::core::Verdict;
use crate::has_dangerous_chars;
use crate::identity::AgentIdentity;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum length of `decision_id` (UUID = 36 chars, but allow up to 64 for
/// future extensibility).
const MAX_DECISION_ID_LEN: usize = 64;

/// Maximum length of `session_id`.
const MAX_SESSION_ID_LEN: usize = 512;

/// Maximum length of `action_fingerprint` (SHA-256 hex = 64 chars).
const MAX_FINGERPRINT_LEN: usize = 128;

/// Maximum length of `matched_policy_id`.
const MAX_POLICY_ID_LEN: usize = 256;

/// Maximum length of `reason` string.
const MAX_REASON_LEN: usize = 4096;

/// Maximum length of `tenant_id`.
const MAX_TENANT_ID_LEN: usize = 256;

/// Maximum length of `transport` label.
const MAX_TRANSPORT_LEN: usize = 32;

/// Maximum number of finding summaries per envelope.
const MAX_FINDINGS: usize = 64;

/// Maximum length of a single finding summary string.
const MAX_FINDING_LEN: usize = 512;

// ── Core types ───────────────────────────────────────────────────────────────

/// The normalized decision kind — a simplified projection of [`Verdict`] for
/// indexing, filtering, and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// Action was permitted.
    Allow,
    /// Action was blocked.
    Deny,
    /// Action requires human/approval-flow consent before proceeding.
    RequireApproval,
}

impl Default for DecisionKind {
    /// Fail-closed: default is Deny.
    fn default() -> Self {
        Self::Deny
    }
}

impl From<&Verdict> for DecisionKind {
    fn from(v: &Verdict) -> Self {
        match v {
            Verdict::Allow => Self::Allow,
            Verdict::Deny { .. } => Self::Deny,
            Verdict::RequireApproval { .. } => Self::RequireApproval,
        }
    }
}

/// The origin of the decision — which enforcement layer produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOrigin {
    /// Policy engine evaluation.
    PolicyEngine,
    /// DLP parameter or response scanning.
    Dlp,
    /// Injection detection (prompt injection, tool squatting, etc.).
    InjectionScanner,
    /// Memory poisoning detection (MINJA).
    MemoryPoisoning,
    /// Approval gate (RequireApproval verdict or approval timeout).
    ApprovalGate,
    /// Capability token enforcement.
    CapabilityEnforcement,
    /// Rate limiter or circuit breaker.
    RateLimiter,
    /// TopologyGuard (unknown tool denial).
    TopologyGuard,
    /// Session guard state violation.
    SessionGuard,
}

/// Summary of the action that triggered the decision.
///
/// Deliberately excludes `parameters` (may contain secrets) and full target
/// lists (may be large).  The `action_fingerprint` is the canonical identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcisActionSummary {
    /// Tool name (e.g. `"file_write"`).
    pub tool: String,
    /// Function name (e.g. `"write"`).
    pub function: String,
    /// Number of target paths.
    pub target_path_count: u32,
    /// Number of target domains.
    pub target_domain_count: u32,
}

/// The ACIS decision envelope — one per runtime decision.
///
/// Emitted by every enforcement path and consumed by audit logging, metrics,
/// external webhooks, and the admin console.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcisDecisionEnvelope {
    // ── Identity ─────────────────────────────────────────────────────────
    /// Unique decision identifier (UUID v4 hex string).
    pub decision_id: String,

    /// ISO 8601 timestamp of the decision (must end with `Z` or `+00:00`).
    pub timestamp: String,

    // ── Session & principal ──────────────────────────────────────────────
    /// Session identifier (from `Mcp-Session-Id` header or stateless blob).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Tenant identifier for multi-tenant deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Cryptographically attested agent identity (from JWT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentity>,

    /// Legacy agent identifier (when full `AgentIdentity` is unavailable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    // ── Action ───────────────────────────────────────────────────────────
    /// Summary of the action (tool, function, target counts).
    pub action_summary: AcisActionSummary,

    /// SHA-256 hex of `tool || function || sorted(target_paths) ||
    /// sorted(target_domains)`.  Never includes parameters.
    pub action_fingerprint: String,

    // ── Decision ─────────────────────────────────────────────────────────
    /// Simplified decision kind for indexing and metrics.
    pub decision: DecisionKind,

    /// Which enforcement layer produced this decision.
    pub origin: DecisionOrigin,

    /// Human-readable reason (from Deny/RequireApproval verdict, or scanner
    /// finding summary).  Empty for Allow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,

    /// Policy ID that matched (if decision originated from policy engine).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_policy_id: Option<String>,

    // ── Transport ────────────────────────────────────────────────────────
    /// Transport surface that intercepted the action (`"stdio"`, `"http"`,
    /// `"websocket"`, `"grpc"`, `"sse"`).
    pub transport: String,

    // ── Security findings ────────────────────────────────────────────────
    /// Brief finding summaries (e.g. `"DLP: API key detected"`,
    /// `"injection: prompt override pattern"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,

    // ── Timing ───────────────────────────────────────────────────────────
    /// Wall-clock evaluation latency in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_us: Option<u64>,

    // ── Depth ────────────────────────────────────────────────────────────
    /// Number of entries in the current call chain (multi-agent depth).
    #[serde(default)]
    pub call_chain_depth: u32,
}

// ── Validation ───────────────────────────────────────────────────────────────

impl AcisDecisionEnvelope {
    /// Validate all fields for length, content, and structural invariants.
    pub fn validate(&self) -> Result<(), String> {
        // decision_id
        if self.decision_id.is_empty() {
            return Err("acis: decision_id must not be empty".into());
        }
        if self.decision_id.len() > MAX_DECISION_ID_LEN {
            return Err("acis: decision_id exceeds maximum length".into());
        }
        if has_dangerous_chars(&self.decision_id) {
            return Err("acis: decision_id contains dangerous characters".into());
        }

        // timestamp
        if self.timestamp.is_empty() {
            return Err("acis: timestamp must not be empty".into());
        }
        if !self.timestamp.ends_with('Z')
            && !self.timestamp.ends_with('z')
            && !self.timestamp.ends_with("+00:00")
        {
            return Err("acis: timestamp must be UTC (end with Z or +00:00)".into());
        }

        // session_id
        if let Some(ref sid) = self.session_id {
            if sid.len() > MAX_SESSION_ID_LEN {
                return Err("acis: session_id exceeds maximum length".into());
            }
            if has_dangerous_chars(sid) {
                return Err("acis: session_id contains dangerous characters".into());
            }
        }

        // tenant_id
        if let Some(ref tid) = self.tenant_id {
            if tid.len() > MAX_TENANT_ID_LEN {
                return Err("acis: tenant_id exceeds maximum length".into());
            }
            if has_dangerous_chars(tid) {
                return Err("acis: tenant_id contains dangerous characters".into());
            }
        }

        // action_fingerprint
        if self.action_fingerprint.is_empty() {
            return Err("acis: action_fingerprint must not be empty".into());
        }
        if self.action_fingerprint.len() > MAX_FINGERPRINT_LEN {
            return Err("acis: action_fingerprint exceeds maximum length".into());
        }

        // action_summary
        if self.action_summary.tool.is_empty() {
            return Err("acis: action_summary.tool must not be empty".into());
        }
        if has_dangerous_chars(&self.action_summary.tool) {
            return Err("acis: action_summary.tool contains dangerous characters".into());
        }
        if has_dangerous_chars(&self.action_summary.function) {
            return Err("acis: action_summary.function contains dangerous characters".into());
        }

        // reason
        if self.reason.len() > MAX_REASON_LEN {
            return Err("acis: reason exceeds maximum length".into());
        }

        // matched_policy_id
        if let Some(ref pid) = self.matched_policy_id {
            if pid.len() > MAX_POLICY_ID_LEN {
                return Err("acis: matched_policy_id exceeds maximum length".into());
            }
            if has_dangerous_chars(pid) {
                return Err("acis: matched_policy_id contains dangerous characters".into());
            }
        }

        // transport
        if self.transport.is_empty() {
            return Err("acis: transport must not be empty".into());
        }
        if self.transport.len() > MAX_TRANSPORT_LEN {
            return Err("acis: transport exceeds maximum length".into());
        }
        if has_dangerous_chars(&self.transport) {
            return Err("acis: transport contains dangerous characters".into());
        }

        // findings
        if self.findings.len() > MAX_FINDINGS {
            return Err("acis: findings exceeds maximum count".into());
        }
        for (i, f) in self.findings.iter().enumerate() {
            if f.len() > MAX_FINDING_LEN {
                return Err(format!("acis: findings[{i}] exceeds maximum length"));
            }
        }

        Ok(())
    }
}

// ── Fingerprint ──────────────────────────────────────────────────────────────

// `compute_action_fingerprint()` (SHA-256) lives in `vellaveto-engine` to avoid
// pulling sha2+hex into this leaf crate.  See `vellaveto_engine::acis`.

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_envelope() -> AcisDecisionEnvelope {
        AcisDecisionEnvelope {
            decision_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            timestamp: "2026-03-09T10:00:00Z".into(),
            session_id: None,
            tenant_id: None,
            agent_identity: None,
            agent_id: None,
            action_summary: AcisActionSummary {
                tool: "file_write".into(),
                function: "write".into(),
                target_path_count: 1,
                target_domain_count: 0,
            },
            // Fingerprint is computed by vellaveto-engine; use a placeholder here.
            action_fingerprint: "a1b2c3d4e5f6".into(),
            decision: DecisionKind::Allow,
            origin: DecisionOrigin::PolicyEngine,
            reason: String::new(),
            matched_policy_id: Some("policy-001".into()),
            transport: "stdio".into(),
            findings: vec![],
            evaluation_us: Some(42),
            call_chain_depth: 0,
        }
    }

    #[test]
    fn test_minimal_envelope_validates() {
        let env = minimal_envelope();
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_decision_kind_default_is_deny() {
        assert_eq!(DecisionKind::default(), DecisionKind::Deny);
    }

    #[test]
    fn test_decision_kind_from_verdict() {
        assert_eq!(DecisionKind::from(&Verdict::Allow), DecisionKind::Allow);
        assert_eq!(
            DecisionKind::from(&Verdict::Deny { reason: "x".into() }),
            DecisionKind::Deny
        );
        assert_eq!(
            DecisionKind::from(&Verdict::RequireApproval { reason: "x".into() }),
            DecisionKind::RequireApproval
        );
    }

    #[test]
    fn test_empty_decision_id_rejected() {
        let mut env = minimal_envelope();
        env.decision_id = String::new();
        let err = env.validate().unwrap_err();
        assert!(err.contains("decision_id must not be empty"));
    }

    #[test]
    fn test_non_utc_timestamp_rejected() {
        let mut env = minimal_envelope();
        env.timestamp = "2026-03-09T10:00:00+01:00".into();
        let err = env.validate().unwrap_err();
        assert!(err.contains("timestamp must be UTC"));
    }

    #[test]
    fn test_dangerous_chars_in_session_id_rejected() {
        let mut env = minimal_envelope();
        env.session_id = Some("sess\x00ion".into());
        let err = env.validate().unwrap_err();
        assert!(err.contains("session_id contains dangerous"));
    }

    #[test]
    fn test_empty_transport_rejected() {
        let mut env = minimal_envelope();
        env.transport = String::new();
        let err = env.validate().unwrap_err();
        assert!(err.contains("transport must not be empty"));
    }

    #[test]
    fn test_too_many_findings_rejected() {
        let mut env = minimal_envelope();
        env.findings = vec!["f".into(); 65];
        let err = env.validate().unwrap_err();
        assert!(err.contains("findings exceeds maximum count"));
    }

    #[test]
    fn test_empty_fingerprint_rejected() {
        let mut env = minimal_envelope();
        env.action_fingerprint = String::new();
        let err = env.validate().unwrap_err();
        assert!(err.contains("action_fingerprint must not be empty"));
    }

    #[test]
    fn test_oversized_fingerprint_rejected() {
        let mut env = minimal_envelope();
        env.action_fingerprint = "x".repeat(129);
        let err = env.validate().unwrap_err();
        assert!(err.contains("action_fingerprint exceeds maximum length"));
    }

    #[test]
    fn test_envelope_serialization_roundtrip() {
        let env = minimal_envelope();
        let json = serde_json::to_string(&env).expect("serialize");
        let decoded: AcisDecisionEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.decision_id, env.decision_id);
        assert_eq!(decoded.action_fingerprint, env.action_fingerprint);
        assert_eq!(decoded.decision, env.decision);
    }

    #[test]
    fn test_deny_unknown_fields_rejects_extra() {
        let json = r#"{
            "decision_id": "abc",
            "timestamp": "2026-03-09T00:00:00Z",
            "action_summary": {"tool":"t","function":"f","target_path_count":0,"target_domain_count":0},
            "action_fingerprint": "abc123",
            "decision": "allow",
            "origin": "policy_engine",
            "transport": "http",
            "call_chain_depth": 0,
            "evil_field": true
        }"#;
        assert!(serde_json::from_str::<AcisDecisionEnvelope>(json).is_err());
    }

    #[test]
    fn test_dangerous_chars_in_tenant_id_rejected() {
        let mut env = minimal_envelope();
        env.tenant_id = Some("tenant\x07id".into());
        let err = env.validate().unwrap_err();
        assert!(err.contains("tenant_id contains dangerous"));
    }

    #[test]
    fn test_oversized_reason_rejected() {
        let mut env = minimal_envelope();
        env.reason = "x".repeat(4097);
        let err = env.validate().unwrap_err();
        assert!(err.contains("reason exceeds maximum length"));
    }

    #[test]
    fn test_finding_too_long_rejected() {
        let mut env = minimal_envelope();
        env.findings = vec!["x".repeat(513)];
        let err = env.validate().unwrap_err();
        assert!(err.contains("findings[0] exceeds maximum length"));
    }

    #[test]
    fn test_utc_plus_zero_timestamp_accepted() {
        let mut env = minimal_envelope();
        env.timestamp = "2026-03-09T10:00:00+00:00".into();
        assert!(env.validate().is_ok());
    }
}
