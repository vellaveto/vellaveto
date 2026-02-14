//! Agent identity types — attested identity, call chain entries,
//! evaluation context, and context builder.

use crate::capability::CapabilityToken;
use crate::verification::VerificationTier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cryptographically attested agent identity from a signed JWT.
///
/// This type represents a validated identity extracted from the `X-Agent-Identity`
/// header. Unlike the simple `agent_id` string, this provides cryptographic
/// attestation of the agent's identity via JWT signature verification.
///
/// # Security (OWASP ASI07 - Agent Identity Attestation)
///
/// - All claims are extracted from a signature-verified JWT
/// - The proxy validates the JWT before populating this struct
/// - Policies can match on issuer, subject, and custom claims
/// - This provides stronger identity guarantees than the legacy `agent_id` field
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AgentIdentity {
    /// JWT issuer (`iss` claim). Identifies the identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// JWT subject (`sub` claim). Identifies the specific agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// JWT audience (`aud` claim). May be a single string or array.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    /// Additional custom claims from the JWT payload.
    /// Common claims: `role`, `team`, `environment`, `permissions`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub claims: HashMap<String, serde_json::Value>,
}

impl AgentIdentity {
    /// Returns true if this identity has any populated fields.
    pub fn is_populated(&self) -> bool {
        self.issuer.is_some()
            || self.subject.is_some()
            || !self.audience.is_empty()
            || !self.claims.is_empty()
    }

    /// Get a claim value as a string, if present and is a string.
    pub fn claim_str(&self, key: &str) -> Option<&str> {
        self.claims.get(key).and_then(|v| v.as_str())
    }

    /// Get a claim value as an array of strings, if present and is an array.
    pub fn claim_str_array(&self, key: &str) -> Option<Vec<&str>> {
        self.claims.get(key).and_then(|v| {
            v.as_array()
                .map(|arr| arr.iter().filter_map(|item| item.as_str()).collect())
        })
    }
}

/// An entry in a multi-agent call chain, tracking the path of a request
/// through multiple agents in a multi-hop MCP scenario.
///
/// OWASP ASI08: Multi-agent communication monitoring requires tracking
/// the full chain of tool calls to detect privilege escalation patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallChainEntry {
    /// The agent that made this call (from X-Upstream-Agent header or OAuth subject).
    pub agent_id: String,
    /// The tool being called.
    pub tool: String,
    /// The function being called.
    pub function: String,
    /// ISO 8601 timestamp when the call was made.
    pub timestamp: String,
    /// HMAC-SHA256 signature over the entry content (FIND-015).
    /// Present when the entry was signed by a Vellaveto instance with a configured HMAC key.
    /// Hex-encoded. Omitted from serialization when `None` for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
    /// Whether the HMAC on this entry has been verified (FIND-015).
    /// `None` = not checked (no key configured or entry has no HMAC).
    /// `Some(true)` = HMAC verified successfully.
    /// `Some(false)` = HMAC verification failed (entry marked as unverified).
    /// Excluded from serialization — this is local verification state only.
    #[serde(skip)]
    pub verified: Option<bool>,
}

/// Session-level context for policy evaluation.
///
/// Separate from [`Action`] because Action = "what to do" (from the agent),
/// while Context = "session state" (from the proxy). This security boundary
/// ensures agents don't control context fields like call counts or timestamps.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvaluationContext {
    /// ISO 8601 timestamp for the evaluation. When `None`, the engine uses
    /// the current wall-clock time. Providing an explicit timestamp enables
    /// deterministic testing of time-window policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Identity of the agent making the request (e.g., OAuth subject, API key hash).
    /// This is the legacy identity field — prefer `agent_identity` for stronger guarantees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Cryptographically attested agent identity from a signed JWT (OWASP ASI07).
    ///
    /// When present, this provides stronger identity guarantees than `agent_id`.
    /// Populated from the `X-Agent-Identity` header after JWT signature verification.
    /// Policies can use `agent_identity` context conditions to match on claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentity>,
    /// Per-tool call counts for the current session (tool_name → count).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub call_counts: HashMap<String, u64>,
    /// History of tool names called in this session (most recent last).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_actions: Vec<String>,
    /// OWASP ASI08: Call chain for multi-agent communication monitoring.
    /// Records the path of the current request through multiple agents.
    /// The first entry is the originating agent, subsequent entries are
    /// intermediary agents in multi-hop scenarios.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_chain: Vec<CallChainEntry>,
    /// Tenant identifier for multi-tenancy support.
    /// When set, policies are scoped to this tenant. Extracted from:
    /// 1. JWT claims (`tenant_id` or `org_id`)
    /// 2. Request header (`X-Tenant-ID`)
    /// 3. Subdomain (`{tenant}.vellaveto.example.com`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Verification tier of the agent making the request.
    /// Used by `min_verification_tier` context condition.
    /// When `None`, policies requiring a minimum tier will deny (fail-closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_tier: Option<VerificationTier>,
    /// Capability delegation token for the agent.
    /// Used by `require_capability_token` context condition.
    /// When `None`, policies requiring a capability token will deny (fail-closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,
    /// Current session state from the SessionGuard state machine (Phase 23.5).
    /// Used by `session_state_required` context condition.
    /// When `None`, policies requiring a session state will deny (fail-closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_state: Option<String>,
}

impl EvaluationContext {
    /// Returns true if any context field is populated with meaningful data.
    /// Used by the engine to decide whether falling back to the legacy path
    /// (which cannot evaluate context conditions) is safe.
    // SECURITY (R16-TYPES-2): Include timestamp so time-window policies
    // fail-closed when compiled policies are unavailable, rather than
    // silently falling back to the legacy path that ignores time constraints.
    pub fn has_any_meaningful_fields(&self) -> bool {
        self.timestamp.is_some()
            || self.agent_id.is_some()
            || self
                .agent_identity
                .as_ref()
                .is_some_and(|id| id.is_populated())
            || !self.call_counts.is_empty()
            || !self.previous_actions.is_empty()
            || !self.call_chain.is_empty()
            || self.tenant_id.is_some()
            || self.verification_tier.is_some()
            || self.capability_token.is_some()
            || self.session_state.is_some()
    }

    /// Returns the depth of the current call chain (number of agents in the chain).
    /// A depth of 0 means no multi-hop scenario (direct call).
    /// A depth of 1 means there is one upstream agent.
    pub fn call_chain_depth(&self) -> usize {
        self.call_chain.len()
    }

    /// Returns the originating agent ID if this is a multi-hop request.
    /// This is the first agent in the call chain (the one that initiated the request).
    pub fn originating_agent(&self) -> Option<&str> {
        self.call_chain.first().map(|e| e.agent_id.as_str())
    }

    /// Create a new builder for constructing an `EvaluationContext`.
    ///
    /// # Example
    ///
    /// ```
    /// use vellaveto_types::EvaluationContext;
    ///
    /// let ctx = EvaluationContext::builder()
    ///     .agent_id("agent-123")
    ///     .tenant_id("tenant-abc")
    ///     .build();
    /// ```
    pub fn builder() -> EvaluationContextBuilder {
        EvaluationContextBuilder::default()
    }
}

/// Builder for constructing [`EvaluationContext`] instances.
///
/// Provides a fluent API for setting context fields, with sensible defaults
/// for fields that aren't explicitly set.
#[derive(Debug, Default)]
pub struct EvaluationContextBuilder {
    timestamp: Option<String>,
    agent_id: Option<String>,
    agent_identity: Option<AgentIdentity>,
    call_counts: HashMap<String, u64>,
    previous_actions: Vec<String>,
    call_chain: Vec<CallChainEntry>,
    tenant_id: Option<String>,
    verification_tier: Option<VerificationTier>,
    capability_token: Option<CapabilityToken>,
    session_state: Option<String>,
}

impl EvaluationContextBuilder {
    /// Set the evaluation timestamp (ISO 8601 format).
    pub fn timestamp(mut self, timestamp: impl Into<String>) -> Self {
        self.timestamp = Some(timestamp.into());
        self
    }

    /// Set the agent ID (legacy identity field).
    pub fn agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Set the cryptographically attested agent identity.
    pub fn agent_identity(mut self, identity: AgentIdentity) -> Self {
        self.agent_identity = Some(identity);
        self
    }

    /// Set the per-tool call counts for the session.
    pub fn call_counts(mut self, counts: HashMap<String, u64>) -> Self {
        self.call_counts = counts;
        self
    }

    /// Add a single tool call count.
    pub fn call_count(mut self, tool: impl Into<String>, count: u64) -> Self {
        self.call_counts.insert(tool.into(), count);
        self
    }

    /// Set the history of previous tool calls.
    pub fn previous_actions(mut self, actions: Vec<String>) -> Self {
        self.previous_actions = actions;
        self
    }

    /// Add a single previous action to the history.
    pub fn previous_action(mut self, action: impl Into<String>) -> Self {
        self.previous_actions.push(action.into());
        self
    }

    /// Set the call chain for multi-agent scenarios.
    pub fn call_chain(mut self, chain: Vec<CallChainEntry>) -> Self {
        self.call_chain = chain;
        self
    }

    /// Add a single entry to the call chain.
    pub fn call_chain_entry(mut self, entry: CallChainEntry) -> Self {
        self.call_chain.push(entry);
        self
    }

    /// Set the tenant ID for multi-tenancy.
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set the verification tier for identity verification policies.
    pub fn verification_tier(mut self, tier: VerificationTier) -> Self {
        self.verification_tier = Some(tier);
        self
    }

    /// Set the capability delegation token for capability-based access control.
    pub fn capability_token(mut self, token: CapabilityToken) -> Self {
        self.capability_token = Some(token);
        self
    }

    /// Set the session state from the SessionGuard state machine.
    pub fn session_state(mut self, state: impl Into<String>) -> Self {
        self.session_state = Some(state.into());
        self
    }

    /// Build the [`EvaluationContext`].
    pub fn build(self) -> EvaluationContext {
        EvaluationContext {
            timestamp: self.timestamp,
            agent_id: self.agent_id,
            agent_identity: self.agent_identity,
            call_counts: self.call_counts,
            previous_actions: self.previous_actions,
            call_chain: self.call_chain,
            tenant_id: self.tenant_id,
            verification_tier: self.verification_tier,
            capability_token: self.capability_token,
            session_state: self.session_state,
        }
    }
}
