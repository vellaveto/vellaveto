//! Agent identity types — attested identity, call chain entries,
//! evaluation context, and context builder.

use crate::capability::CapabilityToken;
use crate::verification::VerificationTier;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

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
#[serde(deny_unknown_fields)]
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

    /// Maximum number of claims to prevent memory abuse.
    pub const MAX_CLAIMS: usize = 64;

    /// Maximum number of audience entries to prevent memory abuse.
    pub const MAX_AUDIENCE: usize = 64;

    /// Maximum byte length of a single claim key.
    ///
    /// SECURITY (FIND-R111-002): Prevents memory exhaustion from attacker-controlled
    /// claim keys supplied in JWTs.
    pub const MAX_CLAIM_KEY_LEN: usize = 256;

    /// Maximum byte length of a serialized claim value.
    ///
    /// SECURITY (FIND-R111-002): Prevents memory exhaustion from attacker-controlled
    /// claim values supplied in JWTs. Measured on the JSON-serialized value to cover
    /// both string and structured values.
    pub const MAX_CLAIM_VALUE_LEN: usize = 4096;

    /// SECURITY (FIND-R49-006, FIND-R111-002): Validate AgentIdentity bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.claims.len() > Self::MAX_CLAIMS {
            return Err(format!(
                "AgentIdentity claims count {} exceeds max {}",
                self.claims.len(),
                Self::MAX_CLAIMS
            ));
        }
        if self.audience.len() > Self::MAX_AUDIENCE {
            return Err(format!(
                "AgentIdentity audience count {} exceeds max {}",
                self.audience.len(),
                Self::MAX_AUDIENCE
            ));
        }
        // SECURITY (FIND-R111-002): Per-key and per-value length bounds.
        for (key, value) in &self.claims {
            if key.len() > Self::MAX_CLAIM_KEY_LEN {
                return Err(format!(
                    "AgentIdentity claim key length {} exceeds max {} (key starts with: '{}')",
                    key.len(),
                    Self::MAX_CLAIM_KEY_LEN,
                    key.chars().take(32).collect::<String>()
                ));
            }
            // Reject control characters and Unicode format characters in claim keys.
            if key.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
                return Err(format!(
                    "AgentIdentity claim key contains control or Unicode format character: '{}'",
                    key.chars().take(32).collect::<String>()
                ));
            }
            // Measure the serialized value length to cover all JSON value types.
            let serialized_value = serde_json::to_string(value).map_err(|e| {
                format!("AgentIdentity claim value for key '{}' failed to serialize: {e}", key)
            })?;
            if serialized_value.len() > Self::MAX_CLAIM_VALUE_LEN {
                return Err(format!(
                    "AgentIdentity claim value for key '{}' length {} exceeds max {}",
                    key,
                    serialized_value.len(),
                    Self::MAX_CLAIM_VALUE_LEN
                ));
            }
        }
        Ok(())
    }
}

/// An entry in a multi-agent call chain, tracking the path of a request
/// through multiple agents in a multi-hop MCP scenario.
///
/// OWASP ASI08: Multi-agent communication monitoring requires tracking
/// the full chain of tool calls to detect privilege escalation patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

    /// Validate that string identity fields (session_state, agent_id, tenant_id)
    /// do not contain control characters and are not empty-but-present.
    ///
    /// SECURITY (FIND-R46-017): Prevents log injection and confusion attacks
    /// via control characters in identity fields. A present-but-empty identity
    /// field may bypass agent-matching logic that treats `None` as "no identity"
    /// but matches `Some("")` against wildcard patterns.
    /// Maximum number of entries in `call_counts` before validation fails.
    const MAX_CALL_COUNTS: usize = 10_000;
    /// Maximum number of entries in `previous_actions` before validation fails.
    const MAX_PREVIOUS_ACTIONS: usize = 10_000;
    /// Maximum number of entries in `call_chain` before validation fails.
    const MAX_CALL_CHAIN: usize = 100;
    /// SECURITY (FIND-R50-064): Maximum byte length per `previous_actions` entry.
    const MAX_ACTION_NAME_LEN: usize = 256;
    /// Maximum byte length for call_chain timestamp fields.
    /// SECURITY (FIND-R56-CORE-007): ISO 8601 timestamps with timezone are typically
    /// 25-35 bytes; 64 provides ample headroom while bounding memory.
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum byte length for call_chain entry fields (agent_id, tool, function).
    /// SECURITY (FIND-R56-CORE-008): Prevents memory abuse via oversized call chain fields.
    const MAX_CALL_CHAIN_FIELD_LEN: usize = 512;
    /// Maximum byte length for call_chain entry HMAC field.
    /// HMAC-SHA256 is exactly 64 hex chars; 128 provides headroom for future algorithms.
    const MAX_HMAC_LEN: usize = 128;

    pub fn validate(&self) -> Result<(), String> {
        Self::validate_optional_id_field(&self.agent_id, "agent_id")?;
        Self::validate_optional_id_field(&self.tenant_id, "tenant_id")?;
        Self::validate_optional_id_field(&self.session_state, "session_state")?;

        // SECURITY (FIND-R49-001): Bound collection sizes to prevent memory exhaustion
        // from oversized deserialized payloads.
        if self.call_counts.len() > Self::MAX_CALL_COUNTS {
            return Err(format!(
                "EvaluationContext call_counts has {} entries, max {}",
                self.call_counts.len(),
                Self::MAX_CALL_COUNTS,
            ));
        }
        if self.previous_actions.len() > Self::MAX_PREVIOUS_ACTIONS {
            return Err(format!(
                "EvaluationContext previous_actions has {} entries, max {}",
                self.previous_actions.len(),
                Self::MAX_PREVIOUS_ACTIONS,
            ));
        }
        // SECURITY (FIND-R50-064): Bound individual previous_actions entry length
        // to prevent memory amplification via to_ascii_lowercase() allocations
        // in sequence/workflow evaluation.
        for (i, action) in self.previous_actions.iter().enumerate() {
            if action.len() > Self::MAX_ACTION_NAME_LEN {
                return Err(format!(
                    "EvaluationContext previous_actions[{}] length {} exceeds max {}",
                    i,
                    action.len(),
                    Self::MAX_ACTION_NAME_LEN,
                ));
            }
            // SECURITY (FIND-R52-008, FIND-R56-CORE-002): Reject control characters
            // and Unicode format characters in previous_actions entries.
            // Compiled sequences reject control characters at compile time, so a history
            // entry with embedded control characters (e.g., "read_secret\x00") would
            // never match a compiled sequence entry via eq_ignore_ascii_case, allowing
            // ForbiddenActionSequence bypass. Format characters (zero-width, bidi) are
            // rejected for parity with call_counts key validation.
            if action
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "EvaluationContext previous_actions[{}] contains control or format characters",
                    i,
                ));
            }
        }
        // SECURITY (FIND-R52-006): Bound individual call_counts key length
        // to prevent memory amplification via oversized HashMap keys.
        // SECURITY (FIND-R55-CORE-013): Reject control and Unicode format characters
        // in call_counts keys to prevent pattern matching bypass (matching the
        // previous_actions validation pattern from FIND-R52-008).
        for key in self.call_counts.keys() {
            if key.len() > Self::MAX_ACTION_NAME_LEN {
                return Err(format!(
                    "EvaluationContext call_counts key length {} exceeds max {}",
                    key.len(),
                    Self::MAX_ACTION_NAME_LEN,
                ));
            }
            if key
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(
                    "EvaluationContext call_counts key contains control or format characters"
                        .to_string(),
                );
            }
        }
        if self.call_chain.len() > Self::MAX_CALL_CHAIN {
            return Err(format!(
                "EvaluationContext call_chain has {} entries, max {}",
                self.call_chain.len(),
                Self::MAX_CALL_CHAIN,
            ));
        }

        // SECURITY (FIND-R51-005): Validate call_chain entry contents to prevent
        // log injection and confusion attacks via control characters or oversized fields.
        for (i, entry) in self.call_chain.iter().enumerate() {
            Self::validate_call_chain_field(&entry.agent_id, "agent_id", i)?;
            Self::validate_call_chain_field(&entry.tool, "tool", i)?;
            Self::validate_call_chain_field(&entry.function, "function", i)?;
            if entry.timestamp.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "EvaluationContext call_chain[{}].timestamp length {} exceeds max {}",
                    i,
                    entry.timestamp.len(),
                    Self::MAX_TIMESTAMP_LEN,
                ));
            }
            // SECURITY (FIND-R85-001): Check both control and Unicode format characters,
            // matching validate_call_chain_field() parity for agent_id/tool/function.
            if entry
                .timestamp
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "EvaluationContext call_chain[{}].timestamp contains control or format characters",
                    i,
                ));
            }
            // SECURITY: Validate HMAC field length if present.
            // HMAC-SHA256 produces 64 hex chars; cap at 128 for future headroom.
            if let Some(ref hmac) = entry.hmac {
                if hmac.len() > Self::MAX_HMAC_LEN {
                    return Err(format!(
                        "EvaluationContext call_chain[{}].hmac length {} exceeds max {}",
                        i,
                        hmac.len(),
                        Self::MAX_HMAC_LEN,
                    ));
                }
            }
        }

        // SECURITY (FIND-R55-CORE-002): Validate nested AgentIdentity bounds
        // (claims count cap) to prevent memory exhaustion via oversized identity payloads.
        if let Some(ref identity) = self.agent_identity {
            identity
                .validate()
                .map_err(|e| format!("EvaluationContext agent_identity: {e}"))?;
        }

        Ok(())
    }

    /// Validate a call_chain entry field: reject control/format chars, enforce max length.
    ///
    /// SECURITY (FIND-R51-005): Prevents log injection via control characters
    /// and memory abuse via oversized call chain fields.
    fn validate_call_chain_field(
        value: &str,
        field_name: &str,
        index: usize,
    ) -> Result<(), String> {
        if value.len() > Self::MAX_CALL_CHAIN_FIELD_LEN {
            return Err(format!(
                "EvaluationContext call_chain[{}].{} length {} exceeds max {}",
                index,
                field_name,
                value.len(),
                Self::MAX_CALL_CHAIN_FIELD_LEN,
            ));
        }
        // SECURITY (FIND-R52-005): Also reject Unicode format characters (category Cf)
        // which include zero-width chars (U+200B-U+200F), bidi overrides (U+202A-U+202E,
        // U+2066-U+2069), and BOM (U+FEFF). These can cause identity confusion in logs.
        if value
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(format!(
                "EvaluationContext call_chain[{}].{} contains control or format characters",
                index, field_name,
            ));
        }
        Ok(())
    }

    /// Validate a single optional identity field: if present, must be non-empty
    /// and must not contain control or Unicode format characters.
    ///
    /// SECURITY (FIND-R52-005): Also reject Unicode format characters (category Cf)
    /// to prevent identity confusion via zero-width chars, bidi overrides, or BOM.
    fn validate_optional_id_field(field: &Option<String>, name: &str) -> Result<(), String> {
        if let Some(value) = field {
            if value.is_empty() {
                return Err(format!("EvaluationContext {name} is present but empty"));
            }
            if value
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "EvaluationContext {name} contains control or format characters"
                ));
            }
        }
        Ok(())
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

    /// Build the [`EvaluationContext`] without validation.
    ///
    /// For trusted internal callers where inputs are already validated.
    /// At trust boundaries (HTTP handlers, deserialization), prefer
    /// [`build_validated`] which rejects invalid identity fields.
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

    /// Build the [`EvaluationContext`] with validation on identity fields.
    ///
    /// SECURITY (FIND-R46-017): Validates that agent_id, tenant_id, and
    /// session_state (if present) are non-empty and free of control characters.
    /// Use this at trust boundaries where inputs come from external sources.
    pub fn build_validated(self) -> Result<EvaluationContext, String> {
        let ctx = self.build();
        ctx.validate()?;
        Ok(ctx)
    }
}

// ═══════════════════════════════════════════════════════════════════
// Phase 25.6: Stateless protocol abstraction
// ═══════════════════════════════════════════════════════════════════

/// Abstraction over session state access for policy evaluation.
///
/// Stateful mode (current behavior): reads from in-memory `SessionStore`.
/// Stateless mode (future): reads from a signed per-request context blob.
///
/// This trait boundary allows security-critical code to remain unchanged
/// while supporting both session-based and stateless HTTP transports.
///
/// # Security
///
/// Implementors must ensure that:
/// - `call_counts()` and `previous_actions()` are tamper-proof
/// - In stateless mode, the context blob is signed and verified
/// - `record_action()` correctly persists state (or returns it in the response)
pub trait RequestContext: Send + Sync {
    /// Per-tool call counts for the current session/request chain.
    fn call_counts(&self) -> &HashMap<String, u64>;

    /// History of tool names called in this session/request chain.
    fn previous_actions(&self) -> &[String];

    /// Multi-agent call chain entries.
    fn call_chain(&self) -> &[CallChainEntry];

    /// Cryptographically attested agent identity (if available).
    fn agent_identity(&self) -> Option<&AgentIdentity>;

    /// Session guard state machine state (if tracked).
    fn session_guard_state(&self) -> Option<&str>;

    /// Current risk score from continuous authorization (if available).
    fn risk_score(&self) -> Option<&crate::abac::RiskScore>;

    /// Build an `EvaluationContext` from this request context.
    ///
    /// Populates all session-derived fields so the policy engine can
    /// evaluate context conditions (call limits, action sequences, etc.).
    fn to_evaluation_context(&self) -> EvaluationContext {
        EvaluationContext {
            call_counts: self.call_counts().clone(),
            previous_actions: self.previous_actions().to_vec(),
            call_chain: self.call_chain().to_vec(),
            agent_identity: self.agent_identity().cloned(),
            session_state: self.session_guard_state().map(|s| s.to_string()),
            ..Default::default()
        }
    }
}

/// Signed context carried per-request in stateless mode.
///
/// In stateless HTTP mode (MCP June 2026+), there is no server-side session.
/// Instead, the proxy issues this blob in responses and the client echoes it
/// back in subsequent requests. The HMAC-SHA256 signature prevents tampering.
///
/// # Security
///
/// - `signature` covers all other fields via HMAC-SHA256 with a server-side key
/// - `issued_at` enables expiry checking (reject stale blobs)
/// - `version` enables forward-compatible format changes
/// - Maximum blob size is bounded to prevent memory abuse
///
/// # Future
///
/// This struct is defined now to lock the wire format. The actual
/// serialization, signing, and verification logic will be implemented
/// when the June 2026 MCP spec is finalized.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatelessContextBlob {
    /// Wire format version. Current: 1.
    pub version: u8,
    /// Agent identifier.
    pub agent_id: String,
    /// Per-tool call counts.
    pub call_counts: HashMap<String, u64>,
    /// Last N actions (bounded to prevent unbounded growth).
    pub recent_actions: Vec<String>,
    /// Multi-agent call chain.
    pub call_chain: Vec<CallChainEntry>,
    /// Risk score from continuous authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<crate::abac::RiskScore>,
    /// Unix timestamp when this blob was issued.
    pub issued_at: u64,
    /// HMAC-SHA256 signature over the serialized content (hex-encoded).
    pub signature: String,
}

impl fmt::Debug for StatelessContextBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatelessContextBlob")
            .field("version", &self.version)
            .field("agent_id", &self.agent_id)
            .field("call_counts", &self.call_counts)
            .field("recent_actions", &self.recent_actions)
            .field("call_chain", &self.call_chain)
            .field("risk_score", &self.risk_score)
            .field("issued_at", &self.issued_at)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl StatelessContextBlob {
    /// Maximum age of a stateless context blob before it's considered expired.
    pub const MAX_AGE_SECS: u64 = 300; // 5 minutes

    /// Maximum number of recent actions stored in the blob.
    pub const MAX_RECENT_ACTIONS: usize = 100;

    /// Maximum number of entries in `call_counts` before validation fails.
    const MAX_BLOB_CALL_COUNTS: usize = 10_000;

    /// Maximum number of entries in `call_chain` before validation fails.
    const MAX_BLOB_CALL_CHAIN: usize = 100;

    /// Check if this blob has expired based on the current time.
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs.saturating_sub(self.issued_at) > Self::MAX_AGE_SECS
    }

    /// Validate the blob's collection sizes and identity fields.
    ///
    /// SECURITY (FIND-R49-002): Prevents memory exhaustion from oversized
    /// deserialized blobs and rejects malformed agent identifiers.
    pub fn validate(&self) -> Result<(), String> {
        if self.agent_id.is_empty() {
            return Err("StatelessContextBlob agent_id is empty".to_string());
        }
        if self.agent_id.len() > 256 {
            return Err(format!(
                "StatelessContextBlob agent_id length {} exceeds max 256",
                self.agent_id.len(),
            ));
        }
        if self.call_counts.len() > Self::MAX_BLOB_CALL_COUNTS {
            return Err(format!(
                "StatelessContextBlob call_counts has {} entries, max {}",
                self.call_counts.len(),
                Self::MAX_BLOB_CALL_COUNTS,
            ));
        }
        if self.recent_actions.len() > Self::MAX_RECENT_ACTIONS {
            return Err(format!(
                "StatelessContextBlob recent_actions has {} entries, max {}",
                self.recent_actions.len(),
                Self::MAX_RECENT_ACTIONS,
            ));
        }
        if self.call_chain.len() > Self::MAX_BLOB_CALL_CHAIN {
            return Err(format!(
                "StatelessContextBlob call_chain has {} entries, max {}",
                self.call_chain.len(),
                Self::MAX_BLOB_CALL_CHAIN,
            ));
        }

        // SECURITY (FIND-R52-019): Validate per-entry lengths for call_counts keys
        // and recent_actions entries to prevent memory amplification.
        const MAX_ENTRY_LEN: usize = 256;
        for key in self.call_counts.keys() {
            if key.len() > MAX_ENTRY_LEN {
                return Err(format!(
                    "StatelessContextBlob call_counts key length {} exceeds max {}",
                    key.len(),
                    MAX_ENTRY_LEN,
                ));
            }
        }
        for (i, action) in self.recent_actions.iter().enumerate() {
            if action.len() > MAX_ENTRY_LEN {
                return Err(format!(
                    "StatelessContextBlob recent_actions[{}] length {} exceeds max {}",
                    i,
                    action.len(),
                    MAX_ENTRY_LEN,
                ));
            }
        }

        // SECURITY (FIND-R51-007): Validate signature format.
        // HMAC-SHA256 produces 32 bytes = 64 hex characters.
        if self.signature.is_empty() {
            return Err("StatelessContextBlob signature must not be empty".to_string());
        }
        if self.signature.len() != 64 {
            return Err(format!(
                "StatelessContextBlob signature length {} is not 64 (expected HMAC-SHA256 hex)",
                self.signature.len(),
            ));
        }
        // SECURITY (FIND-R52-004): Reject non-lowercase hex to ensure canonical
        // representation for consistent comparison and log analysis.
        if !self
            .signature
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(
                "StatelessContextBlob signature must be lowercase hex characters".to_string(),
            );
        }

        Ok(())
    }
}

impl RequestContext for StatelessContextBlob {
    fn call_counts(&self) -> &HashMap<String, u64> {
        &self.call_counts
    }

    fn previous_actions(&self) -> &[String] {
        &self.recent_actions
    }

    fn call_chain(&self) -> &[CallChainEntry] {
        &self.call_chain
    }

    fn agent_identity(&self) -> Option<&AgentIdentity> {
        None // Stateless blobs don't carry full identity (it's in the JWT)
    }

    fn session_guard_state(&self) -> Option<&str> {
        None // Session guard is stateful-only for now
    }

    fn risk_score(&self) -> Option<&crate::abac::RiskScore> {
        self.risk_score.as_ref()
    }
}
