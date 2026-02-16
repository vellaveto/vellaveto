//! Session management for MCP Streamable HTTP transport.
//!
//! Each MCP session is identified by a `Mcp-Session-Id` header. The proxy
//! tracks per-session state including known tool annotations, protocol
//! version, and request counts.
//!
//! **Status:** Production — fully wired into the HTTP proxy.

use dashmap::DashMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vellaveto_config::ToolManifest;
use vellaveto_mcp::memory_tracking::MemoryTracker;
use vellaveto_mcp::rug_pull::ToolAnnotations;
use vellaveto_types::AgentIdentity;

/// Type alias for backward compatibility with existing code.
pub type ToolAnnotationsCompact = ToolAnnotations;

/// Per-session state tracked by the HTTP proxy.
#[derive(Debug)]
pub struct SessionState {
    pub session_id: String,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub protocol_version: Option<String>,
    pub known_tools: HashMap<String, ToolAnnotations>,
    pub request_count: u64,
    /// Whether the initial tools/list response has been seen for this session.
    /// Used for rug-pull detection: tool additions after the first list are suspicious.
    pub tools_list_seen: bool,
    /// OAuth subject identifier from the authenticated token (if OAuth is enabled).
    /// Stored for inclusion in audit trail entries.
    pub oauth_subject: Option<String>,
    /// Tools flagged by rug-pull detection. Tool calls to these tools are
    /// blocked until the session is cleared or a clean tools/list is received.
    pub flagged_tools: HashSet<String>,
    /// Pinned tool manifest for this session. Built from the first tools/list
    /// response, used to verify subsequent tools/list responses.
    pub pinned_manifest: Option<ToolManifest>,
    /// Per-tool call counts for context-aware policy evaluation.
    /// Maps tool name → number of times called in this session.
    pub call_counts: HashMap<String, u64>,
    /// History of tool names called in this session (most recent last).
    /// Capped at 100 entries to bound memory usage. Uses VecDeque for O(1)
    /// pop_front instead of O(n) Vec::remove(0) (FIND-046).
    pub action_history: VecDeque<String>,
    /// OWASP ASI06: Per-session memory poisoning tracker.
    /// Records fingerprints of notable strings from tool responses and flags
    /// when those strings appear verbatim in subsequent tool call parameters.
    pub memory_tracker: MemoryTracker,
    /// Number of elicitation requests processed in this session.
    /// Used for per-session rate limiting of `elicitation/create` requests.
    pub elicitation_count: u32,
    /// Pending tool call correlation map: JSON-RPC response id key -> tool name.
    /// Used to recover tool context for `structuredContent` validation when
    /// upstream responses omit `result._meta.tool`.
    pub pending_tool_calls: HashMap<String, String>,
    /// SECURITY (R15-OAUTH-4): Token expiry timestamp (Unix seconds).
    pub token_expires_at: Option<u64>,
    /// OWASP ASI08: Call chain for multi-agent communication monitoring.
    /// Tracks upstream agent hops for the latest policy-evaluated request.
    /// Updated from `X-Upstream-Agents` headers on tool calls, resource reads,
    /// and task requests.
    pub current_call_chain: Vec<vellaveto_types::CallChainEntry>,
    /// OWASP ASI07: Cryptographically attested agent identity from X-Agent-Identity JWT.
    /// Populated when the header is present and valid, provides stronger identity
    /// guarantees than the legacy oauth_subject field.
    pub agent_identity: Option<AgentIdentity>,
    /// Phase 20: Gateway backend session mapping.
    /// Maps backend_id → upstream session_id for session affinity.
    pub backend_sessions: HashMap<String, String>,
    /// Phase 20: Tools discovered from each gateway backend.
    /// Maps backend_id → list of tool names for conflict detection.
    pub gateway_tools: HashMap<String, Vec<String>>,
    /// Phase 21: Per-session risk score for continuous authorization.
    pub risk_score: Option<vellaveto_types::RiskScore>,
    /// Phase 21: Granted ABAC policy IDs for least-agency tracking.
    pub abac_granted_policies: Vec<String>,
    /// Phase 34: Tools discovered via `vv_discover` with TTL tracking.
    /// Maps tool_id → session entry with discovery timestamp and TTL.
    pub discovered_tools: HashMap<String, DiscoveredToolSession>,
}

/// Maximum number of discovered tools tracked per session.
/// Prevents unbounded memory growth from excessive discovery requests.
const MAX_DISCOVERED_TOOLS_PER_SESSION: usize = 10_000;

/// Per-session tracking of a discovered tool (Phase 34.3).
#[derive(Debug, Clone)]
pub struct DiscoveredToolSession {
    /// The tool's unique identifier (server_id:tool_name).
    pub tool_id: String,
    /// When this tool was discovered.
    pub discovered_at: Instant,
    /// How long until this discovery expires.
    pub ttl: Duration,
    /// Whether the agent has actually called this tool.
    pub used: bool,
}

impl DiscoveredToolSession {
    /// Check whether this discovery has expired.
    pub fn is_expired(&self) -> bool {
        self.discovered_at.elapsed() > self.ttl
    }
}

impl SessionState {
    pub fn new(session_id: String) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            created_at: now,
            last_activity: now,
            protocol_version: None,
            known_tools: HashMap::new(),
            request_count: 0,
            tools_list_seen: false,
            oauth_subject: None,
            flagged_tools: HashSet::new(),
            pinned_manifest: None,
            call_counts: HashMap::new(),
            action_history: VecDeque::new(),
            memory_tracker: MemoryTracker::new(),
            elicitation_count: 0,
            pending_tool_calls: HashMap::new(),
            token_expires_at: None,
            current_call_chain: Vec::new(),
            agent_identity: None,
            backend_sessions: HashMap::new(),
            gateway_tools: HashMap::new(),
            risk_score: None,
            abac_granted_policies: Vec::new(),
            discovered_tools: HashMap::new(),
        }
    }

    /// Record a set of discovered tools with the given TTL.
    ///
    /// Overwrites any existing entry for the same tool_id (re-discovery resets the TTL).
    /// If the session is at capacity (`MAX_DISCOVERED_TOOLS_PER_SESSION`), expired
    /// entries are evicted first. If still at capacity, new tools are silently dropped.
    pub fn record_discovered_tools(&mut self, tool_ids: &[String], ttl: Duration) {
        let now = Instant::now();
        for tool_id in tool_ids {
            // Allow overwrites of existing entries without capacity check
            if !self.discovered_tools.contains_key(tool_id) {
                if self.discovered_tools.len() >= MAX_DISCOVERED_TOOLS_PER_SESSION {
                    // Evict expired entries to make room
                    self.evict_expired_discoveries();
                }
                if self.discovered_tools.len() >= MAX_DISCOVERED_TOOLS_PER_SESSION {
                    tracing::warn!(
                        session_id = %self.session_id,
                        capacity = MAX_DISCOVERED_TOOLS_PER_SESSION,
                        "Discovered tools capacity reached; dropping new tool"
                    );
                    continue;
                }
            }
            self.discovered_tools.insert(
                tool_id.clone(),
                DiscoveredToolSession {
                    tool_id: tool_id.clone(),
                    discovered_at: now,
                    ttl,
                    used: false,
                },
            );
        }
    }

    /// Check whether a discovered tool has expired.
    ///
    /// Returns `None` if the tool was never discovered (not an error — the tool
    /// may be a statically-known tool that doesn't require discovery).
    /// Returns `Some(true)` if discovered but expired, `Some(false)` if still valid.
    pub fn is_tool_discovery_expired(&self, tool_id: &str) -> Option<bool> {
        self.discovered_tools.get(tool_id).map(|d| d.is_expired())
    }

    /// Mark a discovered tool as "used" (the agent actually called it).
    ///
    /// Returns `true` if the tool was found and marked, `false` if not found.
    pub fn mark_tool_used(&mut self, tool_id: &str) -> bool {
        if let Some(entry) = self.discovered_tools.get_mut(tool_id) {
            entry.used = true;
            true
        } else {
            false
        }
    }

    /// Remove expired discovered tools from the session.
    ///
    /// Returns the number of entries evicted.
    pub fn evict_expired_discoveries(&mut self) -> usize {
        let before = self.discovered_tools.len();
        self.discovered_tools.retain(|_, d| !d.is_expired());
        before - self.discovered_tools.len()
    }

    /// Touch the session to update last activity time.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        self.request_count += 1;
    }

    /// Check if this session has expired.
    ///
    /// A session is expired if either:
    /// - Inactivity timeout: no activity for longer than `timeout`
    /// - Absolute lifetime: the session has existed longer than `max_lifetime` (if set)
    pub fn is_expired(&self, timeout: Duration, max_lifetime: Option<Duration>) -> bool {
        if self.last_activity.elapsed() > timeout {
            return true;
        }
        if let Some(max) = max_lifetime {
            if self.created_at.elapsed() > max {
                return true;
            }
        }
        if let Some(exp) = self.token_expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now >= exp {
                return true;
            }
        }
        false
    }
}

// ═══════════════════════════════════════════════════════════════════
// Phase 25.6: StatefulContext — RequestContext impl for SessionState
// ═══════════════════════════════════════════════════════════════════

use vellaveto_types::identity::RequestContext;

/// Adapter that implements [`RequestContext`] for [`SessionState`].
///
/// This is the stateful-mode implementation: all context is read from the
/// in-memory session store. Wrapping `SessionState` in this adapter allows
/// security-critical code to accept `&dyn RequestContext` and work identically
/// in both stateful and (future) stateless modes.
///
/// # Usage
///
/// ```ignore
/// let ctx = StatefulContext::new(&session);
/// let eval = ctx.to_evaluation_context();
/// engine.evaluate(&action, &eval)?;
/// ```
pub struct StatefulContext<'a> {
    session: &'a SessionState,
    /// Cached Vec of previous actions (converted from VecDeque).
    /// Lazily populated on first access. Uses OnceLock for Sync.
    previous_actions_cache: std::sync::OnceLock<Vec<String>>,
}

impl<'a> StatefulContext<'a> {
    /// Create a new stateful context wrapping a session reference.
    pub fn new(session: &'a SessionState) -> Self {
        Self {
            session,
            previous_actions_cache: std::sync::OnceLock::new(),
        }
    }
}

impl RequestContext for StatefulContext<'_> {
    fn call_counts(&self) -> &HashMap<String, u64> {
        &self.session.call_counts
    }

    fn previous_actions(&self) -> &[String] {
        self.previous_actions_cache
            .get_or_init(|| self.session.action_history.iter().cloned().collect())
    }

    fn call_chain(&self) -> &[vellaveto_types::CallChainEntry] {
        &self.session.current_call_chain
    }

    fn agent_identity(&self) -> Option<&AgentIdentity> {
        self.session.agent_identity.as_ref()
    }

    fn session_guard_state(&self) -> Option<&str> {
        None // SessionGuard state is tracked separately, not in SessionState fields
    }

    fn risk_score(&self) -> Option<&vellaveto_types::RiskScore> {
        self.session.risk_score.as_ref()
    }

    fn to_evaluation_context(&self) -> vellaveto_types::EvaluationContext {
        vellaveto_types::EvaluationContext {
            agent_id: self.session.oauth_subject.clone(),
            agent_identity: self.session.agent_identity.clone(),
            call_counts: self.session.call_counts.clone(),
            previous_actions: self.session.action_history.iter().cloned().collect(),
            call_chain: self.session.current_call_chain.clone(),
            session_state: None,
            ..Default::default()
        }
    }
}

/// SECURITY (R39-PROXY-7): Maximum length for client-provided session IDs.
/// Server-generated IDs are UUIDs (36 chars). Reject anything longer than
/// this to prevent memory abuse via arbitrarily long session ID strings.
const MAX_SESSION_ID_LEN: usize = 128;

/// Thread-safe session store with automatic expiry cleanup.
pub struct SessionStore {
    sessions: Arc<DashMap<String, SessionState>>,
    session_timeout: Duration,
    max_sessions: usize,
    /// Optional absolute session lifetime. When set, sessions are expired
    /// after this duration regardless of activity. Prevents indefinite
    /// session reuse (e.g., stolen session IDs).
    max_lifetime: Option<Duration>,
}

impl SessionStore {
    pub fn new(session_timeout: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            session_timeout,
            max_sessions,
            max_lifetime: None,
        }
    }

    /// Set an absolute session lifetime. Sessions older than this duration
    /// are expired regardless of activity. Returns `self` for chaining.
    pub fn with_max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = Some(lifetime);
        self
    }

    /// Get or create a session. Returns the session ID.
    ///
    /// If `client_session_id` is provided and the session exists, it's reused.
    /// Otherwise a new session is created. Session IDs are always server-generated
    /// to prevent session fixation attacks.
    pub fn get_or_create(&self, client_session_id: Option<&str>) -> String {
        // SECURITY (R39-PROXY-7): Reject oversized session IDs — treat as invalid
        // to prevent memory abuse. Server-generated IDs are UUIDs (36 chars).
        let client_session_id = client_session_id.filter(|id| id.len() <= MAX_SESSION_ID_LEN);

        // Try to reuse existing session if client provided an ID
        if let Some(id) = client_session_id {
            if let Some(mut session) = self.sessions.get_mut(id) {
                if !session.is_expired(self.session_timeout, self.max_lifetime) {
                    session.touch();
                    return id.to_string();
                }
                // Expired — drop and create new
                drop(session);
                self.sessions.remove(id);
            }
        }

        // Enforce max sessions.
        // Note: under high concurrency, session count may temporarily exceed
        // max_sessions by up to the number of concurrent requests. This is a
        // TOCTOU race inherent to DashMap's non-atomic len()+insert() sequence.
        // The background cleanup task and per-request eviction correct this
        // within seconds, so the overshoot is transient and self-correcting.
        if self.sessions.len() >= self.max_sessions {
            self.evict_expired();
            // If still at capacity after cleanup, evict oldest
            if self.sessions.len() >= self.max_sessions {
                self.evict_oldest();
            }
        }

        // Create new session with server-generated ID
        let session_id = uuid::Uuid::new_v4().to_string();
        self.sessions
            .insert(session_id.clone(), SessionState::new(session_id.clone()));
        session_id
    }

    /// Get a mutable reference to a session.
    pub fn get_mut(
        &self,
        session_id: &str,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, SessionState>> {
        self.sessions.get_mut(session_id)
    }

    /// Remove expired sessions.
    pub fn evict_expired(&self) {
        self.sessions
            .retain(|_, session| !session.is_expired(self.session_timeout, self.max_lifetime));
    }

    /// Remove the oldest session (by last activity).
    fn evict_oldest(&self) {
        let oldest = self
            .sessions
            .iter()
            .min_by_key(|entry| entry.value().last_activity)
            .map(|entry| entry.key().clone());

        if let Some(id) = oldest {
            self.sessions.remove(&id);
        }
    }

    /// Current number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether there are any active sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Delete a specific session (e.g., on client disconnect via DELETE).
    pub fn remove(&self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(None);
        assert_eq!(id.len(), 36); // UUID format
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_session_reuse() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id1 = store.get_or_create(None);
        let id2 = store.get_or_create(Some(&id1));
        assert_eq!(id1, id2);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_session_unknown_id_creates_new() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(Some("nonexistent-id"));
        assert_ne!(id, "nonexistent-id");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_max_sessions_enforced() {
        let store = SessionStore::new(Duration::from_secs(300), 3);
        store.get_or_create(None);
        store.get_or_create(None);
        store.get_or_create(None);
        assert_eq!(store.len(), 3);
        // 4th session should evict the oldest
        store.get_or_create(None);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn test_session_remove() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(None);
        assert!(store.remove(&id));
        assert_eq!(store.len(), 0);
        assert!(!store.remove(&id));
    }

    #[test]
    fn test_session_touch_increments_count() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(None);
        // First get_or_create doesn't touch (just created)
        // Second reuse does touch
        store.get_or_create(Some(&id));
        let session = store.get_mut(&id).unwrap();
        assert_eq!(session.request_count, 1);
    }

    #[test]
    fn test_flagged_tools_insert_and_contains() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(None);

        // Insert flagged tools
        {
            let mut session = store.get_mut(&id).unwrap();
            session.flagged_tools.insert("evil_tool".to_string());
            session.flagged_tools.insert("suspicious_tool".to_string());
        }

        // Verify containment
        let session = store.get_mut(&id).unwrap();
        assert!(session.flagged_tools.contains("evil_tool"));
        assert!(session.flagged_tools.contains("suspicious_tool"));
        assert!(!session.flagged_tools.contains("safe_tool"));
        assert_eq!(session.flagged_tools.len(), 2);
    }

    #[test]
    fn test_flagged_tools_empty_by_default() {
        let state = SessionState::new("test-session".to_string());
        assert!(state.flagged_tools.is_empty());
        assert!(state.pending_tool_calls.is_empty());
    }

    #[test]
    fn test_oauth_subject_storage() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(None);

        // Initially None
        {
            let session = store.get_mut(&id).unwrap();
            assert!(session.oauth_subject.is_none());
        }

        // Set subject
        {
            let mut session = store.get_mut(&id).unwrap();
            session.oauth_subject = Some("user-42".to_string());
        }

        // Verify persistence
        let session = store.get_mut(&id).unwrap();
        assert_eq!(session.oauth_subject.as_deref(), Some("user-42"));
    }

    #[test]
    fn test_protocol_version_tracking() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(None);

        {
            let session = store.get_mut(&id).unwrap();
            assert!(session.protocol_version.is_none());
        }

        {
            let mut session = store.get_mut(&id).unwrap();
            session.protocol_version = Some("2025-11-25".to_string());
        }

        let session = store.get_mut(&id).unwrap();
        assert_eq!(session.protocol_version.as_deref(), Some("2025-11-25"));
    }

    #[test]
    fn test_known_tools_mutations() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(None);

        {
            let mut session = store.get_mut(&id).unwrap();
            session.known_tools.insert(
                "read_file".to_string(),
                ToolAnnotations {
                    read_only_hint: true,
                    destructive_hint: false,
                    idempotent_hint: true,
                    open_world_hint: false,
                    input_schema_hash: None,
                },
            );
        }

        let session = store.get_mut(&id).unwrap();
        assert_eq!(session.known_tools.len(), 1);
        let ann = session.known_tools.get("read_file").unwrap();
        assert!(ann.read_only_hint);
        assert!(!ann.destructive_hint);
    }

    #[test]
    fn test_tool_annotations_default() {
        let ann = ToolAnnotations::default();
        assert!(!ann.read_only_hint);
        assert!(ann.destructive_hint);
        assert!(!ann.idempotent_hint);
        assert!(ann.open_world_hint);
    }

    #[test]
    fn test_tool_annotations_equality() {
        let a = ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
            input_schema_hash: None,
        };
        let b = ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
            input_schema_hash: None,
        };
        let c = ToolAnnotations::default();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_tools_list_seen_flag() {
        let state = SessionState::new("test".to_string());
        assert!(!state.tools_list_seen);
    }

    // --- Phase 5B: Absolute session lifetime tests ---

    #[test]
    fn test_inactivity_expiry_preserved() {
        let state = SessionState::new("test-inactivity".to_string());
        // Not expired with generous timeout, no max_lifetime
        assert!(!state.is_expired(Duration::from_secs(300), None));
        // Expired with zero timeout (any elapsed time exceeds 0)
        assert!(state.is_expired(Duration::from_nanos(0), None));
    }

    #[test]
    fn test_absolute_lifetime_enforced() {
        let state = SessionState::new("test-lifetime".to_string());
        // With a zero max_lifetime, should be expired immediately (created_at has elapsed > 0)
        assert!(state.is_expired(Duration::from_secs(300), Some(Duration::from_nanos(0))));
        // With generous max_lifetime, should not be expired
        assert!(!state.is_expired(Duration::from_secs(300), Some(Duration::from_secs(86400))));
    }

    #[test]
    fn test_none_max_lifetime_no_absolute_limit() {
        let state = SessionState::new("test-no-limit".to_string());
        // Without max_lifetime, only inactivity timeout matters
        assert!(!state.is_expired(Duration::from_secs(300), None));
    }

    #[test]
    fn test_eviction_checks_both_timeouts() {
        // Create a store with a very short max_lifetime
        let store = SessionStore::new(Duration::from_secs(300), 100)
            .with_max_lifetime(Duration::from_nanos(0));

        let _id = store.get_or_create(None);
        assert_eq!(store.len(), 1);

        // Evict expired should remove the session (max_lifetime exceeded)
        store.evict_expired();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_with_max_lifetime_builder() {
        let store = SessionStore::new(Duration::from_secs(300), 100)
            .with_max_lifetime(Duration::from_secs(86400));
        // Session should be created and accessible
        let id = store.get_or_create(None);
        assert_eq!(store.len(), 1);
        // Can reuse the session (not expired)
        let id2 = store.get_or_create(Some(&id));
        assert_eq!(id, id2);
    }

    // --- R39-PROXY-7: Session ID length validation ---

    #[test]
    fn test_session_id_at_max_length_accepted() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        // Create a session with a 128-char ID first, then try to reuse it
        let long_id = "a".repeat(MAX_SESSION_ID_LEN);
        // Since the session doesn't exist, a new one is created
        let id = store.get_or_create(Some(&long_id));
        assert_ne!(id, long_id); // Server-generated, not client ID
        assert_eq!(store.len(), 1);

        // Now manually insert with the long ID and verify reuse works
        store
            .sessions
            .insert(long_id.clone(), SessionState::new(long_id.clone()));
        let reused = store.get_or_create(Some(&long_id));
        assert_eq!(reused, long_id);
    }

    #[test]
    fn test_session_id_exceeding_max_length_rejected() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        // Insert a session with a 129-char ID manually
        let too_long = "b".repeat(MAX_SESSION_ID_LEN + 1);
        store
            .sessions
            .insert(too_long.clone(), SessionState::new(too_long.clone()));

        // Even though the session exists, the oversized ID should be rejected
        // and a new server-generated session ID returned
        let id = store.get_or_create(Some(&too_long));
        assert_ne!(id, too_long, "Oversized session ID must not be reused");
        assert_eq!(id.len(), 36, "Should return a UUID-format session ID");
    }

    #[test]
    fn test_session_id_empty_string_accepted() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        // Empty string is within the length limit but won't match any session
        let id = store.get_or_create(Some(""));
        assert_eq!(id.len(), 36); // New UUID generated
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_session_id_exactly_128_chars_boundary() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let exact = "x".repeat(128);
        // Should be treated as valid (not rejected)
        let id = store.get_or_create(Some(&exact));
        // Session doesn't exist, so new one is created, but the ID was accepted
        // for lookup (just not found)
        assert_eq!(id.len(), 36);

        let one_over = "x".repeat(129);
        let id2 = store.get_or_create(Some(&one_over));
        assert_eq!(id2.len(), 36);
        // Both should have created new sessions
        assert_eq!(store.len(), 2);
    }

    // ═══════════════════════════════════════════════════
    // Phase 25.6: StatefulContext tests
    // ═══════════════════════════════════════════════════

    /// Phase 25.6: StatefulContext implements RequestContext trait.
    #[test]
    fn test_stateful_context_implements_trait() {
        let session = SessionState::new("test-ctx".to_string());
        let ctx = StatefulContext::new(&session);

        // Verify trait methods work
        let _: &dyn RequestContext = &ctx;
        assert!(ctx.call_counts().is_empty());
        assert!(ctx.previous_actions().is_empty());
        assert!(ctx.call_chain().is_empty());
        assert!(ctx.agent_identity().is_none());
        assert!(ctx.session_guard_state().is_none());
        assert!(ctx.risk_score().is_none());
    }

    /// Phase 25.6: call_counts() returns session's call counts.
    #[test]
    fn test_stateful_context_call_counts() {
        let mut session = SessionState::new("test-counts".to_string());
        session.call_counts.insert("read_file".to_string(), 5);
        session.call_counts.insert("write_file".to_string(), 3);

        let ctx = StatefulContext::new(&session);
        assert_eq!(ctx.call_counts().len(), 2);
        assert_eq!(ctx.call_counts()["read_file"], 5);
        assert_eq!(ctx.call_counts()["write_file"], 3);
    }

    /// Phase 25.6: previous_actions() returns session's action history.
    #[test]
    fn test_stateful_context_previous_actions() {
        let mut session = SessionState::new("test-actions".to_string());
        session.action_history.push_back("read_file".to_string());
        session.action_history.push_back("write_file".to_string());
        session.action_history.push_back("execute".to_string());

        let ctx = StatefulContext::new(&session);
        let actions = ctx.previous_actions();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0], "read_file");
        assert_eq!(actions[1], "write_file");
        assert_eq!(actions[2], "execute");
    }

    // ═══════════════════════════════════════════════════
    // Phase 34.3: Discovered tools TTL tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_discovered_tools_empty_by_default() {
        let state = SessionState::new("test".to_string());
        assert!(state.discovered_tools.is_empty());
    }

    #[test]
    fn test_record_discovered_tools() {
        let mut state = SessionState::new("test".to_string());
        let tools = vec!["server:read_file".to_string(), "server:write_file".to_string()];
        state.record_discovered_tools(&tools, Duration::from_secs(300));

        assert_eq!(state.discovered_tools.len(), 2);
        assert!(state.discovered_tools.contains_key("server:read_file"));
        assert!(state.discovered_tools.contains_key("server:write_file"));
    }

    #[test]
    fn test_record_discovered_tools_sets_ttl() {
        let mut state = SessionState::new("test".to_string());
        state.record_discovered_tools(
            &["server:tool1".to_string()],
            Duration::from_secs(60),
        );

        let entry = state.discovered_tools.get("server:tool1").unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(60));
        assert!(!entry.used);
    }

    #[test]
    fn test_record_discovered_tools_rediscovery_resets_ttl() {
        let mut state = SessionState::new("test".to_string());
        state.record_discovered_tools(
            &["server:tool1".to_string()],
            Duration::from_secs(60),
        );

        // Mark as used
        state.mark_tool_used("server:tool1");
        assert!(state.discovered_tools.get("server:tool1").unwrap().used);

        // Re-discover resets TTL and used flag
        state.record_discovered_tools(
            &["server:tool1".to_string()],
            Duration::from_secs(120),
        );

        let entry = state.discovered_tools.get("server:tool1").unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(120));
        assert!(!entry.used); // reset on re-discovery
    }

    #[test]
    fn test_is_tool_discovery_expired_unknown_tool() {
        let state = SessionState::new("test".to_string());
        assert_eq!(state.is_tool_discovery_expired("unknown:tool"), None);
    }

    #[test]
    fn test_is_tool_discovery_expired_fresh_tool() {
        let mut state = SessionState::new("test".to_string());
        state.record_discovered_tools(
            &["server:tool1".to_string()],
            Duration::from_secs(300),
        );
        assert_eq!(state.is_tool_discovery_expired("server:tool1"), Some(false));
    }

    #[test]
    fn test_is_tool_discovery_expired_zero_ttl() {
        let mut state = SessionState::new("test".to_string());
        // Zero TTL means expired immediately
        state.discovered_tools.insert(
            "server:tool1".to_string(),
            DiscoveredToolSession {
                tool_id: "server:tool1".to_string(),
                discovered_at: Instant::now() - Duration::from_secs(1),
                ttl: Duration::from_nanos(0),
                used: false,
            },
        );
        assert_eq!(state.is_tool_discovery_expired("server:tool1"), Some(true));
    }

    #[test]
    fn test_mark_tool_used_existing() {
        let mut state = SessionState::new("test".to_string());
        state.record_discovered_tools(
            &["server:tool1".to_string()],
            Duration::from_secs(300),
        );
        assert!(!state.discovered_tools.get("server:tool1").unwrap().used);

        assert!(state.mark_tool_used("server:tool1"));
        assert!(state.discovered_tools.get("server:tool1").unwrap().used);
    }

    #[test]
    fn test_mark_tool_used_nonexistent() {
        let mut state = SessionState::new("test".to_string());
        assert!(!state.mark_tool_used("unknown:tool"));
    }

    #[test]
    fn test_evict_expired_discoveries_none_expired() {
        let mut state = SessionState::new("test".to_string());
        state.record_discovered_tools(
            &["server:tool1".to_string(), "server:tool2".to_string()],
            Duration::from_secs(300),
        );
        assert_eq!(state.evict_expired_discoveries(), 0);
        assert_eq!(state.discovered_tools.len(), 2);
    }

    #[test]
    fn test_evict_expired_discoveries_some_expired() {
        let mut state = SessionState::new("test".to_string());

        // Fresh tool
        state.record_discovered_tools(
            &["server:fresh".to_string()],
            Duration::from_secs(300),
        );

        // Expired tool (discovered in the past with short TTL)
        state.discovered_tools.insert(
            "server:stale".to_string(),
            DiscoveredToolSession {
                tool_id: "server:stale".to_string(),
                discovered_at: Instant::now() - Duration::from_secs(10),
                ttl: Duration::from_secs(1),
                used: true,
            },
        );

        assert_eq!(state.evict_expired_discoveries(), 1);
        assert_eq!(state.discovered_tools.len(), 1);
        assert!(state.discovered_tools.contains_key("server:fresh"));
        assert!(!state.discovered_tools.contains_key("server:stale"));
    }

    #[test]
    fn test_evict_expired_discoveries_all_expired() {
        let mut state = SessionState::new("test".to_string());
        let past = Instant::now() - Duration::from_secs(10);
        for i in 0..5 {
            state.discovered_tools.insert(
                format!("server:tool{}", i),
                DiscoveredToolSession {
                    tool_id: format!("server:tool{}", i),
                    discovered_at: past,
                    ttl: Duration::from_secs(1),
                    used: false,
                },
            );
        }

        assert_eq!(state.evict_expired_discoveries(), 5);
        assert!(state.discovered_tools.is_empty());
    }

    #[test]
    fn test_discovered_tool_session_is_expired() {
        let fresh = DiscoveredToolSession {
            tool_id: "t".to_string(),
            discovered_at: Instant::now(),
            ttl: Duration::from_secs(300),
            used: false,
        };
        assert!(!fresh.is_expired());

        let stale = DiscoveredToolSession {
            tool_id: "t".to_string(),
            discovered_at: Instant::now() - Duration::from_secs(10),
            ttl: Duration::from_secs(1),
            used: false,
        };
        assert!(stale.is_expired());
    }

    #[test]
    fn test_discovered_tools_survive_session_touch() {
        let store = SessionStore::new(Duration::from_secs(300), 100);
        let id = store.get_or_create(None);

        // Record a discovered tool
        {
            let mut session = store.get_mut(&id).unwrap();
            session.record_discovered_tools(
                &["server:tool1".to_string()],
                Duration::from_secs(300),
            );
        }

        // Touch via reuse
        store.get_or_create(Some(&id));

        // Discovered tools should persist
        let session = store.get_mut(&id).unwrap();
        assert_eq!(session.discovered_tools.len(), 1);
        assert!(session.discovered_tools.contains_key("server:tool1"));
    }

    #[test]
    fn test_multiple_tools_independent_ttl() {
        let mut state = SessionState::new("test".to_string());

        // Tool with short TTL (already expired)
        state.discovered_tools.insert(
            "server:short".to_string(),
            DiscoveredToolSession {
                tool_id: "server:short".to_string(),
                discovered_at: Instant::now() - Duration::from_secs(5),
                ttl: Duration::from_secs(1),
                used: false,
            },
        );

        // Tool with long TTL (still valid)
        state.record_discovered_tools(
            &["server:long".to_string()],
            Duration::from_secs(3600),
        );

        assert_eq!(state.is_tool_discovery_expired("server:short"), Some(true));
        assert_eq!(state.is_tool_discovery_expired("server:long"), Some(false));
    }

    /// Phase 25.6: EvaluationContext built from StatefulContext.
    #[test]
    fn test_evaluation_context_from_stateful() {
        let mut session = SessionState::new("test-eval".to_string());
        session.oauth_subject = Some("user-42".to_string());
        session.call_counts.insert("tool_a".to_string(), 7);
        session.action_history.push_back("tool_a".to_string());
        session.agent_identity = Some(AgentIdentity {
            issuer: Some("test-issuer".to_string()),
            subject: Some("agent-sub".to_string()),
            ..Default::default()
        });

        let ctx = StatefulContext::new(&session);
        let eval = ctx.to_evaluation_context();

        assert_eq!(eval.agent_id.as_deref(), Some("user-42"));
        assert_eq!(eval.call_counts["tool_a"], 7);
        assert_eq!(eval.previous_actions, vec!["tool_a".to_string()]);
        assert_eq!(
            eval.agent_identity.as_ref().unwrap().issuer.as_deref(),
            Some("test-issuer")
        );
    }
}
