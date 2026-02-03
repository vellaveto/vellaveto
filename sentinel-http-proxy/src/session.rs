//! Session management for MCP Streamable HTTP transport.
//!
//! Each MCP session is identified by a `Mcp-Session-Id` header. The proxy
//! tracks per-session state including known tool annotations, protocol
//! version, and request counts.
//!
//! **Status:** Implemented, pending integration with HTTP proxy (Phase 9).

#![allow(dead_code)] // Stub crate — session module is implemented but not yet wired to proxy

use dashmap::DashMap;
use sentinel_mcp::rug_pull::ToolAnnotations;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        }
    }

    /// Touch the session to update last activity time.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        self.request_count += 1;
    }

    /// Check if this session has expired.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Thread-safe session store with automatic expiry cleanup.
pub struct SessionStore {
    sessions: Arc<DashMap<String, SessionState>>,
    session_timeout: Duration,
    max_sessions: usize,
}

impl SessionStore {
    pub fn new(session_timeout: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            session_timeout,
            max_sessions,
        }
    }

    /// Get or create a session. Returns the session ID.
    ///
    /// If `client_session_id` is provided and the session exists, it's reused.
    /// Otherwise a new session is created. Session IDs are always server-generated
    /// to prevent session fixation attacks.
    pub fn get_or_create(&self, client_session_id: Option<&str>) -> String {
        // Try to reuse existing session if client provided an ID
        if let Some(id) = client_session_id {
            if let Some(mut session) = self.sessions.get_mut(id) {
                if !session.is_expired(self.session_timeout) {
                    session.touch();
                    return id.to_string();
                }
                // Expired — drop and create new
                drop(session);
                self.sessions.remove(id);
            }
        }

        // Enforce max sessions
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
            .retain(|_, session| !session.is_expired(self.session_timeout));
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
        assert_eq!(
            session.protocol_version.as_deref(),
            Some("2025-11-25")
        );
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
        };
        let b = ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
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
}
