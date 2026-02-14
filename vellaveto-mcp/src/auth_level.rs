//! Step-up authentication level tracking for MCP 2025-11-25.
//!
//! This module tracks authentication levels per session to support
//! step-up authentication policies. Sensitive operations can require
//! stronger authentication without blocking the entire session.
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::auth_level::AuthLevelTracker;
//! use vellaveto_types::AuthLevel;
//! use std::time::Duration;
//!
//! let tracker = AuthLevelTracker::new();
//!
//! // Check initial level
//! assert_eq!(tracker.get_level("session-1").await, AuthLevel::None);
//!
//! // Upgrade after successful MFA
//! tracker.upgrade("session-1", AuthLevel::OAuthMfa, Some(Duration::from_secs(1800))).await;
//!
//! // Now the level is elevated
//! assert_eq!(tracker.get_level("session-1").await, AuthLevel::OAuthMfa);
//! ```

use vellaveto_types::AuthLevel;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// State for a session's authentication level.
#[derive(Debug, Clone)]
struct AuthLevelState {
    /// Current authentication level.
    level: AuthLevel,
    /// When the elevated level was granted.
    granted_at: Instant,
    /// When the elevated level expires (if set).
    expires_at: Option<Instant>,
}

impl Default for AuthLevelState {
    fn default() -> Self {
        Self {
            level: AuthLevel::None,
            granted_at: Instant::now(),
            expires_at: None,
        }
    }
}

/// Tracks authentication levels per session.
///
/// Thread-safe via `RwLock` for concurrent access from multiple
/// request handlers.
#[derive(Debug)]
pub struct AuthLevelTracker {
    sessions: RwLock<HashMap<String, AuthLevelState>>,
    /// Default expiry duration for step-up auth. None = no expiry.
    default_expiry: Option<Duration>,
}

/// Initial capacity for tracked auth sessions.
const INITIAL_AUTH_SESSION_CAPACITY: usize = 256;

impl AuthLevelTracker {
    /// Create a new auth level tracker with no default expiry.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::with_capacity(INITIAL_AUTH_SESSION_CAPACITY)),
            default_expiry: None,
        }
    }

    /// Create a new auth level tracker with a default expiry duration.
    pub fn with_default_expiry(expiry: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::with_capacity(INITIAL_AUTH_SESSION_CAPACITY)),
            default_expiry: Some(expiry),
        }
    }

    /// Create a shareable reference to this tracker.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Get the current authentication level for a session.
    ///
    /// Returns `AuthLevel::None` if the session is not tracked or
    /// if the elevated level has expired.
    pub async fn get_level(&self, session_id: &str) -> AuthLevel {
        let sessions = self.sessions.read().await;

        match sessions.get(session_id) {
            Some(state) => {
                // Check if expired
                if let Some(expires_at) = state.expires_at {
                    if Instant::now() > expires_at {
                        return AuthLevel::None;
                    }
                }
                state.level
            }
            None => AuthLevel::None,
        }
    }

    /// Upgrade a session's authentication level.
    ///
    /// # Arguments
    /// * `session_id` - The session to upgrade
    /// * `level` - The new authentication level
    /// * `expires` - Optional expiry duration. If None, uses default expiry.
    pub async fn upgrade(&self, session_id: &str, level: AuthLevel, expires: Option<Duration>) {
        let mut sessions = self.sessions.write().await;

        let expires_at = expires.or(self.default_expiry).map(|d| Instant::now() + d);

        sessions.insert(
            session_id.to_string(),
            AuthLevelState {
                level,
                granted_at: Instant::now(),
                expires_at,
            },
        );
    }

    /// Check if a session requires step-up authentication.
    ///
    /// Returns `true` if the current level is below the required level.
    pub async fn requires_step_up(&self, session_id: &str, required: AuthLevel) -> bool {
        let current = self.get_level(session_id).await;
        !current.satisfies(required)
    }

    /// Downgrade or remove a session's authentication level.
    pub async fn downgrade(&self, session_id: &str, level: AuthLevel) {
        let mut sessions = self.sessions.write().await;

        if level == AuthLevel::None {
            sessions.remove(session_id);
        } else if let Some(state) = sessions.get_mut(session_id) {
            state.level = level;
        }
    }

    /// Remove a session from tracking.
    pub async fn remove(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }

    /// Clean up expired sessions.
    ///
    /// Returns the number of sessions that were removed.
    pub async fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;

        let old_len = sessions.len();
        sessions.retain(|_, state| {
            match state.expires_at {
                Some(expires_at) => now < expires_at,
                None => true, // Keep sessions with no expiry
            }
        });

        old_len - sessions.len()
    }

    /// Get the number of tracked sessions.
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Get session info for debugging/metrics.
    pub async fn get_session_info(&self, session_id: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;

        sessions.get(session_id).map(|state| {
            let now = Instant::now();
            let remaining = state
                .expires_at
                .map(|e| e.saturating_duration_since(now))
                .filter(|d| *d > Duration::ZERO);

            SessionInfo {
                level: state.level,
                age: now.duration_since(state.granted_at),
                expires_in: remaining,
            }
        })
    }
}

impl Default for AuthLevelTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a tracked session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Current authentication level.
    pub level: AuthLevel,
    /// Time since the level was granted.
    pub age: Duration,
    /// Time until the level expires (None if already expired or no expiry).
    pub expires_in: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_level_default_none() {
        let tracker = AuthLevelTracker::new();
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::None);
    }

    #[tokio::test]
    async fn test_upgrade_level() {
        let tracker = AuthLevelTracker::new();

        tracker.upgrade("session-1", AuthLevel::OAuth, None).await;
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::OAuth);

        tracker
            .upgrade("session-1", AuthLevel::OAuthMfa, None)
            .await;
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::OAuthMfa);
    }

    #[tokio::test]
    async fn test_requires_step_up() {
        let tracker = AuthLevelTracker::new();

        // No auth requires step-up for anything above None
        assert!(
            tracker
                .requires_step_up("session-1", AuthLevel::Basic)
                .await
        );
        assert!(
            tracker
                .requires_step_up("session-1", AuthLevel::OAuth)
                .await
        );

        // Upgrade to OAuth
        tracker.upgrade("session-1", AuthLevel::OAuth, None).await;

        // No longer requires step-up for OAuth or below
        assert!(
            !tracker
                .requires_step_up("session-1", AuthLevel::Basic)
                .await
        );
        assert!(
            !tracker
                .requires_step_up("session-1", AuthLevel::OAuth)
                .await
        );

        // Still requires step-up for OAuthMfa
        assert!(
            tracker
                .requires_step_up("session-1", AuthLevel::OAuthMfa)
                .await
        );
    }

    #[tokio::test]
    async fn test_downgrade_level() {
        let tracker = AuthLevelTracker::new();

        tracker
            .upgrade("session-1", AuthLevel::OAuthMfa, None)
            .await;
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::OAuthMfa);

        tracker.downgrade("session-1", AuthLevel::Basic).await;
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::Basic);

        tracker.downgrade("session-1", AuthLevel::None).await;
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::None);
    }

    #[tokio::test]
    async fn test_remove_session() {
        let tracker = AuthLevelTracker::new();

        tracker.upgrade("session-1", AuthLevel::OAuth, None).await;
        assert_eq!(tracker.session_count().await, 1);

        tracker.remove("session-1").await;
        assert_eq!(tracker.session_count().await, 0);
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::None);
    }

    #[tokio::test]
    async fn test_expiry() {
        let tracker = AuthLevelTracker::new();

        // Upgrade with very short expiry
        tracker
            .upgrade(
                "session-1",
                AuthLevel::OAuth,
                Some(Duration::from_millis(10)),
            )
            .await;
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::OAuth);

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Level should now be None due to expiry
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::None);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let tracker = AuthLevelTracker::new();

        // Add sessions with different expiries
        tracker
            .upgrade(
                "session-1",
                AuthLevel::OAuth,
                Some(Duration::from_millis(10)),
            )
            .await;
        tracker.upgrade("session-2", AuthLevel::OAuth, None).await; // No expiry

        // Wait for session-1 to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Cleanup
        let removed = tracker.cleanup_expired().await;
        assert_eq!(removed, 1);
        assert_eq!(tracker.session_count().await, 1);
    }

    #[tokio::test]
    async fn test_default_expiry() {
        let tracker = AuthLevelTracker::with_default_expiry(Duration::from_millis(10));

        tracker.upgrade("session-1", AuthLevel::OAuth, None).await;
        assert_eq!(tracker.get_level("session-1").await, AuthLevel::OAuth);

        // Wait for default expiry
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(tracker.get_level("session-1").await, AuthLevel::None);
    }

    #[tokio::test]
    async fn test_session_info() {
        let tracker = AuthLevelTracker::new();

        tracker
            .upgrade("session-1", AuthLevel::OAuth, Some(Duration::from_secs(60)))
            .await;

        let info = tracker.get_session_info("session-1").await.unwrap();
        assert_eq!(info.level, AuthLevel::OAuth);
        assert!(info.expires_in.is_some());
        assert!(info.expires_in.unwrap() < Duration::from_secs(60));
    }
}
