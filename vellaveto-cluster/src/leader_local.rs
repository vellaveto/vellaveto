//! Local (single-instance) leader election implementation (Phase 27.2).
//!
//! In standalone mode, this instance is always the leader.
//! All operations succeed immediately with no network calls.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use vellaveto_types::LeaderStatus;

use crate::leader::LeaderElection;
use crate::ClusterError;

/// Local leader election: the single instance is always the leader.
pub struct LocalLeaderElection {
    instance_id: String,
    is_leader: AtomicBool,
    acquired_at: std::sync::Mutex<Option<String>>,
}

impl LocalLeaderElection {
    /// Create a new local leader election for the given instance ID.
    pub fn new(instance_id: String) -> Self {
        Self {
            instance_id,
            is_leader: AtomicBool::new(false),
            acquired_at: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait]
impl LeaderElection for LocalLeaderElection {
    async fn try_acquire(&self) -> Result<bool, ClusterError> {
        self.is_leader.store(true, Ordering::SeqCst);
        let now = chrono::Utc::now().to_rfc3339();
        if let Ok(mut guard) = self.acquired_at.lock() {
            *guard = Some(now);
        }
        Ok(true)
    }

    async fn renew(&self) -> Result<bool, ClusterError> {
        // Local leader always succeeds renewal
        Ok(self.is_leader.load(Ordering::SeqCst))
    }

    async fn release(&self) -> Result<(), ClusterError> {
        self.is_leader.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = self.acquired_at.lock() {
            *guard = None;
        }
        Ok(())
    }

    fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::SeqCst)
    }

    fn current_status(&self) -> LeaderStatus {
        if self.is_leader.load(Ordering::SeqCst) {
            let since = self
                .acquired_at
                .lock()
                .ok()
                .and_then(|g| g.clone())
                .unwrap_or_default();
            LeaderStatus::Leader { since }
        } else {
            LeaderStatus::Follower {
                leader_id: Some(self.instance_id.clone()),
            }
        }
    }

    fn current_leader_id(&self) -> Option<String> {
        Some(self.instance_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_leader_acquire() {
        let le = LocalLeaderElection::new("test-0".to_string());
        assert!(!le.is_leader());

        let acquired = le.try_acquire().await.unwrap();
        assert!(acquired);
        assert!(le.is_leader());
    }

    #[tokio::test]
    async fn test_local_leader_renew() {
        let le = LocalLeaderElection::new("test-0".to_string());
        le.try_acquire().await.unwrap();
        let renewed = le.renew().await.unwrap();
        assert!(renewed);
        assert!(le.is_leader());
    }

    #[tokio::test]
    async fn test_local_leader_release() {
        let le = LocalLeaderElection::new("test-0".to_string());
        le.try_acquire().await.unwrap();
        assert!(le.is_leader());

        le.release().await.unwrap();
        assert!(!le.is_leader());
    }

    #[tokio::test]
    async fn test_local_leader_status_leader() {
        let le = LocalLeaderElection::new("test-0".to_string());
        le.try_acquire().await.unwrap();

        let status = le.current_status();
        match status {
            LeaderStatus::Leader { since } => {
                assert!(!since.is_empty());
            }
            _ => panic!("expected Leader status"),
        }
    }

    #[tokio::test]
    async fn test_local_leader_status_follower() {
        let le = LocalLeaderElection::new("test-0".to_string());
        let status = le.current_status();
        match status {
            LeaderStatus::Follower { leader_id } => {
                assert_eq!(leader_id, Some("test-0".to_string()));
            }
            _ => panic!("expected Follower status"),
        }
    }

    #[tokio::test]
    async fn test_local_leader_current_leader_id() {
        let le = LocalLeaderElection::new("node-1".to_string());
        assert_eq!(le.current_leader_id(), Some("node-1".to_string()));
    }

    #[tokio::test]
    async fn test_local_leader_renew_before_acquire_returns_false() {
        let le = LocalLeaderElection::new("test-0".to_string());
        let renewed = le.renew().await.unwrap();
        assert!(!renewed);
    }

    #[tokio::test]
    async fn test_local_leader_acquire_release_acquire() {
        let le = LocalLeaderElection::new("test-0".to_string());
        le.try_acquire().await.unwrap();
        le.release().await.unwrap();
        assert!(!le.is_leader());

        le.try_acquire().await.unwrap();
        assert!(le.is_leader());
    }
}
