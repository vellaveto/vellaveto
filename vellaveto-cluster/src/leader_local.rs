//! Local (single-instance) leader election implementation (Phase 27.2).
//!
//! In standalone mode, this instance is always the leader.
//! All operations succeed immediately with no network calls.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use vellaveto_types::LeaderStatus;

use crate::leader::LeaderElection;
use crate::ClusterError;

/// Local leader election for standalone (single-instance) deployments.
///
/// In local mode, `try_acquire()` always succeeds and `is_leader()` always
/// returns `true` once acquired. This is the default implementation used
/// when deployment mode is `Standalone`. No network calls are made; all
/// operations complete synchronously via in-memory state.
///
/// SECURITY (FIND-R46-009): Uses `std::sync::Mutex` (not `tokio::sync::Mutex`)
/// intentionally. The critical section is trivially short (one `Option<String>`
/// read/write), never awaits, and never performs I/O. `std::sync::Mutex` is
/// cheaper than `tokio::sync::Mutex` for these non-async, sub-microsecond
/// operations and avoids the overhead of the async mutex's waker queue.
/// Mutex poisoning is explicitly handled in all lock sites (see FIND-P27-003).
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
        // SECURITY (FIND-P27-003): Propagate mutex poisoning instead of silently swallowing.
        let now = chrono::Utc::now().to_rfc3339();
        let mut guard = self
            .acquired_at
            .lock()
            .map_err(|e| ClusterError::Backend(format!("Leader election mutex poisoned: {}", e)))?;
        // SECURITY (FIND-R44-044): Set timestamp BEFORE setting AtomicBool to true.
        // This ensures observers always see a valid timestamp when is_leader() returns true.
        *guard = Some(now);
        self.is_leader.store(true, Ordering::SeqCst);
        Ok(true)
    }

    async fn renew(&self) -> Result<bool, ClusterError> {
        // Local leader always succeeds renewal
        Ok(self.is_leader.load(Ordering::SeqCst))
    }

    async fn release(&self) -> Result<(), ClusterError> {
        // SECURITY (FIND-P27-003): Propagate mutex poisoning.
        let mut guard = self
            .acquired_at
            .lock()
            .map_err(|e| ClusterError::Backend(format!("Leader election mutex poisoned: {}", e)))?;
        // SECURITY (FIND-R44-044): Set AtomicBool to false BEFORE clearing the timestamp.
        // This ensures observers never see is_leader()=true with a None timestamp.
        self.is_leader.store(false, Ordering::SeqCst);
        *guard = None;
        Ok(())
    }

    fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::SeqCst)
    }

    fn current_status(&self) -> LeaderStatus {
        if self.is_leader.load(Ordering::SeqCst) {
            // SECURITY (FIND-P27-003): Log mutex poisoning instead of silently defaulting.
            let since = match self.acquired_at.lock() {
                Ok(guard) => guard.clone().unwrap_or_default(),
                Err(e) => {
                    tracing::error!("Leader election acquired_at mutex poisoned: {}", e);
                    "unknown (mutex poisoned)".to_string()
                }
            };
            LeaderStatus::Leader { since }
        } else {
            // DESIGN NOTE (FIND-R111-004): In a true distributed leader election,
            // `leader_id` in the Follower state would be the ID of the current
            // cluster leader (obtained from the coordination backend). For
            // `LocalLeaderElection`, which is only used in standalone (single-node)
            // mode, there is no external coordination backend. Before `try_acquire()`
            // is called the instance has not yet designated itself as leader, so
            // the semantically correct value would be `None`. However, the
            // standalone node IS the only node in the cluster and will always
            // become the leader once `try_acquire()` is called. Reporting
            // `Some(self.instance_id)` gives operators useful context (which
            // instance is involved) when the status is queried before acquisition.
            // Callers that need to distinguish "leadership not yet acquired" from
            // "leadership held by another" should inspect the `LeaderStatus` variant
            // rather than the inner `leader_id` value.
            LeaderStatus::Follower {
                leader_id: Some(self.instance_id.clone()),
            }
        }
    }

    fn current_leader_id(&self) -> Option<String> {
        // DESIGN NOTE (FIND-R111-004): In standalone mode this node is always
        // the only member of the "cluster", so it is the authoritative leader
        // candidate regardless of whether `try_acquire()` has been called.
        // Returning `Some(instance_id)` is consistent with `current_status()`
        // and allows callers to display the node's own identity even before
        // leadership has been formally acquired.
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

    // ─────────────────────────────────────────────────────────
    // FIND-R44-044: Verify AtomicBool/Mutex ordering consistency
    // ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_local_leader_acquire_sets_timestamp_before_flag() {
        // After try_acquire(), is_leader should be true AND current_status
        // should return a Leader variant with a non-empty timestamp.
        let le = LocalLeaderElection::new("test-0".to_string());
        le.try_acquire().await.unwrap();

        assert!(le.is_leader());
        match le.current_status() {
            LeaderStatus::Leader { since } => {
                assert!(
                    !since.is_empty(),
                    "timestamp should be set when is_leader is true"
                );
            }
            other => panic!("expected Leader status after acquire, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_local_leader_release_clears_flag_before_timestamp() {
        // After release(), is_leader should be false. Even if we peek at the
        // timestamp while is_leader is false, we should not see stale data
        // that suggests leadership.
        let le = LocalLeaderElection::new("test-0".to_string());
        le.try_acquire().await.unwrap();
        le.release().await.unwrap();

        assert!(!le.is_leader());
        match le.current_status() {
            LeaderStatus::Follower { .. } => {
                // Correct: after release, status is Follower
            }
            other => panic!("expected Follower status after release, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_local_leader_repeated_acquire_release_consistency() {
        let le = LocalLeaderElection::new("test-0".to_string());
        for _ in 0..10 {
            le.try_acquire().await.unwrap();
            assert!(le.is_leader());
            match le.current_status() {
                LeaderStatus::Leader { since } => {
                    assert!(!since.is_empty());
                }
                other => panic!("expected Leader, got {:?}", other),
            }

            le.release().await.unwrap();
            assert!(!le.is_leader());
            match le.current_status() {
                LeaderStatus::Follower { .. } => {}
                other => panic!("expected Follower, got {:?}", other),
            }
        }
    }
}
