//! Leader election trait (Phase 27.2).
//!
//! Provides an abstraction for leader election with pluggable backends.
//! The `LocalLeaderElection` implementation (always-leader) is the default
//! for single-instance deployments. Kubernetes Lease-based election
//! is a future feature-gated addition.

use async_trait::async_trait;
use vellaveto_types::LeaderStatus;

use crate::ClusterError;

/// Trait for leader election implementations.
///
/// Implementations must be `Send + Sync` for use behind `Arc<dyn LeaderElection>`.
///
/// **Fail-closed contract:** If the backend is unreachable, `try_acquire` and
/// `renew` return `Err`, and `is_leader` returns `false`.
#[async_trait]
pub trait LeaderElection: Send + Sync {
    /// Attempt to acquire the leader lease.
    /// Returns `true` if this instance became the leader.
    async fn try_acquire(&self) -> Result<bool, ClusterError>;

    /// Renew the leader lease (must already be leader).
    /// Returns `true` if renewal succeeded.
    async fn renew(&self) -> Result<bool, ClusterError>;

    /// Release the leader lease voluntarily (graceful shutdown).
    async fn release(&self) -> Result<(), ClusterError>;

    /// Check if this instance currently holds the leader lease.
    /// This is a local check (no network call).
    fn is_leader(&self) -> bool;

    /// Get the current leader election status.
    fn current_status(&self) -> LeaderStatus;

    /// Get the current leader's instance ID, if known.
    fn current_leader_id(&self) -> Option<String>;
}
