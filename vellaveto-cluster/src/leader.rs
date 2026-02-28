// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

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
///
/// # Lifecycle
///
/// ```text
/// try_acquire() --> is_leader()=true --> renew() (periodic) --> release()
///       |                                     |
///       v                                     v
///  Err => is_leader()=false             Err => lost leadership
/// ```
#[async_trait]
pub trait LeaderElection: Send + Sync {
    /// Attempt to acquire the leader lease.
    ///
    /// Returns `Ok(true)` if this instance became the leader, `Ok(false)` if
    /// another instance holds the lease. Returns `Err` if the backend is
    /// unreachable (fail-closed: caller must not assume leadership).
    async fn try_acquire(&self) -> Result<bool, ClusterError>;

    /// Renew the leader lease. Must already be the leader.
    ///
    /// Returns `Ok(true)` if renewal succeeded, `Ok(false)` if the lease was
    /// lost (e.g., expired before renewal). Returns `Err` on backend failure.
    /// On `Err` or `Ok(false)`, the caller should stop performing leader duties.
    async fn renew(&self) -> Result<bool, ClusterError>;

    /// Release the leader lease voluntarily (e.g., during graceful shutdown).
    ///
    /// After release, `is_leader()` returns `false`. Other instances can
    /// immediately acquire the lease without waiting for expiry.
    async fn release(&self) -> Result<(), ClusterError>;

    /// Check if this instance currently holds the leader lease.
    ///
    /// This is a local, non-blocking check (no network call). Returns the
    /// cached leadership state; use `renew()` to refresh from the backend.
    fn is_leader(&self) -> bool;

    /// Get the current leader election status with metadata.
    ///
    /// Returns `LeaderStatus::Leader { since }` when this instance is leader,
    /// or `LeaderStatus::Follower { leader_id }` when it is not.
    fn current_status(&self) -> LeaderStatus;

    /// Get the current leader's instance ID, if known.
    ///
    /// Returns `Some(id)` when the leader identity is known (including self),
    /// or `None` if no leader has been elected or the information is stale.
    fn current_leader_id(&self) -> Option<String>;
}
