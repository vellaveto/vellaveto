// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Distributed state backend for Vellaveto clustering.
//!
//! Provides a `ClusterBackend` trait with two implementations:
//! - `LocalBackend`: delegates to in-process `ApprovalStore` (default, zero overhead)
//! - `RedisBackend`: stores shared state in Redis (requires `redis-backend` feature)
//!
//! When clustering is disabled or unconfigured, `LocalBackend` preserves existing
//! single-instance behavior exactly.

pub mod local;
#[cfg(feature = "redis-backend")]
pub mod redis_backend;

pub mod leader;
pub mod leader_local;

pub mod discovery;
pub mod discovery_dns;
pub mod discovery_static;

use async_trait::async_trait;
use thiserror::Error;
use vellaveto_approval::PendingApproval;

/// Errors from cluster backend operations.
///
/// All operations return `Result<_, ClusterError>` so callers can fail-closed
/// (deny) when the backend is unreachable. No `unwrap()` in library code.
#[derive(Error, Debug)]
pub enum ClusterError {
    /// Approval not found in the backend store.
    #[error("Approval not found: {0}")]
    NotFound(String),

    /// Approval already resolved (approved/consumed/denied/expired).
    #[error("Approval already resolved: {0}")]
    AlreadyResolved(String),

    /// Approval has expired past its TTL.
    #[error("Approval expired: {0}")]
    Expired(String),

    /// Approval store at capacity.
    #[error("Approval store at capacity ({0} max pending)")]
    CapacityExceeded(usize),

    /// Input validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Backend connection error (Redis unavailable, etc.).
    #[error("Backend connection error: {0}")]
    Connection(String),

    /// Serialization / deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Generic backend error.
    #[error("Backend error: {0}")]
    Backend(String),
}

impl From<vellaveto_approval::ApprovalError> for ClusterError {
    fn from(err: vellaveto_approval::ApprovalError) -> Self {
        match err {
            vellaveto_approval::ApprovalError::NotFound(id) => ClusterError::NotFound(id),
            vellaveto_approval::ApprovalError::AlreadyResolved(id) => {
                ClusterError::AlreadyResolved(id)
            }
            vellaveto_approval::ApprovalError::Expired(id) => ClusterError::Expired(id),
            vellaveto_approval::ApprovalError::CapacityExceeded(max) => {
                ClusterError::CapacityExceeded(max)
            }
            vellaveto_approval::ApprovalError::Validation(msg) => ClusterError::Validation(msg),
            vellaveto_approval::ApprovalError::Io(e) => {
                ClusterError::Backend(format!("IO error: {e}"))
            }
            vellaveto_approval::ApprovalError::Serialization(e) => {
                ClusterError::Serialization(e.to_string())
            }
        }
    }
}

/// Backend for distributed state sharing across Vellaveto instances.
///
/// Implementations must be `Send + Sync + 'static` for use in async contexts
/// behind `Arc<dyn ClusterBackend>`.
///
/// **Fail-closed contract:** If the backend is unreachable (e.g., Redis down),
/// all operations MUST return `Err(ClusterError::Connection(...))`. The caller
/// converts errors to `Deny` verdicts. We never silently fall back to local state.
#[async_trait]
pub trait ClusterBackend: Send + Sync {
    // --- Approvals ---

    /// Create a new pending approval. Returns the approval ID.
    /// If an identical pending approval already exists (dedup), returns its ID.
    async fn approval_create(
        &self,
        action: vellaveto_types::Action,
        reason: String,
        requested_by: Option<String>,
        session_id: Option<String>,
        action_fingerprint: Option<String>,
    ) -> Result<String, ClusterError>;

    /// Get an approval by ID.
    async fn approval_get(&self, id: &str) -> Result<PendingApproval, ClusterError>;

    /// Approve a pending approval. Returns the updated approval.
    async fn approval_approve(&self, id: &str, by: &str) -> Result<PendingApproval, ClusterError>;

    /// Consume an approved approval exactly once for a matching request scope.
    ///
    /// Returns `Ok(true)` when the approval was consumed, `Ok(false)` when the
    /// approval exists but is not usable for this request, and `Err` on backend
    /// or lookup failures.
    async fn approval_consume_approved(
        &self,
        id: &str,
        session_id: Option<&str>,
        action_fingerprint: Option<&str>,
    ) -> Result<bool, ClusterError>;

    /// Deny a pending approval. Returns the updated approval.
    async fn approval_deny(&self, id: &str, by: &str) -> Result<PendingApproval, ClusterError>;

    /// List all pending (unresolved) approvals.
    async fn approval_list_pending(&self) -> Result<Vec<PendingApproval>, ClusterError>;

    /// Count pending approvals without cloning all entries.
    async fn approval_pending_count(&self) -> Result<usize, ClusterError>;

    /// Expire stale approvals past their TTL. Returns the number expired.
    async fn approval_expire_stale(&self) -> Result<usize, ClusterError>;

    // --- Rate Limiting ---

    /// Check a rate limit for the given category and key.
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    ///
    /// - `category`: "per_ip" or "per_principal"
    /// - `key`: the IP address string or principal identifier
    /// - `rps`: sustained requests per second
    /// - `burst`: burst capacity
    async fn rate_limit_check(
        &self,
        category: &str,
        key: &str,
        rps: u32,
        burst: u32,
    ) -> Result<bool, ClusterError>;

    // --- Health ---

    /// Check backend health. Returns `Ok(())` if the backend is reachable
    /// and functional, `Err` otherwise.
    async fn health_check(&self) -> Result<(), ClusterError>;
}

/// Re-export `ClusterConfig` from `vellaveto-config` for convenience.
pub use vellaveto_config::ClusterConfig;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_config_reexport() {
        // Verify ClusterConfig is re-exported from vellaveto-config
        let cfg = ClusterConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.backend, "local");
        assert_eq!(cfg.redis_pool_size, 8);
        assert_eq!(cfg.key_prefix, "vellaveto:");
    }

    #[test]
    fn test_cluster_error_from_approval_error() {
        let err: ClusterError =
            vellaveto_approval::ApprovalError::NotFound("test-id".into()).into();
        assert!(matches!(err, ClusterError::NotFound(_)));

        let err: ClusterError =
            vellaveto_approval::ApprovalError::AlreadyResolved("test-id".into()).into();
        assert!(matches!(err, ClusterError::AlreadyResolved(_)));

        let err: ClusterError = vellaveto_approval::ApprovalError::Expired("test-id".into()).into();
        assert!(matches!(err, ClusterError::Expired(_)));

        let err: ClusterError = vellaveto_approval::ApprovalError::CapacityExceeded(100).into();
        assert!(matches!(err, ClusterError::CapacityExceeded(100)));

        let err: ClusterError = vellaveto_approval::ApprovalError::Validation("bad".into()).into();
        assert!(matches!(err, ClusterError::Validation(_)));
    }
}
