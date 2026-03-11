// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Local (in-process) cluster backend.
//!
//! Delegates all operations to the existing `ApprovalStore` and in-process
//! rate limiters. This is the default backend when clustering is disabled,
//! preserving single-instance behavior exactly.

use async_trait::async_trait;
use std::sync::Arc;
use vellaveto_approval::{ApprovalContainmentContext, ApprovalStore};

use crate::{ClusterBackend, ClusterError};

/// Local backend that delegates to in-process state.
///
/// This wraps the existing `ApprovalStore` (unchanged) and provides a no-op
/// rate limiter (rate limiting remains process-local via the existing governor
/// rate limiters in `vellaveto-server`).
pub struct LocalBackend {
    approvals: Arc<ApprovalStore>,
}

impl LocalBackend {
    /// Create a new local backend wrapping an existing `ApprovalStore`.
    pub fn new(approvals: Arc<ApprovalStore>) -> Self {
        Self { approvals }
    }
}

#[async_trait]
impl ClusterBackend for LocalBackend {
    async fn approval_create_with_context(
        &self,
        action: vellaveto_types::Action,
        reason: String,
        requested_by: Option<String>,
        session_id: Option<String>,
        action_fingerprint: Option<String>,
        containment_context: Option<ApprovalContainmentContext>,
    ) -> Result<String, ClusterError> {
        Ok(self
            .approvals
            .create_with_context(
                action,
                reason,
                requested_by,
                session_id,
                action_fingerprint,
                containment_context,
            )
            .await?)
    }

    async fn approval_get(
        &self,
        id: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ClusterError> {
        Ok(self.approvals.get(id).await?)
    }

    async fn approval_approve(
        &self,
        id: &str,
        by: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ClusterError> {
        Ok(self.approvals.approve(id, by).await?)
    }

    async fn approval_consume_approved(
        &self,
        id: &str,
        session_id: Option<&str>,
        action_fingerprint: Option<&str>,
    ) -> Result<bool, ClusterError> {
        Ok(self
            .approvals
            .consume_approved(id, session_id, action_fingerprint)
            .await?)
    }

    async fn approval_deny(
        &self,
        id: &str,
        by: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ClusterError> {
        Ok(self.approvals.deny(id, by).await?)
    }

    async fn approval_list_pending(
        &self,
    ) -> Result<Vec<vellaveto_approval::PendingApproval>, ClusterError> {
        Ok(self.approvals.list_pending().await)
    }

    async fn approval_pending_count(&self) -> Result<usize, ClusterError> {
        Ok(self.approvals.pending_count().await)
    }

    async fn approval_expire_stale(&self) -> Result<usize, ClusterError> {
        Ok(self.approvals.expire_stale().await)
    }

    async fn rate_limit_check(
        &self,
        _category: &str,
        _key: &str,
        _rps: u32,
        _burst: u32,
    ) -> Result<bool, ClusterError> {
        // Rate limiting is handled process-locally by the existing governor
        // rate limiters in vellaveto-server. The local backend always returns
        // "allowed" and defers to the caller's own rate limiter.
        Ok(true)
    }

    async fn health_check(&self) -> Result<(), ClusterError> {
        // Local backend is always healthy — it's in-process memory.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vellaveto_approval::ApprovalStatus;
    use vellaveto_types::Action;

    fn make_store() -> Arc<ApprovalStore> {
        let dir = tempfile::tempdir().expect("create temp dir");
        // Leak the TempDir to prevent cleanup during test (store holds the path).
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);
        Arc::new(ApprovalStore::new(
            path.join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        ))
    }

    fn test_action() -> Action {
        Action::new(
            "file_system".to_string(),
            "read_file".to_string(),
            json!({"path": "/tmp/test.txt"}),
        )
    }

    #[tokio::test]
    async fn test_local_backend_new_creates_backend() {
        let store = make_store();
        let backend = LocalBackend::new(store);
        // Health check should always succeed for local backend.
        assert!(backend.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_local_backend_health_check_always_ok() {
        let store = make_store();
        let backend = LocalBackend::new(store);
        let result = backend.health_check().await;
        assert!(
            result.is_ok(),
            "Local backend health check should always succeed"
        );
    }

    #[tokio::test]
    async fn test_local_backend_rate_limit_check_always_allows() {
        let store = make_store();
        let backend = LocalBackend::new(store);
        // The local backend defers rate limiting to the caller's governor.
        let allowed = backend
            .rate_limit_check("per_ip", "192.168.1.1", 100, 200)
            .await
            .unwrap();
        assert!(
            allowed,
            "Local backend rate_limit_check should always return true"
        );
    }

    #[tokio::test]
    async fn test_local_backend_rate_limit_check_ignores_parameters() {
        let store = make_store();
        let backend = LocalBackend::new(store);
        // Even with extreme parameters, local backend always allows.
        let allowed = backend
            .rate_limit_check("per_principal", "admin@example.com", 0, 0)
            .await
            .unwrap();
        assert!(allowed);
    }

    #[tokio::test]
    async fn test_local_backend_approval_create_and_get() {
        let store = make_store();
        let backend = LocalBackend::new(store);

        let id = backend
            .approval_create(test_action(), "needs review".to_string(), None, None, None)
            .await
            .unwrap();
        assert!(!id.is_empty());

        let approval = backend.approval_get(&id).await.unwrap();
        assert_eq!(approval.status, ApprovalStatus::Pending);
        assert_eq!(approval.reason, "needs review");
    }

    #[tokio::test]
    async fn test_local_backend_approval_approve_delegates() {
        let store = make_store();
        let backend = LocalBackend::new(store);

        let id = backend
            .approval_create(test_action(), "review this".to_string(), None, None, None)
            .await
            .unwrap();

        let approved = backend.approval_approve(&id, "admin").await.unwrap();
        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(approved.resolved_by.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn test_local_backend_approval_deny_delegates() {
        let store = make_store();
        let backend = LocalBackend::new(store);

        let id = backend
            .approval_create(test_action(), "deny this".to_string(), None, None, None)
            .await
            .unwrap();

        let denied = backend.approval_deny(&id, "security-team").await.unwrap();
        assert_eq!(denied.status, ApprovalStatus::Denied);
        assert_eq!(denied.resolved_by.as_deref(), Some("security-team"));
    }

    #[tokio::test]
    async fn test_local_backend_approval_consume_approved_delegates() {
        let store = make_store();
        let backend = LocalBackend::new(store.clone());

        let action = test_action();
        let fingerprint = "a".repeat(64);
        let id = backend
            .approval_create(
                action,
                "review this".to_string(),
                None,
                None,
                Some(fingerprint.clone()),
            )
            .await
            .unwrap();
        backend.approval_approve(&id, "admin").await.unwrap();

        assert!(backend
            .approval_consume_approved(&id, None, Some(fingerprint.as_str()))
            .await
            .unwrap());
        assert_eq!(
            store.get(&id).await.unwrap().status,
            ApprovalStatus::Consumed
        );
    }

    #[tokio::test]
    async fn test_local_backend_approval_get_not_found_returns_error() {
        let store = make_store();
        let backend = LocalBackend::new(store);

        let result = backend.approval_get("nonexistent-id").await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ClusterError::NotFound(_)),
            "Should return NotFound error for missing approval"
        );
    }

    #[tokio::test]
    async fn test_local_backend_approval_list_pending() {
        let store = make_store();
        let backend = LocalBackend::new(store);

        backend
            .approval_create(test_action(), "first".to_string(), None, None, None)
            .await
            .unwrap();
        backend
            .approval_create(test_action(), "second".to_string(), None, None, None)
            .await
            .unwrap();

        let pending = backend.approval_list_pending().await.unwrap();
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn test_local_backend_approval_pending_count() {
        let store = make_store();
        let backend = LocalBackend::new(store);

        assert_eq!(backend.approval_pending_count().await.unwrap(), 0);

        backend
            .approval_create(test_action(), "test".to_string(), None, None, None)
            .await
            .unwrap();

        assert_eq!(backend.approval_pending_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_local_backend_approval_expire_stale() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);
        // TTL of 0 seconds: immediately expires
        let store = Arc::new(ApprovalStore::new(
            path.join("approvals.jsonl"),
            std::time::Duration::from_secs(0),
        ));
        let backend = LocalBackend::new(store);

        backend
            .approval_create(test_action(), "will expire".to_string(), None, None, None)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let expired_count = backend.approval_expire_stale().await.unwrap();
        assert_eq!(expired_count, 1);

        let pending = backend.approval_list_pending().await.unwrap();
        assert!(pending.is_empty(), "No pending approvals after expiry");
    }

    #[tokio::test]
    async fn test_local_backend_double_approve_returns_error() {
        let store = make_store();
        let backend = LocalBackend::new(store);

        let id = backend
            .approval_create(test_action(), "test".to_string(), None, None, None)
            .await
            .unwrap();

        backend.approval_approve(&id, "admin").await.unwrap();
        let result = backend.approval_approve(&id, "admin2").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClusterError::AlreadyResolved(_)
        ));
    }
}
