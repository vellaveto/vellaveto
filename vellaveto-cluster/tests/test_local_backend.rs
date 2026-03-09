// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests for the LocalBackend cluster implementation.
//!
//! Verifies that the LocalBackend correctly delegates all operations
//! to the underlying ApprovalStore while conforming to the ClusterBackend
//! trait contract.

use std::sync::Arc;
use tempfile::TempDir;
use vellaveto_approval::ApprovalStore;
use vellaveto_cluster::local::LocalBackend;
use vellaveto_cluster::ClusterBackend;
use vellaveto_types::Action;

/// Helper: create a LocalBackend with a temporary persistence file.
fn make_backend() -> (Arc<dyn ClusterBackend>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("approvals.jsonl");
    let store = Arc::new(ApprovalStore::new(
        path,
        std::time::Duration::from_secs(900),
    ));
    let backend: Arc<dyn ClusterBackend> = Arc::new(LocalBackend::new(store));
    (backend, tmp)
}

fn make_action() -> Action {
    Action::new(
        "test-tool",
        "test-function",
        serde_json::json!({"key": "value"}),
    )
}

#[tokio::test]
async fn test_create_and_get_approval() {
    let (backend, _tmp) = make_backend();

    let id = backend
        .approval_create(make_action(), "needs review".to_string(), None, None, None)
        .await
        .expect("create should succeed");

    assert!(!id.is_empty());

    let approval = backend.approval_get(&id).await.expect("get should succeed");

    assert_eq!(approval.id, id);
    assert_eq!(approval.reason, "needs review");
    assert!(matches!(
        approval.status,
        vellaveto_approval::ApprovalStatus::Pending
    ));
}

#[tokio::test]
async fn test_approve_approval() {
    let (backend, _tmp) = make_backend();

    let id = backend
        .approval_create(make_action(), "needs review".to_string(), None, None, None)
        .await
        .unwrap();

    let approval = backend
        .approval_approve(&id, "admin")
        .await
        .expect("approve should succeed");

    assert!(matches!(
        approval.status,
        vellaveto_approval::ApprovalStatus::Approved
    ));
}

#[tokio::test]
async fn test_deny_approval() {
    let (backend, _tmp) = make_backend();

    let id = backend
        .approval_create(make_action(), "needs review".to_string(), None, None, None)
        .await
        .unwrap();

    let approval = backend
        .approval_deny(&id, "admin")
        .await
        .expect("deny should succeed");

    assert!(matches!(
        approval.status,
        vellaveto_approval::ApprovalStatus::Denied
    ));
}

#[tokio::test]
async fn test_approve_nonexistent_returns_not_found() {
    let (backend, _tmp) = make_backend();

    let result = backend.approval_approve("nonexistent-id", "admin").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, vellaveto_cluster::ClusterError::NotFound(_)));
}

#[tokio::test]
async fn test_deny_nonexistent_returns_not_found() {
    let (backend, _tmp) = make_backend();

    let result = backend.approval_deny("nonexistent-id", "admin").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, vellaveto_cluster::ClusterError::NotFound(_)));
}

#[tokio::test]
async fn test_double_approve_returns_already_resolved() {
    let (backend, _tmp) = make_backend();

    let id = backend
        .approval_create(make_action(), "needs review".to_string(), None, None, None)
        .await
        .unwrap();

    backend.approval_approve(&id, "admin").await.unwrap();

    let result = backend.approval_approve(&id, "admin2").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        vellaveto_cluster::ClusterError::AlreadyResolved(_)
    ));
}

#[tokio::test]
async fn test_list_pending_approvals() {
    let (backend, _tmp) = make_backend();

    // Initially empty
    let pending = backend
        .approval_list_pending()
        .await
        .expect("list should succeed");
    assert!(pending.is_empty());

    // Create two approvals
    backend
        .approval_create(make_action(), "reason 1".to_string(), None, None, None)
        .await
        .unwrap();
    let id2 = backend
        .approval_create(
            Action::new("tool2", "func2", serde_json::json!({})),
            "reason 2".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let pending = backend.approval_list_pending().await.unwrap();
    assert_eq!(pending.len(), 2);

    // Resolve one
    backend.approval_approve(&id2, "admin").await.unwrap();
    let pending = backend.approval_list_pending().await.unwrap();
    assert_eq!(pending.len(), 1);
}

#[tokio::test]
async fn test_pending_count() {
    let (backend, _tmp) = make_backend();

    assert_eq!(backend.approval_pending_count().await.unwrap(), 0);

    backend
        .approval_create(make_action(), "reason".to_string(), None, None, None)
        .await
        .unwrap();

    assert_eq!(backend.approval_pending_count().await.unwrap(), 1);
}

#[tokio::test]
async fn test_rate_limit_check_always_allows() {
    let (backend, _tmp) = make_backend();

    // LocalBackend always returns true (defers to process-local governor)
    let allowed = backend
        .rate_limit_check("per_ip", "127.0.0.1", 10, 20)
        .await
        .unwrap();
    assert!(allowed);
}

#[tokio::test]
async fn test_health_check_always_ok() {
    let (backend, _tmp) = make_backend();

    backend
        .health_check()
        .await
        .expect("health check should always succeed for local backend");
}

#[tokio::test]
async fn test_expire_stale_approvals() {
    // Create a store with a very short TTL so approvals expire quickly
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("approvals.jsonl");
    let store = Arc::new(ApprovalStore::new(
        path,
        std::time::Duration::from_millis(1), // 1ms TTL
    ));
    let backend: Arc<dyn ClusterBackend> = Arc::new(LocalBackend::new(store));

    backend
        .approval_create(make_action(), "expiring".to_string(), None, None, None)
        .await
        .unwrap();

    // Wait for the approval to expire
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let expired = backend.approval_expire_stale().await.unwrap();
    assert_eq!(expired, 1);

    // After expiry, pending count should be 0
    assert_eq!(backend.approval_pending_count().await.unwrap(), 0);
}

#[tokio::test]
async fn test_self_approval_prevention() {
    let (backend, _tmp) = make_backend();

    // Create an approval with a known requester
    let id = backend
        .approval_create(
            make_action(),
            "needs review".to_string(),
            Some("alice".to_string()),
            None,
            None,
        )
        .await
        .unwrap();

    // The same person should not be able to approve their own request
    let result = backend.approval_approve(&id, "alice").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        vellaveto_cluster::ClusterError::Validation(_)
    ));

    // A different person should be able to approve
    let approval = backend
        .approval_approve(&id, "bob")
        .await
        .expect("different user should be able to approve");
    assert!(matches!(
        approval.status,
        vellaveto_approval::ApprovalStatus::Approved
    ));
}

#[tokio::test]
async fn test_deduplication() {
    let (backend, _tmp) = make_backend();

    // Create the same approval twice — should return the same ID (dedup)
    let action = make_action();
    let id1 = backend
        .approval_create(action.clone(), "reason".to_string(), None, None, None)
        .await
        .unwrap();
    let id2 = backend
        .approval_create(action, "reason".to_string(), None, None, None)
        .await
        .unwrap();

    assert_eq!(id1, id2, "duplicate approval should return same ID");
}

// ── R254: Consume-approved flow tests ────────────────────────────────

#[tokio::test]
async fn test_consume_approved_succeeds() {
    let (backend, _tmp) = make_backend();
    let action = make_action();
    let fingerprint = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";

    let id = backend
        .approval_create(
            action,
            "needs review".to_string(),
            Some("requester".to_string()),
            Some("sess-1".to_string()),
            Some(fingerprint.to_string()),
        )
        .await
        .unwrap();

    // Approve with a different user
    backend.approval_approve(&id, "admin").await.unwrap();

    // Consume should succeed with matching fingerprint and session
    let consumed = backend
        .approval_consume_approved(&id, Some("sess-1"), Some(fingerprint))
        .await
        .expect("consume should succeed");
    assert!(consumed, "approved approval should be consumable");
}

#[tokio::test]
async fn test_consume_approved_wrong_fingerprint_fails() {
    let (backend, _tmp) = make_backend();
    let id = backend
        .approval_create(
            make_action(),
            "reason".to_string(),
            Some("requester".to_string()),
            None,
            Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6abcd".to_string()),
        )
        .await
        .unwrap();

    backend.approval_approve(&id, "admin").await.unwrap();

    let consumed = backend
        .approval_consume_approved(
            &id,
            None,
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        )
        .await
        .expect("should return Ok(false) for wrong fingerprint");
    assert!(!consumed, "wrong fingerprint should not consume");
}

#[tokio::test]
async fn test_consume_approved_not_approved_fails() {
    let (backend, _tmp) = make_backend();
    let id = backend
        .approval_create(
            make_action(),
            "reason".to_string(),
            None,
            None,
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()),
        )
        .await
        .unwrap();

    // Don't approve — try to consume a Pending approval
    let consumed = backend
        .approval_consume_approved(
            &id,
            None,
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        )
        .await
        .expect("should return Ok(false) for non-Approved");
    assert!(!consumed, "pending approval should not be consumable");
}

#[tokio::test]
async fn test_consume_approved_double_consume_fails() {
    let (backend, _tmp) = make_backend();
    let id = backend
        .approval_create(
            make_action(),
            "reason".to_string(),
            Some("req".to_string()),
            None,
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()),
        )
        .await
        .unwrap();

    backend.approval_approve(&id, "admin").await.unwrap();

    // First consume succeeds
    let first = backend
        .approval_consume_approved(
            &id,
            None,
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        )
        .await
        .unwrap();
    assert!(first);

    // Second consume must fail (already consumed)
    let second = backend
        .approval_consume_approved(
            &id,
            None,
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        )
        .await
        .unwrap();
    assert!(!second, "double-consume must be prevented");
}

#[tokio::test]
async fn test_consume_approved_dedup_cleared() {
    let (backend, _tmp) = make_backend();
    let action = make_action();

    let id = backend
        .approval_create(
            action.clone(),
            "reason".to_string(),
            Some("req".to_string()),
            None,
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()),
        )
        .await
        .unwrap();

    backend.approval_approve(&id, "admin").await.unwrap();
    let consumed = backend
        .approval_consume_approved(
            &id,
            None,
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        )
        .await
        .unwrap();
    assert!(consumed);

    // After consumption, creating the same approval again should get a NEW id
    // (not the consumed one), proving dedup entry was cleaned up.
    let id2 = backend
        .approval_create(
            action,
            "reason".to_string(),
            Some("req".to_string()),
            None,
            Some("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string()),
        )
        .await
        .unwrap();

    assert_ne!(id, id2, "consumed approval dedup entry should be cleared");
}
