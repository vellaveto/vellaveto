//! Integration tests for the LocalBackend cluster implementation.
//!
//! Verifies that the LocalBackend correctly delegates all operations
//! to the underlying ApprovalStore while conforming to the ClusterBackend
//! trait contract.

use sentinel_approval::ApprovalStore;
use sentinel_cluster::local::LocalBackend;
use sentinel_cluster::ClusterBackend;
use sentinel_types::Action;
use std::sync::Arc;
use tempfile::TempDir;

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
        .approval_create(make_action(), "needs review".to_string(), None)
        .await
        .expect("create should succeed");

    assert!(!id.is_empty());

    let approval = backend.approval_get(&id).await.expect("get should succeed");

    assert_eq!(approval.id, id);
    assert_eq!(approval.reason, "needs review");
    assert!(matches!(
        approval.status,
        sentinel_approval::ApprovalStatus::Pending
    ));
}

#[tokio::test]
async fn test_approve_approval() {
    let (backend, _tmp) = make_backend();

    let id = backend
        .approval_create(make_action(), "needs review".to_string(), None)
        .await
        .unwrap();

    let approval = backend
        .approval_approve(&id, "admin")
        .await
        .expect("approve should succeed");

    assert!(matches!(
        approval.status,
        sentinel_approval::ApprovalStatus::Approved { .. }
    ));
}

#[tokio::test]
async fn test_deny_approval() {
    let (backend, _tmp) = make_backend();

    let id = backend
        .approval_create(make_action(), "needs review".to_string(), None)
        .await
        .unwrap();

    let approval = backend
        .approval_deny(&id, "admin")
        .await
        .expect("deny should succeed");

    assert!(matches!(
        approval.status,
        sentinel_approval::ApprovalStatus::Denied { .. }
    ));
}

#[tokio::test]
async fn test_approve_nonexistent_returns_not_found() {
    let (backend, _tmp) = make_backend();

    let result = backend.approval_approve("nonexistent-id", "admin").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, sentinel_cluster::ClusterError::NotFound(_)));
}

#[tokio::test]
async fn test_deny_nonexistent_returns_not_found() {
    let (backend, _tmp) = make_backend();

    let result = backend.approval_deny("nonexistent-id", "admin").await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, sentinel_cluster::ClusterError::NotFound(_)));
}

#[tokio::test]
async fn test_double_approve_returns_already_resolved() {
    let (backend, _tmp) = make_backend();

    let id = backend
        .approval_create(make_action(), "needs review".to_string(), None)
        .await
        .unwrap();

    backend.approval_approve(&id, "admin").await.unwrap();

    let result = backend.approval_approve(&id, "admin2").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        sentinel_cluster::ClusterError::AlreadyResolved(_)
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
        .approval_create(make_action(), "reason 1".to_string(), None)
        .await
        .unwrap();
    let id2 = backend
        .approval_create(
            Action::new("tool2", "func2", serde_json::json!({})),
            "reason 2".to_string(),
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
        .approval_create(make_action(), "reason".to_string(), None)
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
        .approval_create(make_action(), "expiring".to_string(), None)
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
        )
        .await
        .unwrap();

    // The same person should not be able to approve their own request
    let result = backend.approval_approve(&id, "alice").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, sentinel_cluster::ClusterError::Validation(_)));

    // A different person should be able to approve
    let approval = backend
        .approval_approve(&id, "bob")
        .await
        .expect("different user should be able to approve");
    assert!(matches!(
        approval.status,
        sentinel_approval::ApprovalStatus::Approved { .. }
    ));
}

#[tokio::test]
async fn test_deduplication() {
    let (backend, _tmp) = make_backend();

    // Create the same approval twice — should return the same ID (dedup)
    let action = make_action();
    let id1 = backend
        .approval_create(action.clone(), "reason".to_string(), None)
        .await
        .unwrap();
    let id2 = backend
        .approval_create(action, "reason".to_string(), None)
        .await
        .unwrap();

    assert_eq!(id1, id2, "duplicate approval should return same ID");
}
