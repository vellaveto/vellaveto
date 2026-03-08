// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! End-to-end integration tests for the approval workflow.
//!
//! Tests the full flow: RequireApproval verdict → ApprovalStore → approve/deny/expire → persist.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_approval::{ApprovalStatus, ApprovalStore};
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn approval_policy() -> Policy {
    Policy {
        id: "bash:*".to_string(),
        name: "Bash requires approval".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"require_approval": true}),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

fn bash_action() -> Action {
    Action::new(
        "bash".to_string(),
        "execute".to_string(),
        json!({"cmd": "ls -la"}),
    )
}

// ═══════════════════════════════════════
// BASIC APPROVAL LIFECYCLE
// ═══════════════════════════════════════

#[test]
fn engine_produces_require_approval_verdict() {
    let engine = PolicyEngine::new(false);
    let policies = [approval_policy()];
    let verdict = engine.evaluate_action(&bash_action(), &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::RequireApproval { .. }),
        "Bash actions should require approval, got: {verdict:?}"
    );
}

#[test]
fn create_and_approve_pending_approval() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Create pending approval
        let id = store
            .create(
                bash_action(),
                "Bash requires approval".to_string(),
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // Verify it appears in pending list
        let pending = store.list_pending().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].status, ApprovalStatus::Pending);

        // Approve it
        let approved = store.approve(&id, "admin").await.unwrap();
        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(approved.resolved_by, Some("admin".to_string()));
        assert!(approved.resolved_at.is_some());

        // Pending list should now be empty
        let pending = store.list_pending().await;
        assert!(pending.is_empty());
    });
}

#[test]
fn create_and_deny_pending_approval() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(
                bash_action(),
                "Bash requires approval".to_string(),
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let denied = store.deny(&id, "security-team").await.unwrap();
        assert_eq!(denied.status, ApprovalStatus::Denied);
        assert_eq!(denied.resolved_by, Some("security-team".to_string()));

        // Should be gone from pending list
        let pending = store.list_pending().await;
        assert!(pending.is_empty());
    });
}

#[test]
fn double_approve_fails() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(bash_action(), "test".to_string(), None, None, None)
            .await
            .unwrap();

        // First approve succeeds
        store.approve(&id, "admin").await.unwrap();

        // Second approve fails
        let result = store.approve(&id, "admin2").await;
        assert!(
            result.is_err(),
            "Double approve should fail, got: {result:?}"
        );
    });
}

// ═══════════════════════════════════════
// EXPIRY
// ═══════════════════════════════════════

#[test]
fn stale_approvals_expire() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        // Use very short TTL so it expires immediately
        let store = ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_millis(1),
        );

        let id = store
            .create(bash_action(), "will expire".to_string(), None, None, None)
            .await
            .unwrap();

        // Wait for expiry
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // expire_stale should mark it
        let expired_count = store.expire_stale().await;
        assert_eq!(expired_count, 1, "One approval should have expired");

        // Pending list should be empty
        let pending = store.list_pending().await;
        assert!(pending.is_empty());

        // Trying to approve an expired one should fail
        let result = store.approve(&id, "admin").await;
        assert!(result.is_err(), "Approving an expired entry should fail");
    });
}

// ═══════════════════════════════════════
// PERSISTENCE
// ═══════════════════════════════════════

#[test]
fn approvals_persist_to_file() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("approvals.jsonl");
        let store = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(900));

        // Create and approve
        let id = store
            .create(bash_action(), "persist test".to_string(), None, None, None)
            .await
            .unwrap();
        store.approve(&id, "admin").await.unwrap();

        // Read the log file directly
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        assert!(!content.is_empty(), "Log file should have content");

        // Each line should be valid JSON
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("Invalid JSON in log: {e}: {line}"));
            // Should have an id field
            assert!(parsed.get("id").is_some(), "Entry should have id field");
        }
    });
}

// ═══════════════════════════════════════
// FULL ENGINE → APPROVAL PIPELINE
// ═══════════════════════════════════════

#[test]
fn engine_verdict_drives_approval_creation() {
    let rt = runtime();
    rt.block_on(async {
        let engine = PolicyEngine::new(false);
        let policies = [approval_policy()];
        let action = bash_action();

        let tmp = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Engine evaluates action
        let verdict = engine.evaluate_action(&action, &policies).unwrap();

        // If RequireApproval, create pending approval
        if let Verdict::RequireApproval { reason } = &verdict {
            let id = store
                .create(action.clone(), reason.clone(), None, None, None)
                .await
                .unwrap();
            let approval = store.get(&id).await.unwrap();
            assert_eq!(approval.action.tool, "bash");
            assert_eq!(approval.status, ApprovalStatus::Pending);
        } else {
            panic!("Expected RequireApproval, got: {verdict:?}");
        }
    });
}

#[test]
fn multiple_approvals_tracked_independently() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Create three pending approvals
        let id1 = store
            .create(bash_action(), "first".to_string(), None, None, None)
            .await
            .unwrap();
        let id2 = store
            .create(bash_action(), "second".to_string(), None, None, None)
            .await
            .unwrap();
        let id3 = store
            .create(bash_action(), "third".to_string(), None, None, None)
            .await
            .unwrap();

        assert_eq!(store.list_pending().await.len(), 3);

        // Approve first, deny second, leave third pending
        store.approve(&id1, "admin").await.unwrap();
        store.deny(&id2, "admin").await.unwrap();

        // Only third should be pending
        let pending = store.list_pending().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id3);

        // Verify each has the correct status
        let a1 = store.get(&id1).await.unwrap();
        let a2 = store.get(&id2).await.unwrap();
        let a3 = store.get(&id3).await.unwrap();
        assert_eq!(a1.status, ApprovalStatus::Approved);
        assert_eq!(a2.status, ApprovalStatus::Denied);
        assert_eq!(a3.status, ApprovalStatus::Pending);
    });
}
