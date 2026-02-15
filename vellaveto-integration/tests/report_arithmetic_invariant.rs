//! Verifies the arithmetic invariant:
//!   report.total_entries == report.allow_count + report.deny_count + report.require_approval_count
//! across varied verdict distributions. Also verifies report.entries.len() == report.total_entries.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action() -> Action {
    Action::new("invariant_test".to_string(), "check".to_string(), json!({}))
}

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

/// Helper: log a specific distribution of verdicts and verify the invariant.
async fn verify_invariant(allows: usize, denies: usize, approvals: usize) {
    let (logger, _tmp) = setup_logger();
    let action = make_action();

    for _ in 0..allows {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    for i in 0..denies {
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: format!("deny_{}", i),
                },
                json!({}),
            )
            .await
            .unwrap();
    }
    for i in 0..approvals {
        logger
            .log_entry(
                &action,
                &Verdict::RequireApproval {
                    reason: format!("approval_{}", i),
                },
                json!({}),
            )
            .await
            .unwrap();
    }

    let report = logger.generate_report().await.unwrap();
    let expected_total = allows + denies + approvals;

    assert_eq!(
        report.total_entries, expected_total,
        "total_entries mismatch: expected {} ({}+{}+{}), got {}",
        expected_total, allows, denies, approvals, report.total_entries
    );
    assert_eq!(report.allow_count, allows, "allow_count mismatch");
    assert_eq!(report.deny_count, denies, "deny_count mismatch");
    assert_eq!(
        report.require_approval_count, approvals,
        "require_approval_count mismatch"
    );

    // Structural invariant: entries vec length matches total
    assert_eq!(
        report.entries.len(),
        report.total_entries,
        "entries.len() should equal total_entries"
    );

    // Arithmetic invariant
    assert_eq!(
        report.total_entries,
        report.allow_count + report.deny_count + report.require_approval_count,
        "total_entries != allow + deny + require_approval"
    );
}

#[test]
fn invariant_all_allows() {
    runtime().block_on(verify_invariant(10, 0, 0));
}

#[test]
fn invariant_all_denies() {
    runtime().block_on(verify_invariant(0, 10, 0));
}

#[test]
fn invariant_all_approvals() {
    runtime().block_on(verify_invariant(0, 0, 10));
}

#[test]
fn invariant_mixed_distribution() {
    runtime().block_on(verify_invariant(5, 3, 2));
}

#[test]
fn invariant_empty_log() {
    runtime().block_on(verify_invariant(0, 0, 0));
}

#[test]
fn invariant_single_entry_each() {
    runtime().block_on(verify_invariant(1, 1, 1));
}

#[test]
fn invariant_heavily_skewed_allows() {
    runtime().block_on(verify_invariant(100, 1, 0));
}

#[test]
fn invariant_heavily_skewed_denies() {
    runtime().block_on(verify_invariant(0, 100, 1));
}

#[test]
fn invariant_large_mixed() {
    runtime().block_on(verify_invariant(50, 30, 20));
}
