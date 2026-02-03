//! Tests report generation with unusual verdict distributions:
//! all-same-type, alternating, single entry, exactly-one-of-each.
//! Verifies the arithmetic invariant holds across all patterns.

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

fn action() -> Action {
    Action::new("report_test".to_string(), "verify".to_string(), json!({}))
}

/// Verify the invariant: total == allow + deny + require_approval
macro_rules! assert_report_invariant {
    ($report:expr) => {
        assert_eq!(
            $report.total_entries,
            $report.allow_count + $report.deny_count + $report.require_approval_count,
            "Invariant violated: {} != {} + {} + {}",
            $report.total_entries,
            $report.allow_count,
            $report.deny_count,
            $report.require_approval_count
        );
        assert_eq!(
            $report.entries.len(),
            $report.total_entries,
            "entries.len() != total_entries"
        );
    };
}

#[test]
fn report_all_allows() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();
        for _ in 0..20 {
            logger
                .log_entry(&a, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 20);
        assert_eq!(report.allow_count, 20);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert_report_invariant!(report);
    });
}

#[test]
fn report_all_denies() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();
        for i in 0..15 {
            let v = Verdict::Deny {
                reason: format!("reason_{}", i),
            };
            logger.log_entry(&a, &v, json!({})).await.unwrap();
        }
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 15);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 15);
        assert_eq!(report.require_approval_count, 0);
        assert_report_invariant!(report);
    });
}

#[test]
fn report_all_require_approval() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();
        for i in 0..10 {
            let v = Verdict::RequireApproval {
                reason: format!("approval_{}", i),
            };
            logger.log_entry(&a, &v, json!({})).await.unwrap();
        }
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 10);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 10);
        assert_report_invariant!(report);
    });
}

#[test]
fn report_single_entry_each_type() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();

        logger
            .log_entry(&a, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(
                &a,
                &Verdict::Deny {
                    reason: "no".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
        logger
            .log_entry(
                &a,
                &Verdict::RequireApproval {
                    reason: "check".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 1);
        assert_report_invariant!(report);
    });
}

#[test]
fn report_alternating_verdict_types() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();

        let verdicts = [
            Verdict::Allow,
            Verdict::Deny {
                reason: "d".to_string(),
            },
            Verdict::RequireApproval {
                reason: "r".to_string(),
            },
        ];

        // Log 30 entries cycling through verdict types
        for i in 0..30 {
            logger
                .log_entry(&a, &verdicts[i % 3], json!({"cycle": i}))
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 30);
        assert_eq!(report.allow_count, 10);
        assert_eq!(report.deny_count, 10);
        assert_eq!(report.require_approval_count, 10);
        assert_report_invariant!(report);
    });
}

#[test]
fn report_single_allow_entry() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        logger
            .log_entry(&action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert_report_invariant!(report);
    });
}

#[test]
fn report_empty_log() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert_eq!(report.entries.len(), 0);
        assert_report_invariant!(report);
    });
}

/// Heavily skewed distribution: 1000 allows, 1 deny, 1 approval.
#[test]
fn report_heavily_skewed_distribution() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let a = action();

        for _ in 0..1000 {
            logger
                .log_entry(&a, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger
            .log_entry(
                &a,
                &Verdict::Deny {
                    reason: "rare".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
        logger
            .log_entry(
                &a,
                &Verdict::RequireApproval {
                    reason: "rare".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1002);
        assert_eq!(report.allow_count, 1000);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 1);
        assert_report_invariant!(report);
    });
}
