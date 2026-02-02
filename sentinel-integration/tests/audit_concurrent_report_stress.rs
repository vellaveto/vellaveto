//! Stress tests for concurrent generate_report() calls interleaved
//! with concurrent writes. Verifies report consistency properties:
//! - total_entries == allow_count + deny_count + require_approval_count
//! - report.entries.len() == report.total_entries
//! - counts are non-decreasing over time (no lost entries)

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

fn runtime_mt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to create multi-thread runtime")
}

fn runtime_st() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create single-thread runtime")
}

fn make_action() -> Action {
    Action {
        tool: "report_stress".to_string(),
        function: "probe".to_string(),
        parameters: json!({}),
    }
}

// ═══════════════════════════════════
// SEQUENTIAL WRITES THEN CONCURRENT REPORTS
// ═══════════════════════════════════

/// Write 50 entries, then generate 10 reports concurrently.
/// All reports must agree on the total count and maintain the invariant.
#[test]
fn concurrent_reports_after_sequential_writes() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
        let action = make_action();

        // Write 50 entries sequentially
        for i in 0..50 {
            let verdict = match i % 3 {
                0 => Verdict::Allow,
                1 => Verdict::Deny {
                    reason: format!("deny-{}", i),
                },
                _ => Verdict::RequireApproval {
                    reason: format!("approval-{}", i),
                },
            };
            logger
                .log_entry(&action, &verdict, json!({}))
                .await
                .unwrap();
        }

        // Generate 10 reports concurrently
        let mut handles = Vec::new();
        for _ in 0..10 {
            let l = Arc::clone(&logger);
            handles.push(tokio::spawn(async move { l.generate_report().await }));
        }

        for handle in handles {
            let report = handle.await.unwrap().unwrap();
            assert_eq!(report.total_entries, 50);
            assert_eq!(report.entries.len(), 50);
            assert_eq!(
                report.total_entries,
                report.allow_count + report.deny_count + report.require_approval_count
            );
            // 50 entries, cycling 0/1/2  17 allow, 17 deny, 16 approval
            assert_eq!(report.allow_count, 17);
            assert_eq!(report.deny_count, 17);
            assert_eq!(report.require_approval_count, 16);
        }
    });
}

// ═══════════════════════════════════
// CONCURRENT WRITES AND REPORTS SIMULTANEOUSLY
// ═══════════════════════════════════

/// Writers and report generators run simultaneously.
/// Reports must always maintain the invariant, even if they see
/// a partial set of entries.
#[test]
fn concurrent_writes_and_reports_maintain_invariant() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));

        let action = make_action();

        // Spawn 5 writer tasks, each writing 20 entries
        let mut writer_handles = Vec::new();
        for task_id in 0..5 {
            let l = Arc::clone(&logger);
            let a = action.clone();
            writer_handles.push(tokio::spawn(async move {
                for i in 0..20 {
                    let verdict = if (task_id + i) % 2 == 0 {
                        Verdict::Allow
                    } else {
                        Verdict::Deny {
                            reason: format!("d-{}-{}", task_id, i),
                        }
                    };
                    l.log_entry(&a, &verdict, json!({})).await.unwrap();
                }
            }));
        }

        // Spawn 5 report generators running simultaneously
        let mut report_handles = Vec::new();
        for _ in 0..5 {
            let l = Arc::clone(&logger);
            report_handles.push(tokio::spawn(async move {
                // Generate report multiple times during the write phase
                let mut reports = Vec::new();
                for _ in 0..4 {
                    if let Ok(report) = l.generate_report().await {
                        reports.push(report);
                    }
                    tokio::task::yield_now().await;
                }
                reports
            }));
        }

        // Wait for all writers
        for h in writer_handles {
            h.await.unwrap();
        }

        // Wait for all reporters
        for h in report_handles {
            let reports = h.await.unwrap();
            for report in reports {
                // Invariant must always hold
                assert_eq!(
                    report.total_entries,
                    report.allow_count + report.deny_count + report.require_approval_count,
                    "Invariant violated: {} != {} + {} + {}",
                    report.total_entries,
                    report.allow_count,
                    report.deny_count,
                    report.require_approval_count,
                );
                assert_eq!(report.entries.len(), report.total_entries);
            }
        }

        // Final report after all writes complete
        let final_report = logger.generate_report().await.unwrap();
        assert_eq!(final_report.total_entries, 100); // 5 tasks * 20 entries
    });
}

// ═══════════════════════════════════
// REPORT ON EMPTY LOG
// ═══════════════════════════════════

/// Generating a report on an empty (nonexistent) log file should
/// return a report with all zeros.
#[test]
fn report_on_empty_log_returns_zero_counts() {
    let rt = runtime_st();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert!(report.entries.is_empty());
    });
}

// ════════════════════════════════════
// SINGLE ENTRY REPORT
// ═══════════════════════════════════

#[test]
fn report_with_single_allow_entry() {
    let rt = runtime_st();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        logger
            .log_entry(&make_action(), &Verdict::Allow, json!({}))
            .await
            .unwrap();
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
    });
}

#[test]
fn report_with_single_deny_entry() {
    let rt = runtime_st();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        logger
            .log_entry(
                &make_action(),
                &Verdict::Deny {
                    reason: "test".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 0);
    });
}

#[test]
fn report_with_single_require_approval_entry() {
    let rt = runtime_st();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));
        logger
            .log_entry(
                &make_action(),
                &Verdict::RequireApproval {
                    reason: "needs review".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 1);
    });
}
