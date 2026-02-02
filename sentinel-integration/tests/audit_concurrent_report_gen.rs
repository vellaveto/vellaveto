//! Tests concurrent generate_report() calls while writes are happening.
//! Existing concurrent tests focus on write integrity; these focus on
//! whether concurrent report generation produces consistent results.

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
        tool: "report_gen_test".to_string(),
        function: "probe".to_string(),
        parameters: json!({}),
    }
}

// ════════════════════════════════
// SEQUENTIAL WRITES THEN CONCURRENT REPORTS
// ═══════════════════════════════

/// Write 100 entries, then generate 10 reports concurrently.
/// All reports must agree on counts.
#[test]
fn concurrent_reports_after_sequential_writes_agree() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
        let action = make_action();

        // Write 100 entries: 40 Allow, 35 Deny, 25 RequireApproval
        for i in 0..100u32 {
            let verdict = match i % 20 {
                0..=7 => Verdict::Allow,
                8..=14 => Verdict::Deny { reason: format!("deny-{}", i) },
                _ => Verdict::RequireApproval { reason: format!("approval-{}", i) },
            };
            logger.log_entry(&action, &verdict, json!({"i": i})).await.unwrap();
        }

        // Generate 10 reports concurrently
        let mut handles = Vec::new();
        for _ in 0..10 {
            let lg = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                lg.generate_report().await.unwrap()
            }));
        }

        let mut reports = Vec::new();
        for handle in handles {
            reports.push(handle.await.unwrap());
        }

        // All reports must agree
        for report in &reports {
            assert_eq!(report.total_entries, 100,
                "Report should have 100 entries, got {}", report.total_entries);
            assert_eq!(
                report.total_entries,
                report.allow_count + report.deny_count + report.require_approval_count,
                "Arithmetic invariant violated"
            );
            // All reports should have identical counts
            assert_eq!(report.allow_count, reports[0].allow_count);
            assert_eq!(report.deny_count, reports[0].deny_count);
            assert_eq!(report.require_approval_count, reports[0].require_approval_count);
        }
    });
}

// ══════════════════════════════════
// EMPTY LOG: CONCURRENT REPORTS
// ═════════════════════════════════

/// Generate multiple reports concurrently on an empty log file.
/// All should return total_entries == 0.
#[test]
fn concurrent_reports_on_empty_log() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let lg = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                lg.generate_report().await.unwrap()
            }));
        }

        for handle in handles {
            let report = handle.await.unwrap();
            assert_eq!(report.total_entries, 0);
            assert_eq!(report.allow_count, 0);
            assert_eq!(report.deny_count, 0);
            assert_eq!(report.require_approval_count, 0);
        }
    });
}

// ═════════════════════════════════════════
// SINGLE ENTRY: CONCURRENT REPORTS
// ══════════════════════════════════════════

/// Write one entry, then generate reports concurrently.
#[test]
fn concurrent_reports_with_single_entry() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
        logger.log_entry(&make_action(), &Verdict::Deny { reason: "test".to_string() }, json!({}))
            .await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let lg = Arc::clone(&logger);
            handles.push(tokio::spawn(async move {
                lg.generate_report().await.unwrap()
            }));
        }

        for handle in handles {
            let report = handle.await.unwrap();
            assert_eq!(report.total_entries, 1);
            assert_eq!(report.deny_count, 1);
            assert_eq!(report.allow_count, 0);
            assert_eq!(report.require_approval_count, 0);
        }
    });
}

// ══════════════════════════════════════════
// WRITES AND REPORTS INTERLEAVED
// ══════════════════════════════════════════

/// Start writers and report generators at the same time.
/// Reports should never have inconsistent arithmetic (total != sum).
#[test]
fn interleaved_writes_and_report_generation() {
    let rt = runtime_mt();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
        let action = make_action();

        // Spawn 5 writers (10 entries each)
        let mut handles = Vec::new();
        for w in 0..5u32 {
            let lg = Arc::clone(&logger);
            let a = action.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..10u32 {
                    let verdict = if (w + i) % 2 == 0 {
                        Verdict::Allow
                    } else {
                        Verdict::Deny { reason: format!("w{}-i{}", w, i) }
                    };
                    lg.log_entry(&a, &verdict, json!({})).await.unwrap();
                }
            }));
        }

        // Spawn 5 report generators
        let mut report_handles = Vec::new();
        for _ in 0..5 {
            let lg = Arc::clone(&logger);
            report_handles.push(tokio::spawn(async move {
                // Generate report multiple times
                let mut reports = Vec::new();
                for _ in 0..3 {
                    match lg.generate_report().await {
                        Ok(report) => reports.push(report),
                        Err(_) => {} // Concurrent read during write might fail; that's acceptable
                    }
                    tokio::task::yield_now().await;
                }
                reports
            }));
        }

        // Wait for all writers
        for handle in handles {
            handle.await.unwrap();
        }

        // Wait for all report generators
        for handle in report_handles {
            let reports = handle.await.unwrap();
            for report in reports {
                // Arithmetic invariant must ALWAYS hold
                assert_eq!(
                    report.total_entries,
                    report.allow_count + report.deny_count + report.require_approval_count,
                    "Invariant violated: {} != {} + {} + {}",
                    report.total_entries, report.allow_count,
                    report.deny_count, report.require_approval_count
                );
                assert_eq!(report.entries.len(), report.total_entries);
            }
        }
    });
}