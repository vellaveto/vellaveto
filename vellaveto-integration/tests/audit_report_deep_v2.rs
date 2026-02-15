//! Deep tests for AuditReport generation: correctness, consistency,
//! and adversarial edge cases in report statistics.

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

fn setup_logger() -> (AuditLogger, TempDir) {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));
    (logger, tmp)
}

fn make_action(tool: &str, function: &str) -> Action {
    Action::new(tool.to_string(), function.to_string(), json!({}))
}

// ══════════════════════════════════════════
// TIMESTAMP PLAUSIBILITY
// ═══════════════════════════════════════════

#[test]
fn entries_have_plausible_rfc3339_timestamps() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("t", "f");

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        let ts = &entries[0].timestamp;
        assert!(ts.contains('T'), "timestamp should contain 'T': {}", ts);
        assert!(
            ts.len() >= 20,
            "timestamp should be at least 20 chars: {}",
            ts
        );
        assert!(
            ts.contains('+') || ts.contains('Z'),
            "timestamp should have timezone: {}",
            ts
        );
    });
}

// ═══════════════════════════════════════════
// REPORT COUNTS MUST EQUAL TOTAL
// ═══════════════════════════════════════════

#[test]
fn report_counts_sum_to_total() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("tool", "func");

        // Log a mix of all three verdict types
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "r1".into(),
                },
                json!({}),
            )
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::RequireApproval {
                    reason: "r2".into(),
                },
                json!({}),
            )
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "r3".into(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 5);
        assert_eq!(
            report.allow_count + report.deny_count + report.require_approval_count,
            report.total_entries,
            "Counts must sum to total: {} + {} + {} != {}",
            report.allow_count,
            report.deny_count,
            report.require_approval_count,
            report.total_entries
        );
        assert_eq!(report.allow_count, 2);
        assert_eq!(report.deny_count, 2);
        assert_eq!(report.require_approval_count, 1);
    });
}

// ════════════════════════════════════════════
// EMPTY REPORT
// ═══════════════════════════════════════════

#[test]
fn empty_log_produces_zero_count_report() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
        assert_eq!(report.require_approval_count, 0);
        assert!(report.entries.is_empty());
    });
}

// ═══════════════════════════════════════════
// REPORT ENTRIES MATCH LOADED ENTRIES
// ════════════════════════════════════════════

#[test]
fn report_entries_match_load_entries() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("x", "y");

        for i in 0..10 {
            let verdict = if i % 3 == 0 {
                Verdict::Allow
            } else if i % 3 == 1 {
                Verdict::Deny {
                    reason: format!("deny-{}", i),
                }
            } else {
                Verdict::RequireApproval {
                    reason: format!("approve-{}", i),
                }
            };
            logger
                .log_entry(&action, &verdict, json!({"i": i}))
                .await
                .unwrap();
        }

        let loaded = logger.load_entries().await.unwrap();
        let report = logger.generate_report().await.unwrap();

        assert_eq!(loaded.len(), report.entries.len());
        assert_eq!(loaded.len(), report.total_entries);

        // Verify IDs match in order
        for (l, r) in loaded.iter().zip(report.entries.iter()) {
            assert_eq!(l.id, r.id, "Entry IDs should match between load and report");
        }
    });
}

// ════════════════════════════════════════════
// ONLY-DENY REPORT
// ════════════════════════════════════════════

#[test]
fn report_with_only_deny_verdicts() {
    let rt = runtime();
    rt.block_on(async {
        let (logger, _tmp) = setup_logger();
        let action = make_action("t", "f");

        for i in 0..5 {
            logger
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: format!("reason-{}", i),
                    },
                    json!({}),
                )
                .await
                .unwrap();
        }

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 5);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 5);
        assert_eq!(report.require_approval_count, 0);
    });
}
