//! Benchmark: Audit logging throughput measurement.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example audit_throughput_benchmark

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use std::time::Instant;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        println!("Audit Throughput Benchmark");
        println!("=========================");
        println!();

        // === Write throughput ===
        let tmp = tempfile::TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("bench_audit.log"));

        let action = Action {
            tool: "benchmark".to_string(),
            function: "measure".to_string(),
            parameters: json!({"iteration": 0}),
        };

        let counts = [100, 500, 1000, 5000];

        println!("{:<15} {:>15} {:>15} {:>15}",
            "Entries", "Write Total", "Write/entry", "Entries/sec");
        println!("{}", "-".repeat(60));

        for &count in &counts {
            let tmp_inner = tempfile::TempDir::new().unwrap();
            let logger_inner = AuditLogger::new(tmp_inner.path().join("audit.log"));

            let start = Instant::now();
            for i in 0..count {
                let verdict = match i % 3 {
                    0 => Verdict::Allow,
                    1 => Verdict::Deny { reason: format!("reason_{}", i) },
                    _ => Verdict::RequireApproval { reason: format!("review_{}", i) },
                };
                logger_inner.log_entry(&action, &verdict, json!({"i": i})).await.unwrap();
            }
            let write_dur = start.elapsed();
            let per_entry = write_dur / count as u32;
            let entries_per_sec = count as f64 / write_dur.as_secs_f64();

            println!("{:<15} {:>15.2?} {:>15.2?} {:>15.0}",
                count, write_dur, per_entry, entries_per_sec);
        }

        println!();
        println!("=== Read & Report Throughput ===");
        println!();

        // Write 1000 entries then measure read/report
        let tmp_read = tempfile::TempDir::new().unwrap();
        let logger_read = AuditLogger::new(tmp_read.path().join("audit.log"));

        for i in 0..1000 {
            let verdict = match i % 3 {
                0 => Verdict::Allow,
                1 => Verdict::Deny { reason: "d".into() },
                _ => Verdict::RequireApproval { reason: "r".into() },
            };
            logger_read.log_entry(&action, &verdict, json!({})).await.unwrap();
        }

        // Measure load_entries
        let start = Instant::now();
        for _ in 0..100 {
            let _ = logger_read.load_entries().await.unwrap();
        }
        let load_dur = start.elapsed();
        println!("load_entries (1000 entries) x100: {:?} ({:?}/call)", load_dur, load_dur / 100);

        // Measure generate_report
        let start = Instant::now();
        for _ in 0..100 {
            let _ = logger_read.generate_report().await.unwrap();
        }
        let report_dur = start.elapsed();
        println!("generate_report (1000 entries) x100: {:?} ({:?}/call)", report_dur, report_dur / 100);

        println!();

        // Verify report correctness after benchmark
        let report = logger_read.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 1000);
        println!("Report verification: {} entries, {} allow, {} deny, {} approval",
            report.total_entries, report.allow_count, report.deny_count, report.require_approval_count);
    });
}