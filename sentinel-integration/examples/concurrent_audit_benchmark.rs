//! Benchmark: Measures audit logger throughput under multi-threaded contention.
//!
//! Run with:
//!
//!   export PATH=$HOME/.cargo/bin:$PATH && cargo run -p sentinel-integration --example concurrent_audit_benchmark

use sentinel_audit::AuditLogger;
use sentinel_types::{Action, Verdict};
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        println!("Concurrent Audit Logger Benchmark");
        println!("==================================");
        println!();

        let task_counts = [1, 2, 4, 8, 16];
        let entries_per_task = 500;

        println!(
            "{:<12} {:<12} {:>15} {:>15}",
            "Tasks", "Total Writes", "Duration", "Writes/sec"
        );
        println!("{}", "-".repeat(54));

        for &num_tasks in &task_counts {
            let tmp = tempfile::TempDir::new().unwrap();
            let logger = Arc::new(AuditLogger::new(tmp.path().join("bench.log")));

            let action = Action {
                tool: "bench".to_string(),
                function: "write".to_string(),
                parameters: json!({"task": 0}),
            };

            let start = Instant::now();
            let mut handles = Vec::new();

            for task_id in 0..num_tasks {
                let logger = Arc::clone(&logger);
                let action = action.clone();
                handles.push(tokio::spawn(async move {
                    for i in 0..entries_per_task {
                        let _ = logger
                            .log_entry(
                                &action,
                                &Verdict::Allow,
                                json!({"task": task_id, "entry": i}),
                            )
                            .await;
                    }
                }));
            }

            for h in handles {
                h.await.unwrap();
            }

            let elapsed = start.elapsed();
            let total_writes = num_tasks * entries_per_task;
            let writes_per_sec = total_writes as f64 / elapsed.as_secs_f64();

            println!(
                "{:<12} {:<12} {:>12.2?} {:>12.0}/s",
                num_tasks, total_writes, elapsed, writes_per_sec
            );
        }
    });
}
