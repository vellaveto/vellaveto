// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Criterion benchmarks for audit logging and export throughput.
//!
//! Run with: `cargo bench -p vellaveto-audit --bench audit`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use serde_json::json;
use tempfile::TempDir;

use vellaveto_audit::{
    export::{to_cef, to_json_lines},
    redact_keys_and_patterns, AuditEntry, AuditLogger,
};
use vellaveto_types::{Action, Verdict};

fn make_test_action(idx: usize) -> Action {
    Action {
        tool: format!("test_tool_{}", idx % 10),
        function: format!("function_{}", idx % 5),
        parameters: json!({
            "path": format!("/tmp/test_{}.txt", idx),
            "content": "Hello, world!",
            "options": {"recursive": true, "verbose": false}
        }),
        target_paths: vec![format!("/tmp/test_{}.txt", idx)],
        target_domains: vec![],
        resolved_ips: vec![],
    }
}

fn make_test_entry(idx: usize) -> AuditEntry {
    AuditEntry {
        id: format!("entry-{idx}"),
        action: make_test_action(idx),
        verdict: if idx.is_multiple_of(3) {
            Verdict::Deny {
                reason: "Test denial".to_string(),
            }
        } else {
            Verdict::Allow
        },
        timestamp: "2026-02-08T12:00:00Z".to_string(),
        metadata: json!({"request_id": format!("req-{}", idx)}),
        sequence: idx as u64,
        entry_hash: Some(format!("hash_{idx}")),
        prev_hash: if idx > 0 {
            Some(format!("hash_{}", idx - 1))
        } else {
            None
        },
        commitment: None,
        tenant_id: None,
    }
}

fn bench_export_formats(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_export");

    let entry = make_test_entry(0);

    group.bench_function("to_cef_single", |b| b.iter(|| to_cef(black_box(&entry))));

    group.bench_function("to_json_lines_single", |b| {
        b.iter(|| to_json_lines(black_box(&entry)))
    });

    // Benchmark batch formatting
    let entries: Vec<AuditEntry> = (0..100).map(make_test_entry).collect();
    group.throughput(Throughput::Elements(100));

    group.bench_function("format_cef_100", |b| {
        b.iter(|| {
            let mut output = String::new();
            for entry in black_box(&entries) {
                output.push_str(&to_cef(entry));
                output.push('\n');
            }
            output
        })
    });

    group.bench_function("format_json_lines_100", |b| {
        b.iter(|| {
            let mut output = String::new();
            for entry in black_box(&entries) {
                output.push_str(&to_json_lines(entry));
                output.push('\n');
            }
            output
        })
    });

    group.finish();
}

fn bench_redaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_redaction");

    // Simple parameters - no sensitive data
    group.bench_function("redact_simple_clean", |b| {
        let params = json!({
            "path": "/tmp/test.txt",
            "content": "Hello, world!",
            "count": 42
        });
        b.iter(|| redact_keys_and_patterns(black_box(&params)))
    });

    // Parameters with sensitive keys
    group.bench_function("redact_sensitive_keys", |b| {
        let params = json!({
            "path": "/tmp/test.txt",
            "password": "super_secret_123",
            "api_key": "sk-1234567890abcdef",
            "auth_token": "Bearer xyz"
        });
        b.iter(|| redact_keys_and_patterns(black_box(&params)))
    });

    // Parameters with PII patterns (email, SSN-like, phone)
    group.bench_function("redact_pii_patterns", |b| {
        let params = json!({
            "user": "john.doe@example.com",
            "phone": "555-123-4567",
            "ssn": "123-45-6789",
            "content": "Contact us at support@company.org"
        });
        b.iter(|| redact_keys_and_patterns(black_box(&params)))
    });

    // Deeply nested structure
    group.bench_function("redact_deeply_nested", |b| {
        let params = json!({
            "config": {
                "database": {
                    "host": "localhost",
                    "credentials": {
                        "username": "admin",
                        "password": "hunter2",
                        "options": {
                            "ssl_key": "secret-key",
                            "ca_cert": "/path/to/ca.pem"
                        }
                    }
                },
                "api": {
                    "endpoint": "https://api.example.com",
                    "auth": {
                        "bearer_token": "eyJhbGciOiJIUzI1NiJ9.test",
                        "refresh_token": "rt_abc123"
                    }
                }
            }
        });
        b.iter(|| redact_keys_and_patterns(black_box(&params)))
    });

    // AWS key detection
    group.bench_function("redact_aws_key", |b| {
        let params = json!({
            "content": "Here is the key: AKIAIOSFODNN7EXAMPLE and secret: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        });
        b.iter(|| redact_keys_and_patterns(black_box(&params)))
    });

    group.finish();
}

fn bench_logging_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("audit_logging");

    // Benchmark single entry logging
    group.bench_function("log_single_entry", |b| {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = make_test_action(0);
        let verdict = Verdict::Allow;
        let metadata = json!({"request_id": "bench-1"});

        b.iter(|| {
            rt.block_on(async {
                logger
                    .log_entry(
                        black_box(&action),
                        black_box(&verdict),
                        black_box(metadata.clone()),
                    )
                    .await
                    .unwrap()
            })
        })
    });

    // Benchmark with redaction disabled
    group.bench_function("log_single_entry_no_redaction", |b| {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.jsonl");
        let logger = AuditLogger::new_unredacted(log_path);

        let action = make_test_action(0);
        let verdict = Verdict::Allow;
        let metadata = json!({"request_id": "bench-1"});

        b.iter(|| {
            rt.block_on(async {
                logger
                    .log_entry(
                        black_box(&action),
                        black_box(&verdict),
                        black_box(metadata.clone()),
                    )
                    .await
                    .unwrap()
            })
        })
    });

    // Benchmark with sensitive data requiring redaction
    group.bench_function("log_with_sensitive_data", |b| {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = Action {
            tool: "database".to_string(),
            function: "connect".to_string(),
            parameters: json!({
                "host": "localhost",
                "password": "super_secret",
                "api_key": "sk-123456",
                "user_email": "admin@example.com"
            }),
            target_paths: vec![],
            target_domains: vec!["localhost".to_string()],
            resolved_ips: vec!["127.0.0.1".to_string()],
        };
        let verdict = Verdict::Allow;
        let metadata = json!({"client_ip": "192.168.1.1"});

        b.iter(|| {
            rt.block_on(async {
                logger
                    .log_entry(
                        black_box(&action),
                        black_box(&verdict),
                        black_box(metadata.clone()),
                    )
                    .await
                    .unwrap()
            })
        })
    });

    // Benchmark chain verification (read-heavy)
    group.bench_function("verify_chain_100_entries", |b| {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        // Pre-populate with 100 entries
        rt.block_on(async {
            for i in 0..100 {
                let action = make_test_action(i);
                let verdict = Verdict::Allow;
                let metadata = json!({"i": i});
                logger.log_entry(&action, &verdict, metadata).await.unwrap();
            }
        });

        b.iter(|| rt.block_on(async { logger.verify_chain().await.unwrap() }))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmarks: Merkle tree operations (Phase D)
// ---------------------------------------------------------------------------

fn bench_merkle_append_leaf(c: &mut Criterion) {
    use vellaveto_audit::merkle::{hash_leaf, MerkleTree};

    let temp_dir = TempDir::new().unwrap();
    let leaf_path = temp_dir.path().join("merkle_append.bin");
    let mut tree = MerkleTree::new(leaf_path);

    let leaf_hash = hash_leaf(b"benchmark leaf data");

    c.bench_function("merkle/append_leaf", |b| {
        b.iter(|| {
            tree.append(black_box(leaf_hash)).unwrap();
        })
    });
}

fn bench_merkle_generate_proof_100_leaves(c: &mut Criterion) {
    use vellaveto_audit::merkle::{hash_leaf, MerkleTree};

    let temp_dir = TempDir::new().unwrap();
    let leaf_path = temp_dir.path().join("merkle_proof_100.bin");
    let mut tree = MerkleTree::new(leaf_path);

    // Pre-populate with 100 leaves
    for i in 0u64..100 {
        let leaf_hash = hash_leaf(&i.to_le_bytes());
        tree.append(leaf_hash).unwrap();
    }

    c.bench_function("merkle/generate_proof_100_leaves", |b| {
        b.iter(|| tree.generate_proof(black_box(50)).unwrap())
    });
}

fn bench_merkle_generate_proof_10000_leaves(c: &mut Criterion) {
    use vellaveto_audit::merkle::{hash_leaf, MerkleTree};

    let temp_dir = TempDir::new().unwrap();
    let leaf_path = temp_dir.path().join("merkle_proof_10000.bin");
    let mut tree = MerkleTree::new(leaf_path);

    // Pre-populate with 10,000 leaves
    for i in 0u64..10_000 {
        let leaf_hash = hash_leaf(&i.to_le_bytes());
        tree.append(leaf_hash).unwrap();
    }

    c.bench_function("merkle/generate_proof_10000_leaves", |b| {
        b.iter(|| tree.generate_proof(black_box(5_000)).unwrap())
    });
}

fn bench_merkle_verify_proof(c: &mut Criterion) {
    use vellaveto_audit::merkle::{hash_leaf, MerkleTree};

    let temp_dir = TempDir::new().unwrap();
    let leaf_path = temp_dir.path().join("merkle_verify.bin");
    let mut tree = MerkleTree::new(leaf_path);

    // Pre-populate with 100 leaves
    for i in 0u64..100 {
        let leaf_hash = hash_leaf(&i.to_le_bytes());
        tree.append(leaf_hash).unwrap();
    }

    let proof_index = 42u64;
    let proof = tree.generate_proof(proof_index).unwrap();
    let leaf_hash = hash_leaf(&proof_index.to_le_bytes());
    let trusted_root = tree.root_hex().unwrap();

    c.bench_function("merkle/verify_proof", |b| {
        b.iter(|| {
            MerkleTree::verify_proof(
                black_box(leaf_hash),
                black_box(&proof),
                black_box(&trusted_root),
            )
            .unwrap()
        })
    });
}

criterion_group!(
    audit_benches,
    bench_export_formats,
    bench_redaction,
    bench_logging_throughput,
);

criterion_group!(
    merkle_benches,
    bench_merkle_append_leaf,
    bench_merkle_generate_proof_100_leaves,
    bench_merkle_generate_proof_10000_leaves,
    bench_merkle_verify_proof,
);

criterion_main!(audit_benches, merkle_benches);
