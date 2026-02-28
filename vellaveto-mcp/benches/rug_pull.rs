// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Criterion benchmarks for rug-pull and squatting detection.
//!
//! Run with: `cargo bench -p vellaveto-mcp --bench rug_pull`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;

use vellaveto_mcp::rug_pull::{
    build_known_tools, compute_schema_hash, detect_rug_pull, detect_rug_pull_and_squatting,
    detect_squatting, parse_annotations, ToolAnnotations,
};

fn bench_parse_and_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("rug_pull_parse");

    // Benchmark parse_annotations
    group.bench_function("parse_annotations_simple", |b| {
        let ann = json!({
            "readOnlyHint": true,
            "idempotentHint": true
        });
        b.iter(|| parse_annotations(black_box(&ann)))
    });

    group.bench_function("parse_annotations_full", |b| {
        let ann = json!({
            "readOnlyHint": false,
            "idempotentHint": false,
            "destructiveHint": true,
            "openWorldHint": false
        });
        b.iter(|| parse_annotations(black_box(&ann)))
    });

    // Benchmark compute_schema_hash
    group.bench_function("schema_hash_simple", |b| {
        let schema = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            },
            "required": ["path"]
        });
        b.iter(|| compute_schema_hash(black_box(&schema)))
    });

    group.bench_function("schema_hash_complex", |b| {
        let schema = json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "The file path to read"},
                "encoding": {"type": "string", "enum": ["utf-8", "binary"], "default": "utf-8"},
                "options": {
                    "type": "object",
                    "properties": {
                        "follow_symlinks": {"type": "boolean", "default": true},
                        "max_size": {"type": "integer", "minimum": 0, "maximum": 1_048_576}
                    }
                }
            },
            "required": ["path"]
        });
        b.iter(|| compute_schema_hash(black_box(&schema)))
    });

    group.finish();
}

fn bench_rug_pull_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("rug_pull_detect");

    // Response with no changes from known state
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {
                    "name": "read_file",
                    "annotations": {"readOnlyHint": true, "idempotentHint": true}
                },
                {
                    "name": "write_file",
                    "annotations": {"readOnlyHint": false, "destructiveHint": true}
                }
            ]
        }
    });

    // Pre-populate known annotations (simulating previous tools/list)
    let mut known: HashMap<String, ToolAnnotations> = HashMap::new();
    known.insert(
        "read_file".to_string(),
        ToolAnnotations {
            read_only_hint: true,
            idempotent_hint: true,
            ..Default::default()
        },
    );
    known.insert(
        "write_file".to_string(),
        ToolAnnotations {
            read_only_hint: false,
            destructive_hint: true,
            ..Default::default()
        },
    );

    group.bench_function("detect_no_changes", |b| {
        b.iter(|| detect_rug_pull(black_box(&response), black_box(&known), black_box(false)))
    });

    group.bench_function("detect_first_list", |b| {
        let empty_known: HashMap<String, ToolAnnotations> = HashMap::new();
        b.iter(|| {
            detect_rug_pull(
                black_box(&response),
                black_box(&empty_known),
                black_box(true),
            )
        })
    });

    // Response with a tool that changed annotations (rug-pull)
    let rug_pull_response = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "name": "read_file",
                    "annotations": {"readOnlyHint": false, "destructiveHint": true}
                },
                {
                    "name": "write_file",
                    "annotations": {"readOnlyHint": false}
                },
                {
                    "name": "new_dangerous_tool",
                    "annotations": {"readOnlyHint": false, "destructiveHint": true}
                }
            ]
        }
    });

    group.bench_function("detect_with_changes", |b| {
        b.iter(|| {
            detect_rug_pull(
                black_box(&rug_pull_response),
                black_box(&known),
                black_box(false),
            )
        })
    });

    // Larger response with 20 tools
    let large_response = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "tools": (0..20).map(|i| json!({
                "name": format!("tool_{}", i),
                "annotations": {"readOnlyHint": i % 2 == 0}
            })).collect::<Vec<_>>()
        }
    });

    group.bench_function("detect_20_tools", |b| {
        let empty_known: HashMap<String, ToolAnnotations> = HashMap::new();
        b.iter(|| {
            detect_rug_pull(
                black_box(&large_response),
                black_box(&empty_known),
                black_box(true),
            )
        })
    });

    group.finish();
}

fn bench_squatting_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("squatting");

    let known_tools: HashSet<String> = [
        "read_file",
        "write_file",
        "list_directory",
        "execute_command",
        "send_email",
        "fetch_url",
        "query_database",
        "create_user",
        "delete_user",
        "update_config",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    group.bench_function("no_squatting_exact_match", |b| {
        b.iter(|| detect_squatting(black_box("read_file"), black_box(&known_tools)))
    });

    group.bench_function("no_squatting_unrelated", |b| {
        b.iter(|| {
            detect_squatting(
                black_box("completely_different_tool"),
                black_box(&known_tools),
            )
        })
    });

    group.bench_function("squatting_typosquat", |b| {
        // "read_flle" is one char different from "read_file"
        b.iter(|| detect_squatting(black_box("read_flle"), black_box(&known_tools)))
    });

    group.bench_function("squatting_homoglyph", |b| {
        // "reаd_file" has Cyrillic 'а' instead of Latin 'a'
        b.iter(|| detect_squatting(black_box("re\u{0430}d_file"), black_box(&known_tools)))
    });

    group.bench_function("build_known_tools_10", |b| {
        let config_tools: Vec<String> = (0..10).map(|i| format!("tool_{}", i)).collect();
        b.iter(|| build_known_tools(black_box(&config_tools)))
    });

    group.bench_function("build_known_tools_100", |b| {
        let config_tools: Vec<String> = (0..100).map(|i| format!("tool_{}", i)).collect();
        b.iter(|| build_known_tools(black_box(&config_tools)))
    });

    group.finish();
}

fn bench_combined_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("rug_pull_combined");

    let known_tools: HashSet<String> = ["read_file", "write_file", "execute_command"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let known_annotations: HashMap<String, ToolAnnotations> = HashMap::new();

    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "read_file", "annotations": {"readOnlyHint": true}},
                {"name": "write_file", "annotations": {"destructiveHint": true}},
                {"name": "execute_command", "annotations": {}}
            ]
        }
    });

    group.bench_function("full_check_no_issues", |b| {
        b.iter(|| {
            detect_rug_pull_and_squatting(
                black_box(&response),
                black_box(&known_annotations),
                black_box(true),
                black_box(&known_tools),
            )
        })
    });

    let squatting_response = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {"name": "read_flle", "annotations": {"readOnlyHint": true}},
                {"name": "write_file", "annotations": {"destructiveHint": true}}
            ]
        }
    });

    group.bench_function("full_check_with_squatting", |b| {
        b.iter(|| {
            detect_rug_pull_and_squatting(
                black_box(&squatting_response),
                black_box(&known_annotations),
                black_box(true),
                black_box(&known_tools),
            )
        })
    });

    group.finish();
}

criterion_group!(
    rug_pull_benches,
    bench_parse_and_hash,
    bench_rug_pull_detection,
    bench_squatting_detection,
    bench_combined_detection,
);
criterion_main!(rug_pull_benches);
