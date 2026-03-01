// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Tests for JSON serialization and topology operations.

use vellaveto_discovery::topology::*;

fn make_test_topology() -> TopologyGraph {
    TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" }
                        }
                    }),
                },
                StaticToolDecl {
                    name: "write_file".to_string(),
                    description: "Write a file".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "content": { "type": "string" }
                        }
                    }),
                },
            ],
            resources: vec![],
        },
        StaticServerDecl {
            name: "git".to_string(),
            tools: vec![StaticToolDecl {
                name: "commit".to_string(),
                description: "Commit changes".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            resources: vec![],
        },
    ])
    .unwrap()
}

#[test]
fn test_json_roundtrip() {
    let original = make_test_topology();
    let json = original.to_json().unwrap();
    let restored = TopologyGraph::from_json(&json).unwrap();

    assert_eq!(original.node_count(), restored.node_count());
    assert_eq!(original.server_count(), restored.server_count());
    assert_eq!(original.tool_names(), restored.tool_names());
}

#[test]
fn test_json_includes_edges() {
    let graph = make_test_topology();
    let json = graph.to_json().unwrap();

    // Parse and check edges array exists
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let edges = parsed["edges"].as_array().unwrap();
    assert!(!edges.is_empty(), "JSON should include Owns edges");
}

#[test]
fn test_tools_matching_search() {
    let graph = make_test_topology();
    let matches = graph.tools_matching_capability("read");
    assert!(matches.contains(&"fs::read_file".to_string()));
}

#[test]
fn test_tools_matching_write() {
    let graph = make_test_topology();
    let matches = graph.tools_matching_capability("write");
    assert!(matches.contains(&"fs::write_file".to_string()));
}

#[test]
fn test_tools_matching_none() {
    let graph = make_test_topology();
    let matches = graph.tools_matching_capability("nonexistent_xyz");
    assert!(matches.is_empty());
}

#[test]
fn test_merge_disjoint() {
    let topo1 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read".to_string(),
            description: "Read".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    let topo2 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "git".to_string(),
        tools: vec![StaticToolDecl {
            name: "commit".to_string(),
            description: "Commit".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    let merged = topo1.merge(&topo2).unwrap();
    assert_eq!(merged.server_count(), 2);
    assert!(merged.find_tool("fs::read").is_some());
    assert!(merged.find_tool("git::commit").is_some());
}

#[test]
fn test_merge_overlapping() {
    let topo1 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read".to_string(),
            description: "Read v1".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    let topo2 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read".to_string(),
            description: "Read v2".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    let merged = topo1.merge(&topo2).unwrap();
    assert_eq!(merged.server_count(), 1);
    // Should have the tool (deduplicated)
    assert!(merged.find_tool("fs::read").is_some());
}

#[test]
fn test_filter_servers() {
    let graph = make_test_topology();
    let filtered = graph.filter_servers(&["fs"]).unwrap();

    assert_eq!(filtered.server_count(), 1);
    assert!(filtered.find_tool("fs::read_file").is_some());
    assert!(filtered.find_tool("git::commit").is_none());
}

#[test]
fn test_filter_preserves_internal_edges() {
    let graph = make_test_topology();
    let filtered = graph.filter_servers(&["fs"]).unwrap();

    // Should still have Owns edges for the kept server
    assert!(filtered.edge_count() > 0);
}

#[test]
fn test_adjacency_list() {
    let graph = make_test_topology();
    let adj = graph.to_adjacency_list();

    assert!(!adj.is_empty());
    // Should have entries for servers (which own tools)
    let server_entries: Vec<_> = adj
        .iter()
        .filter(|(src, _)| src == "fs" || src == "git")
        .collect();
    assert!(!server_entries.is_empty());
}

#[test]
fn test_snapshot_roundtrip() {
    let original = make_test_topology();
    let snapshot = original.to_snapshot();
    let restored = TopologyGraph::from_snapshot(snapshot).unwrap();

    assert_eq!(original.node_count(), restored.node_count());
    assert_eq!(original.tool_names(), restored.tool_names());
}
