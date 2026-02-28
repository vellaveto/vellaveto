// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Tests for topology fingerprinting.

use vellaveto_discovery::topology::*;

#[test]
fn test_fingerprint_deterministic() {
    let topo1 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![
            StaticToolDecl {
                name: "read_file".to_string(),
                description: "Read a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            },
            StaticToolDecl {
                name: "write_file".to_string(),
                description: "Write a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            },
        ],
        resources: vec![],
    }])
    .unwrap();

    let topo2 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![
            StaticToolDecl {
                name: "read_file".to_string(),
                description: "Read a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            },
            StaticToolDecl {
                name: "write_file".to_string(),
                description: "Write a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            },
        ],
        resources: vec![],
    }])
    .unwrap();

    assert_eq!(topo1.fingerprint(), topo2.fingerprint());
    assert_eq!(topo1.fingerprint_hex(), topo2.fingerprint_hex());
}

#[test]
fn test_fingerprint_changes_on_modification() {
    let topo1 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read_file".to_string(),
            description: "Read a file".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }],
        resources: vec![],
    }])
    .unwrap();

    let topo2 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![
            StaticToolDecl {
                name: "read_file".to_string(),
                description: "Read a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            },
            StaticToolDecl {
                name: "write_file".to_string(),
                description: "Write a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            },
        ],
        resources: vec![],
    }])
    .unwrap();

    assert_ne!(
        topo1.fingerprint(),
        topo2.fingerprint(),
        "Adding a tool should change the fingerprint"
    );
}

#[test]
fn test_fingerprint_hex_format() {
    let topo = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read".to_string(),
            description: "Read".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    let hex = topo.fingerprint_hex();
    assert_eq!(hex.len(), 64, "SHA-256 hex should be 64 chars");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "Should be valid hex"
    );
}

#[test]
fn test_fingerprint_empty_topology() {
    let topo = TopologyGraph::empty();
    let hex = topo.fingerprint_hex();
    // Empty topology should have a consistent fingerprint
    assert_eq!(hex.len(), 64);
}

#[test]
fn test_fingerprint_order_independence() {
    // Build same topology with servers in different order
    let topo1 = TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "aaa".to_string(),
            tools: vec![StaticToolDecl {
                name: "tool1".to_string(),
                description: "Tool 1".to_string(),
                input_schema: serde_json::json!({}),
            }],
            resources: vec![],
        },
        StaticServerDecl {
            name: "bbb".to_string(),
            tools: vec![StaticToolDecl {
                name: "tool2".to_string(),
                description: "Tool 2".to_string(),
                input_schema: serde_json::json!({}),
            }],
            resources: vec![],
        },
    ])
    .unwrap();

    let topo2 = TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "bbb".to_string(),
            tools: vec![StaticToolDecl {
                name: "tool2".to_string(),
                description: "Tool 2".to_string(),
                input_schema: serde_json::json!({}),
            }],
            resources: vec![],
        },
        StaticServerDecl {
            name: "aaa".to_string(),
            tools: vec![StaticToolDecl {
                name: "tool1".to_string(),
                description: "Tool 1".to_string(),
                input_schema: serde_json::json!({}),
            }],
            resources: vec![],
        },
    ])
    .unwrap();

    assert_eq!(
        topo1.fingerprint(),
        topo2.fingerprint(),
        "Server order should not affect fingerprint"
    );
}

#[test]
fn test_fingerprint_description_change() {
    let topo1 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read".to_string(),
            description: "Read version 1".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    let topo2 = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read".to_string(),
            description: "Read version 2".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    assert_ne!(
        topo1.fingerprint(),
        topo2.fingerprint(),
        "Description change should change fingerprint"
    );
}
