//! Tests for topology diffing.

use vellaveto_discovery::topology::*;

fn make_v1() -> TopologyGraph {
    TopologyGraph::from_static(vec![
        StaticServerDecl {
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
            resources: vec![StaticResourceDecl {
                uri_template: "file:///{path}".to_string(),
                name: "file".to_string(),
                mime_type: None,
            }],
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
fn test_diff_no_change() {
    let v1 = make_v1();
    let v2 = make_v1();
    let diff = v1.diff(&v2);

    assert!(diff.is_empty());
    assert!(!diff.has_removals());
    assert!(!diff.has_schema_changes());
    assert_eq!(diff.summary(), "no changes");
}

#[test]
fn test_diff_added_tool() {
    let v1 = make_v1();
    let v2 = TopologyGraph::from_static(vec![
        StaticServerDecl {
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
                StaticToolDecl {
                    name: "delete_file".to_string(),
                    description: "Delete a file".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
            ],
            resources: vec![StaticResourceDecl {
                uri_template: "file:///{path}".to_string(),
                name: "file".to_string(),
                mime_type: None,
            }],
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
    .unwrap();

    let diff = v1.diff(&v2);
    assert!(!diff.is_empty());
    assert_eq!(diff.added_tools.len(), 1);
    assert_eq!(diff.added_tools[0].qualified, "fs::delete_file");
    assert!(diff.removed_tools.is_empty());
}

#[test]
fn test_diff_removed_tool() {
    let v1 = make_v1();
    let v2 = TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![StaticToolDecl {
                name: "read_file".to_string(),
                description: "Read a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            resources: vec![StaticResourceDecl {
                uri_template: "file:///{path}".to_string(),
                name: "file".to_string(),
                mime_type: None,
            }],
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
    .unwrap();

    let diff = v1.diff(&v2);
    assert!(diff.has_removals());
    assert_eq!(diff.removed_tools.len(), 1);
    assert_eq!(diff.removed_tools[0].qualified, "fs::write_file");
}

#[test]
fn test_diff_added_server() {
    let v1 = make_v1();
    let mut servers = vec![
        StaticServerDecl {
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
            resources: vec![StaticResourceDecl {
                uri_template: "file:///{path}".to_string(),
                name: "file".to_string(),
                mime_type: None,
            }],
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
    ];
    servers.push(StaticServerDecl {
        name: "web".to_string(),
        tools: vec![StaticToolDecl {
            name: "fetch".to_string(),
            description: "Fetch URL".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }],
        resources: vec![],
    });

    let v2 = TopologyGraph::from_static(servers).unwrap();
    let diff = v1.diff(&v2);

    assert_eq!(diff.added_servers.len(), 1);
    assert!(diff.added_servers.contains(&"web".to_string()));
}

#[test]
fn test_diff_removed_server() {
    let v1 = make_v1();
    let v2 = TopologyGraph::from_static(vec![StaticServerDecl {
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
        resources: vec![StaticResourceDecl {
            uri_template: "file:///{path}".to_string(),
            name: "file".to_string(),
            mime_type: None,
        }],
    }])
    .unwrap();

    let diff = v1.diff(&v2);
    assert!(diff.has_removals());
    assert_eq!(diff.removed_servers.len(), 1);
    assert!(diff.removed_servers.contains(&"git".to_string()));
}

#[test]
fn test_diff_schema_change() {
    let v1 = make_v1();
    let v2 = TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "file_path": { "type": "string" },
                            "encoding": { "type": "string" }
                        }
                    }),
                },
                StaticToolDecl {
                    name: "write_file".to_string(),
                    description: "Write a file".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
            ],
            resources: vec![StaticResourceDecl {
                uri_template: "file:///{path}".to_string(),
                name: "file".to_string(),
                mime_type: None,
            }],
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
    .unwrap();

    let diff = v1.diff(&v2);
    assert!(diff.has_schema_changes());
    assert_eq!(diff.modified_tools.len(), 1);
    assert_eq!(diff.modified_tools[0].qualified, "fs::read_file");
    assert!(diff.modified_tools[0].schema_changed);
}

#[test]
fn test_diff_description_change() {
    let v1 = make_v1();
    let v2 = TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read a file from disk (updated)".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
                StaticToolDecl {
                    name: "write_file".to_string(),
                    description: "Write a file".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
            ],
            resources: vec![StaticResourceDecl {
                uri_template: "file:///{path}".to_string(),
                name: "file".to_string(),
                mime_type: None,
            }],
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
    .unwrap();

    let diff = v1.diff(&v2);
    assert!(!diff.is_empty());
    assert_eq!(diff.modified_tools.len(), 1);
    assert!(diff.modified_tools[0].description_changed);
}

#[test]
fn test_diff_summary() {
    let v1 = make_v1();
    let v2 = TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
                StaticToolDecl {
                    name: "delete_file".to_string(),
                    description: "Delete a file".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
            ],
            resources: vec![StaticResourceDecl {
                uri_template: "file:///{path}".to_string(),
                name: "file".to_string(),
                mime_type: None,
            }],
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
    .unwrap();

    let diff = v1.diff(&v2);
    let summary = diff.summary();
    assert!(summary.contains("tools"), "Summary: {summary}");
}

#[test]
fn test_diff_resource_added() {
    let v1 = make_v1();
    let v2 = TopologyGraph::from_static(vec![
        StaticServerDecl {
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
            resources: vec![
                StaticResourceDecl {
                    uri_template: "file:///{path}".to_string(),
                    name: "file".to_string(),
                    mime_type: None,
                },
                StaticResourceDecl {
                    uri_template: "dir:///{path}".to_string(),
                    name: "directory".to_string(),
                    mime_type: None,
                },
            ],
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
    .unwrap();

    let diff = v1.diff(&v2);
    assert_eq!(diff.added_resources.len(), 1);
}
