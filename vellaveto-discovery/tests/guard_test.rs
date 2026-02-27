//! Tests for TopologyGuard — pre-policy filter.

use vellaveto_discovery::guard::*;
use vellaveto_discovery::topology::*;

fn make_test_topology() -> TopologyGraph {
    TopologyGraph::from_static(vec![
        StaticServerDecl {
            name: "fs".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: serde_json::json!({}),
                },
                StaticToolDecl {
                    name: "write_file".to_string(),
                    description: "Write a file".to_string(),
                    input_schema: serde_json::json!({}),
                },
            ],
            resources: vec![],
        },
        StaticServerDecl {
            name: "git".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "commit".to_string(),
                    description: "Commit changes".to_string(),
                    input_schema: serde_json::json!({}),
                },
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read file from git".to_string(),
                    input_schema: serde_json::json!({}),
                },
            ],
            resources: vec![],
        },
    ])
    .unwrap()
}

#[test]
fn test_guard_known_qualified() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    match guard.check("fs::read_file") {
        TopologyVerdict::Known { server, tool, .. } => {
            assert_eq!(server, "fs");
            assert_eq!(tool, "read_file");
        }
        other => panic!("Expected Known, got {:?}", other),
    }
}

#[test]
fn test_guard_known_unqualified() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    // "commit" is unique across servers
    match guard.check("commit") {
        TopologyVerdict::Known { server, tool, .. } => {
            assert_eq!(server, "git");
            assert_eq!(tool, "commit");
        }
        other => panic!("Expected Known, got {:?}", other),
    }
}

#[test]
fn test_guard_unknown() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    match guard.check("nonexistent_tool") {
        TopologyVerdict::Unknown {
            requested_tool,
            available_tools,
            ..
        } => {
            assert_eq!(requested_tool, "nonexistent_tool");
            assert!(!available_tools.is_empty());
        }
        other => panic!("Expected Unknown, got {:?}", other),
    }
}

#[test]
fn test_guard_unknown_with_suggestion() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    match guard.check("read_fil") {
        TopologyVerdict::Unknown { suggestion, .. } => {
            // Should suggest something close to "read_file"
            assert!(suggestion.is_some(), "Expected a suggestion");
        }
        other => panic!("Expected Unknown, got {:?}", other),
    }
}

#[test]
fn test_guard_ambiguous() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    // "read_file" exists on both "fs" and "git"
    match guard.check("read_file") {
        TopologyVerdict::Ambiguous {
            requested_tool,
            matches,
        } => {
            assert_eq!(requested_tool, "read_file");
            assert_eq!(matches.len(), 2);
            assert!(matches.contains(&"fs::read_file".to_string()));
            assert!(matches.contains(&"git::read_file".to_string()));
        }
        other => panic!("Expected Ambiguous, got {:?}", other),
    }
}

#[test]
fn test_guard_bypassed() {
    let guard = TopologyGuard::new();
    // No topology loaded
    match guard.check("any_tool") {
        TopologyVerdict::Bypassed => {}
        other => panic!("Expected Bypassed, got {:?}", other),
    }
}

#[test]
fn test_guard_load_and_check() {
    let guard = TopologyGuard::new();
    assert!(matches!(guard.check("commit"), TopologyVerdict::Bypassed));

    guard.load(make_test_topology());
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));
}

#[test]
fn test_guard_update_hotswap() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());

    // "commit" is known
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));

    // Update with a topology that doesn't have git
    let new_topology = TopologyGraph::from_static(vec![StaticServerDecl {
        name: "fs".to_string(),
        tools: vec![StaticToolDecl {
            name: "read_file".to_string(),
            description: "Read a file".to_string(),
            input_schema: serde_json::json!({}),
        }],
        resources: vec![],
    }])
    .unwrap();

    guard.update(new_topology);

    // "commit" should now be unknown
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Unknown { .. }
    ));

    // "read_file" should now be Known (unique)
    assert!(matches!(
        guard.check("read_file"),
        TopologyVerdict::Known { .. }
    ));
}

#[test]
fn test_guard_clear() {
    let guard = TopologyGuard::new();
    guard.load(make_test_topology());
    assert!(matches!(
        guard.check("commit"),
        TopologyVerdict::Known { .. }
    ));

    guard.clear();
    assert!(matches!(guard.check("commit"), TopologyVerdict::Bypassed));
}

#[test]
fn test_guard_concurrent_reads() {
    use std::sync::Arc;

    let guard = Arc::new(TopologyGuard::new());
    guard.load(make_test_topology());

    let handles: Vec<_> = (0..100)
        .map(|_| {
            let g = Arc::clone(&guard);
            std::thread::spawn(move || {
                let result = g.check("commit");
                assert!(matches!(result, TopologyVerdict::Known { .. }));
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_guard_update_during_reads() {
    use std::sync::Arc;

    let guard = Arc::new(TopologyGuard::new());
    guard.load(make_test_topology());

    let handles: Vec<_> = (0..50)
        .map(|i| {
            let g = Arc::clone(&guard);
            std::thread::spawn(move || {
                if i % 10 == 0 {
                    // Writer: update topology
                    let new_topo = TopologyGraph::from_static(vec![StaticServerDecl {
                        name: "fs".to_string(),
                        tools: vec![StaticToolDecl {
                            name: "read_file".to_string(),
                            description: "Read".to_string(),
                            input_schema: serde_json::json!({}),
                        }],
                        resources: vec![],
                    }])
                    .unwrap();
                    g.update(new_topo);
                } else {
                    // Reader: just check, should not panic
                    let _result = g.check("read_file");
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_guard_current() {
    let guard = TopologyGuard::new();
    assert!(guard.current().is_none());

    guard.load(make_test_topology());
    let current = guard.current();
    assert!(current.is_some());
    assert!(current.unwrap().node_count() > 0);
}

#[test]
fn test_guard_default() {
    let guard = TopologyGuard::default();
    assert!(matches!(guard.check("any"), TopologyVerdict::Bypassed));
}

#[test]
fn test_guard_debug() {
    let guard = TopologyGuard::new();
    let debug = format!("{:?}", guard);
    assert!(debug.contains("TopologyGuard"));
    assert!(debug.contains("loaded"));
}
