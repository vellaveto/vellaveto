// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Topology diffing — compare two snapshots.
//!
//! Detects added, removed, and modified tools/servers/resources between
//! two topology snapshots.

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use crate::topology::{TopologyEdge, TopologyGraph, TopologyNode};
use petgraph::visit::EdgeRef;

/// A qualified tool reference (server::tool).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct QualifiedTool {
    /// The server name.
    pub server: String,
    /// The tool name.
    pub tool: String,
    /// The qualified name ("server::tool").
    pub qualified: String,
}

/// A modification to a tool's schema or description.
#[derive(Debug, Clone, Serialize)]
pub struct ToolModification {
    /// The qualified tool name.
    pub qualified: String,
    /// Whether the description changed.
    pub description_changed: bool,
    /// Whether the input schema changed.
    pub schema_changed: bool,
    /// Human-readable summary of the change.
    pub summary: String,
}

/// The difference between two topology snapshots.
#[derive(Debug, Clone, Serialize)]
pub struct TopologyDiff {
    /// Servers that were added.
    pub added_servers: Vec<String>,
    /// Servers that were removed.
    pub removed_servers: Vec<String>,
    /// Tools that were added.
    pub added_tools: Vec<QualifiedTool>,
    /// Tools that were removed.
    pub removed_tools: Vec<QualifiedTool>,
    /// Tools that were modified (description or schema changed).
    pub modified_tools: Vec<ToolModification>,
    /// Resources that were added.
    pub added_resources: Vec<String>,
    /// Resources that were removed.
    pub removed_resources: Vec<String>,
    /// SECURITY (R231-DISC-6): DataFlow edges that were added.
    pub added_data_flow_edges: Vec<(String, String)>,
    /// DataFlow edges that were removed.
    pub removed_data_flow_edges: Vec<(String, String)>,
    /// When this diff was computed.
    pub timestamp: SystemTime,
}

impl TopologyDiff {
    /// Returns true if there are no changes.
    pub fn is_empty(&self) -> bool {
        self.added_servers.is_empty()
            && self.removed_servers.is_empty()
            && self.added_tools.is_empty()
            && self.removed_tools.is_empty()
            && self.modified_tools.is_empty()
            && self.added_resources.is_empty()
            && self.removed_resources.is_empty()
            && self.added_data_flow_edges.is_empty()
            && self.removed_data_flow_edges.is_empty()
    }

    /// Returns true if any tools or servers were removed.
    pub fn has_removals(&self) -> bool {
        !self.removed_servers.is_empty()
            || !self.removed_tools.is_empty()
            || !self.removed_resources.is_empty()
    }

    /// Returns true if any tool schemas changed.
    pub fn has_schema_changes(&self) -> bool {
        self.modified_tools.iter().any(|m| m.schema_changed)
    }

    /// Human-readable one-line summary.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if !self.added_servers.is_empty() {
            parts.push(format!("+{} servers", self.added_servers.len()));
        }
        if !self.removed_servers.is_empty() {
            parts.push(format!("-{} servers", self.removed_servers.len()));
        }
        if !self.added_tools.is_empty() {
            parts.push(format!("+{} tools", self.added_tools.len()));
        }
        if !self.removed_tools.is_empty() {
            parts.push(format!("-{} tools", self.removed_tools.len()));
        }
        if !self.modified_tools.is_empty() {
            parts.push(format!("~{} tools", self.modified_tools.len()));
        }
        if !self.added_resources.is_empty() {
            parts.push(format!("+{} resources", self.added_resources.len()));
        }
        if !self.removed_resources.is_empty() {
            parts.push(format!("-{} resources", self.removed_resources.len()));
        }
        if !self.added_data_flow_edges.is_empty() {
            parts.push(format!("+{} data flows", self.added_data_flow_edges.len()));
        }
        if !self.removed_data_flow_edges.is_empty() {
            parts.push(format!(
                "-{} data flows",
                self.removed_data_flow_edges.len()
            ));
        }

        if parts.is_empty() {
            "no changes".to_string()
        } else {
            parts.join(", ")
        }
    }
}

impl TopologyGraph {
    /// Compute the diff between this (older) topology and a newer one.
    pub fn diff(&self, newer: &TopologyGraph) -> TopologyDiff {
        let old_servers: HashSet<String> = self.server_names().into_iter().collect();
        let new_servers: HashSet<String> = newer.server_names().into_iter().collect();

        let added_servers: Vec<String> = new_servers.difference(&old_servers).cloned().collect();
        let removed_servers: Vec<String> = old_servers.difference(&new_servers).cloned().collect();

        let old_tools: HashSet<String> = self.tool_names().into_iter().collect();
        let new_tools: HashSet<String> = newer.tool_names().into_iter().collect();

        let added_tools: Vec<QualifiedTool> = new_tools
            .difference(&old_tools)
            .map(|q| qualified_from_str(q))
            .collect();
        let removed_tools: Vec<QualifiedTool> = old_tools
            .difference(&new_tools)
            .map(|q| qualified_from_str(q))
            .collect();

        // Check for modifications (same qualified name, different content)
        let common_tools: HashSet<&String> = old_tools.intersection(&new_tools).collect();
        let mut modified_tools = Vec::new();

        let old_tool_map = build_tool_map(self);
        let new_tool_map = build_tool_map(newer);

        for qualified in common_tools {
            if let (Some(old_node), Some(new_node)) = (
                old_tool_map.get(qualified.as_str()),
                new_tool_map.get(qualified.as_str()),
            ) {
                let desc_changed = old_node.0 != new_node.0;
                let schema_changed = old_node.1 != new_node.1;

                if desc_changed || schema_changed {
                    let mut changes = Vec::new();
                    if desc_changed {
                        changes.push("description");
                    }
                    if schema_changed {
                        changes.push("schema");
                    }
                    modified_tools.push(ToolModification {
                        qualified: qualified.clone(),
                        description_changed: desc_changed,
                        schema_changed,
                        summary: format!("{}: {} changed", qualified, changes.join(" and ")),
                    });
                }
            }
        }

        // Resources
        let old_resources: HashSet<String> = self.resource_names().into_iter().collect();
        let new_resources: HashSet<String> = newer.resource_names().into_iter().collect();

        let added_resources: Vec<String> =
            new_resources.difference(&old_resources).cloned().collect();
        let removed_resources: Vec<String> =
            old_resources.difference(&new_resources).cloned().collect();

        // SECURITY (R231-DISC-6): Track DataFlow edge changes.
        let old_data_flows = collect_data_flow_edges(self);
        let new_data_flows = collect_data_flow_edges(newer);
        let added_data_flow_edges: Vec<(String, String)> = new_data_flows
            .difference(&old_data_flows)
            .cloned()
            .collect();
        let removed_data_flow_edges: Vec<(String, String)> = old_data_flows
            .difference(&new_data_flows)
            .cloned()
            .collect();

        TopologyDiff {
            added_servers,
            removed_servers,
            added_tools,
            removed_tools,
            modified_tools,
            added_resources,
            removed_resources,
            added_data_flow_edges,
            removed_data_flow_edges,
            timestamp: SystemTime::now(),
        }
    }

    /// All qualified resource names in the topology.
    pub fn resource_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .name_index()
            .iter()
            .filter(|(_, idx)| self.graph()[**idx].is_resource())
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
    }
}

/// Build a map of qualified_name → (description, schema_json) for diffing.
fn build_tool_map(graph: &TopologyGraph) -> HashMap<&str, (&str, &serde_json::Value)> {
    let mut map = HashMap::new();
    for (name, idx) in graph.name_index() {
        if let TopologyNode::Tool {
            description,
            input_schema,
            ..
        } = &graph.graph()[*idx]
        {
            map.insert(name.as_str(), (description.as_str(), input_schema));
        }
    }
    map
}

/// Collect all DataFlow edges as (source_qualified, target_qualified) pairs.
fn collect_data_flow_edges(graph: &TopologyGraph) -> HashSet<(String, String)> {
    let reverse_index: HashMap<petgraph::graph::NodeIndex, &str> = graph
        .name_index()
        .iter()
        .map(|(name, idx)| (*idx, name.as_str()))
        .collect();
    let mut edges = HashSet::new();
    for edge in graph.graph().edge_references() {
        if matches!(edge.weight(), TopologyEdge::DataFlow { .. }) {
            if let (Some(&src), Some(&tgt)) = (
                reverse_index.get(&edge.source()),
                reverse_index.get(&edge.target()),
            ) {
                edges.insert((src.to_string(), tgt.to_string()));
            }
        }
    }
    edges
}

/// Parse a qualified name "server::tool" into a QualifiedTool.
fn qualified_from_str(s: &str) -> QualifiedTool {
    let parts: Vec<&str> = s.splitn(2, "::").collect();
    if parts.len() == 2 {
        QualifiedTool {
            server: parts[0].to_string(),
            tool: parts[1].to_string(),
            qualified: s.to_string(),
        }
    } else {
        QualifiedTool {
            server: String::new(),
            tool: s.to_string(),
            qualified: s.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{StaticResourceDecl, StaticServerDecl, StaticToolDecl, TopologyGraph};

    fn make_topology(servers: Vec<StaticServerDecl>) -> TopologyGraph {
        TopologyGraph::from_static(servers).unwrap()
    }

    #[test]
    fn test_qualified_from_str_with_separator() {
        let q = qualified_from_str("server::tool_name");
        assert_eq!(q.server, "server");
        assert_eq!(q.tool, "tool_name");
        assert_eq!(q.qualified, "server::tool_name");
    }

    #[test]
    fn test_qualified_from_str_without_separator() {
        let q = qualified_from_str("just_a_name");
        assert_eq!(q.server, "");
        assert_eq!(q.tool, "just_a_name");
        assert_eq!(q.qualified, "just_a_name");
    }

    #[test]
    fn test_qualified_from_str_multiple_separators() {
        // splitn(2, "::") should only split at the first "::"
        let q = qualified_from_str("server::nested::tool");
        assert_eq!(q.server, "server");
        assert_eq!(q.tool, "nested::tool");
    }

    #[test]
    fn test_diff_empty_topologies() {
        let t1 = TopologyGraph::empty();
        let t2 = TopologyGraph::empty();
        let diff = t1.diff(&t2);
        assert!(diff.is_empty());
        assert_eq!(diff.summary(), "no changes");
    }

    #[test]
    fn test_diff_data_flow_edge_added() {
        let t1 = make_topology(vec![StaticServerDecl {
            name: "srv".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "producer".to_string(),
                    description: "Search for files. Returns file paths.".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
                StaticToolDecl {
                    name: "consumer".to_string(),
                    description: "Read file content".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"}
                        }
                    }),
                },
            ],
            resources: vec![],
        }]);

        // Build t2 with DataFlow edges via inference
        let mut t2 = make_topology(vec![StaticServerDecl {
            name: "srv".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "producer".to_string(),
                    description: "Search for files. Returns file paths.".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
                StaticToolDecl {
                    name: "consumer".to_string(),
                    description: "Read file content".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"}
                        }
                    }),
                },
            ],
            resources: vec![],
        }]);
        let engine = crate::inference::InferenceEngine::new(crate::inference::InferenceConfig {
            threshold: 0.0,
            ..crate::inference::InferenceConfig::default()
        });
        engine.infer_edges(&mut t2);

        let diff = t1.diff(&t2);
        // DataFlow edges were added to t2, so diff should detect them
        if t2.edge_count() > t1.edge_count() {
            assert!(
                !diff.added_data_flow_edges.is_empty(),
                "Should detect added DataFlow edges"
            );
            let summary = diff.summary();
            assert!(summary.contains("data flows"));
        }
    }

    #[test]
    fn test_diff_data_flow_edge_removed() {
        // Build t1 with DataFlow edges, t2 without
        let mut t1 = make_topology(vec![StaticServerDecl {
            name: "srv".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "file_search".to_string(),
                    description: "Search for files. Returns file paths.".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read content".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"}
                        }
                    }),
                },
            ],
            resources: vec![],
        }]);
        let engine = crate::inference::InferenceEngine::new(crate::inference::InferenceConfig {
            threshold: 0.0,
            ..crate::inference::InferenceConfig::default()
        });
        engine.infer_edges(&mut t1);

        let t2 = make_topology(vec![StaticServerDecl {
            name: "srv".to_string(),
            tools: vec![
                StaticToolDecl {
                    name: "file_search".to_string(),
                    description: "Search for files. Returns file paths.".to_string(),
                    input_schema: serde_json::json!({"type": "object"}),
                },
                StaticToolDecl {
                    name: "read_file".to_string(),
                    description: "Read content".to_string(),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"}
                        }
                    }),
                },
            ],
            resources: vec![],
        }]);

        let diff = t1.diff(&t2);
        if t1.edge_count() > t2.edge_count() {
            assert!(
                !diff.removed_data_flow_edges.is_empty(),
                "Should detect removed DataFlow edges"
            );
        }
    }

    #[test]
    fn test_diff_simultaneous_add_remove_same_server() {
        // t1 has server "alpha" with tool_a, t2 has server "alpha" with tool_b
        // This means tool_a is removed and tool_b is added simultaneously
        let t1 = make_topology(vec![StaticServerDecl {
            name: "alpha".to_string(),
            tools: vec![StaticToolDecl {
                name: "tool_a".to_string(),
                description: "A".to_string(),
                input_schema: serde_json::json!({}),
            }],
            resources: vec![],
        }]);

        let t2 = make_topology(vec![StaticServerDecl {
            name: "alpha".to_string(),
            tools: vec![StaticToolDecl {
                name: "tool_b".to_string(),
                description: "B".to_string(),
                input_schema: serde_json::json!({}),
            }],
            resources: vec![],
        }]);

        let diff = t1.diff(&t2);
        assert!(diff.added_servers.is_empty(), "Server alpha still exists");
        assert!(diff.removed_servers.is_empty(), "Server alpha still exists");
        assert_eq!(diff.removed_tools.len(), 1);
        assert_eq!(diff.removed_tools[0].qualified, "alpha::tool_a");
        assert_eq!(diff.added_tools.len(), 1);
        assert_eq!(diff.added_tools[0].qualified, "alpha::tool_b");
    }

    #[test]
    fn test_diff_summary_multiple_change_types() {
        let t1 = make_topology(vec![
            StaticServerDecl {
                name: "s1".to_string(),
                tools: vec![StaticToolDecl {
                    name: "old_tool".to_string(),
                    description: "Old".to_string(),
                    input_schema: serde_json::json!({}),
                }],
                resources: vec![StaticResourceDecl {
                    uri_template: "old://".to_string(),
                    name: "old_res".to_string(),
                    mime_type: None,
                }],
            },
            StaticServerDecl {
                name: "to_remove".to_string(),
                tools: vec![],
                resources: vec![],
            },
        ]);

        let t2 = make_topology(vec![
            StaticServerDecl {
                name: "s1".to_string(),
                tools: vec![StaticToolDecl {
                    name: "new_tool".to_string(),
                    description: "New".to_string(),
                    input_schema: serde_json::json!({}),
                }],
                resources: vec![],
            },
            StaticServerDecl {
                name: "added_server".to_string(),
                tools: vec![],
                resources: vec![],
            },
        ]);

        let diff = t1.diff(&t2);
        let summary = diff.summary();
        // Should contain multiple change indicators
        assert!(
            summary.contains("servers")
                || summary.contains("tools")
                || summary.contains("resources"),
            "Summary should describe changes: {summary}"
        );
        assert!(diff.has_removals());
    }

    #[test]
    fn test_diff_resource_removed() {
        let t1 = make_topology(vec![StaticServerDecl {
            name: "s1".to_string(),
            tools: vec![],
            resources: vec![
                StaticResourceDecl {
                    uri_template: "a://".to_string(),
                    name: "res_a".to_string(),
                    mime_type: None,
                },
                StaticResourceDecl {
                    uri_template: "b://".to_string(),
                    name: "res_b".to_string(),
                    mime_type: None,
                },
            ],
        }]);

        let t2 = make_topology(vec![StaticServerDecl {
            name: "s1".to_string(),
            tools: vec![],
            resources: vec![StaticResourceDecl {
                uri_template: "a://".to_string(),
                name: "res_a".to_string(),
                mime_type: None,
            }],
        }]);

        let diff = t1.diff(&t2);
        assert_eq!(diff.removed_resources.len(), 1);
        assert!(diff.removed_resources.contains(&"s1::res_b".to_string()));
        assert!(diff.has_removals());
    }

    #[test]
    fn test_diff_is_empty_all_fields_considered() {
        // Verify that is_empty checks all fields
        let mut diff = TopologyDiff {
            added_servers: vec![],
            removed_servers: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            modified_tools: vec![],
            added_resources: vec![],
            removed_resources: vec![],
            added_data_flow_edges: vec![],
            removed_data_flow_edges: vec![],
            timestamp: SystemTime::now(),
        };
        assert!(diff.is_empty());

        // Adding just one data flow edge should make it non-empty
        diff.added_data_flow_edges
            .push(("a".to_string(), "b".to_string()));
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_diff_has_schema_changes_false_when_only_description() {
        let t1 = make_topology(vec![StaticServerDecl {
            name: "s".to_string(),
            tools: vec![StaticToolDecl {
                name: "t".to_string(),
                description: "v1".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            resources: vec![],
        }]);

        let t2 = make_topology(vec![StaticServerDecl {
            name: "s".to_string(),
            tools: vec![StaticToolDecl {
                name: "t".to_string(),
                description: "v2 updated".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            resources: vec![],
        }]);

        let diff = t1.diff(&t2);
        assert!(
            !diff.has_schema_changes(),
            "Only description changed, not schema"
        );
        assert!(
            diff.modified_tools[0].description_changed,
            "Description should be marked as changed"
        );
    }

    #[test]
    fn test_resource_names_sorted() {
        let graph = make_topology(vec![StaticServerDecl {
            name: "s".to_string(),
            tools: vec![],
            resources: vec![
                StaticResourceDecl {
                    uri_template: "z://".to_string(),
                    name: "zebra".to_string(),
                    mime_type: None,
                },
                StaticResourceDecl {
                    uri_template: "a://".to_string(),
                    name: "alpha".to_string(),
                    mime_type: None,
                },
            ],
        }]);

        let names = graph.resource_names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(
            names, sorted,
            "resource_names() should return sorted results"
        );
    }
}
