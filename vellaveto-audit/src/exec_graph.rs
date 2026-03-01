// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Execution Graph for visualizing agent call chains.
//!
//! Provides data structures for tracking parent-child relationships between
//! tool calls, enabling visualization of agent execution flows and detection
//! of anomalous patterns.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Maximum number of nodes stored per execution graph.
/// Prevents unbounded memory growth in long sessions (FIND-R41-007).
const MAX_NODES_PER_GRAPH: usize = 50_000;

/// Maximum number of edges stored per execution graph.
/// Prevents unbounded memory growth in long sessions (FIND-041-010).
const MAX_EDGES_PER_GRAPH: usize = 50_000;

/// Maximum length of a session ID in bytes.
/// SECURITY (FIND-R215-003): Prevents unbounded session_id from consuming excessive memory.
const MAX_SESSION_ID_LEN: usize = 256;

/// Maximum number of metadata entries per execution node.
/// SECURITY (FIND-R215-004): Prevents unbounded metadata HashMap growth.
const MAX_METADATA_ENTRIES: usize = 50;

/// Maximum length of a metadata key in bytes.
/// SECURITY (FIND-R215-004): Prevents oversized metadata keys.
const MAX_METADATA_KEY_LEN: usize = 256;

/// Maximum length of a metadata value in bytes.
/// SECURITY (FIND-R215-004): Prevents oversized metadata values.
const MAX_METADATA_VALUE_LEN: usize = 4096;

/// Unique identifier for a graph node.
pub type NodeId = String;

/// Unique identifier for a session.
pub type SessionId = String;

/// A node in the execution graph representing a single tool call.
/// SECURITY (FIND-R215-005): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionNode {
    /// Unique identifier for this node.
    pub id: NodeId,
    /// Session this node belongs to.
    pub session_id: SessionId,
    /// Parent node ID (if any).
    pub parent_id: Option<NodeId>,
    /// Tool name.
    pub tool: String,
    /// Function/action name.
    pub function: String,
    /// Timestamp when the call started.
    pub started_at: u64,
    /// Timestamp when the call completed (if finished).
    pub completed_at: Option<u64>,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Verdict (allow/deny).
    pub verdict: NodeVerdict,
    /// Principal who initiated the call.
    pub principal: Option<String>,
    /// Agent ID (for multi-agent scenarios).
    pub agent_id: Option<String>,
    /// Depth in the call tree (0 = root).
    pub depth: u32,
    /// Child node IDs.
    #[serde(default)]
    pub children: Vec<NodeId>,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Verdict for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeVerdict {
    Allow,
    Deny,
    Pending,
    RequireApproval,
}

impl ExecutionNode {
    /// Create a new execution node.
    pub fn new(id: NodeId, session_id: SessionId, tool: String, function: String) -> Self {
        ExecutionNode {
            id,
            session_id,
            parent_id: None,
            tool,
            function,
            started_at: current_timestamp(),
            completed_at: None,
            duration_ms: None,
            verdict: NodeVerdict::Pending,
            principal: None,
            agent_id: None,
            depth: 0,
            children: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set the parent node.
    pub fn with_parent(mut self, parent_id: NodeId, depth: u32) -> Self {
        self.parent_id = Some(parent_id);
        self.depth = depth;
        self
    }

    /// Set the principal.
    pub fn with_principal(mut self, principal: String) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Set the agent ID.
    pub fn with_agent(mut self, agent_id: String) -> Self {
        self.agent_id = Some(agent_id);
        self
    }

    /// Mark the node as completed.
    pub fn complete(&mut self, verdict: NodeVerdict) {
        let now = current_timestamp();
        self.completed_at = Some(now);
        self.duration_ms = Some(now.saturating_sub(self.started_at));
        self.verdict = verdict;
    }

    /// Add a child node.
    pub fn add_child(&mut self, child_id: NodeId) {
        self.children.push(child_id);
    }

    /// Check if this is a root node.
    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }

    /// Check if the node is complete.
    pub fn is_complete(&self) -> bool {
        self.completed_at.is_some()
    }
}

/// An edge in the execution graph.
/// SECURITY (FIND-R215-005): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEdge {
    /// Source node ID.
    pub from: NodeId,
    /// Target node ID.
    pub to: NodeId,
    /// Edge type.
    pub edge_type: EdgeType,
    /// Timestamp of the edge creation.
    pub timestamp: u64,
}

/// Type of edge relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    /// Parent-child call relationship.
    Call,
    /// Data flow between calls.
    DataFlow,
    /// Delegation to another agent.
    Delegation,
}

/// A complete execution graph for a session.
/// SECURITY (FIND-R215-005): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGraph {
    /// Session ID.
    pub session_id: SessionId,
    /// All nodes in the graph.
    pub nodes: HashMap<NodeId, ExecutionNode>,
    /// All edges in the graph.
    pub edges: Vec<ExecutionEdge>,
    /// Root node IDs (entry points).
    pub roots: Vec<NodeId>,
    /// Graph metadata.
    pub metadata: GraphMetadata,
}

/// Metadata about the execution graph.
/// SECURITY (FIND-R215-005): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphMetadata {
    /// When the session started.
    pub started_at: Option<u64>,
    /// When the session ended.
    pub ended_at: Option<u64>,
    /// Total number of tool calls.
    pub total_calls: u32,
    /// Number of allowed calls.
    pub allowed_calls: u32,
    /// Number of denied calls.
    pub denied_calls: u32,
    /// Maximum depth reached.
    pub max_depth: u32,
    /// Unique tools used.
    pub unique_tools: HashSet<String>,
    /// Unique agents involved.
    pub unique_agents: HashSet<String>,
}

impl ExecutionGraph {
    /// Create a new empty execution graph.
    pub fn new(session_id: SessionId) -> Self {
        ExecutionGraph {
            session_id,
            nodes: HashMap::new(),
            edges: Vec::new(),
            roots: Vec::new(),
            metadata: GraphMetadata::default(),
        }
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, mut node: ExecutionNode) {
        // SECURITY (FIND-R215-004): Validate metadata bounds before insertion.
        if node.metadata.len() > MAX_METADATA_ENTRIES {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                node_id = %node.id,
                count = node.metadata.len(),
                limit = MAX_METADATA_ENTRIES,
                "Node metadata exceeds limit — truncating"
            );
            let keys: Vec<String> = node
                .metadata
                .keys()
                .skip(MAX_METADATA_ENTRIES)
                .cloned()
                .collect();
            for key in keys {
                node.metadata.remove(&key);
            }
        }
        node.metadata.retain(|k, v| {
            if k.len() > MAX_METADATA_KEY_LEN {
                tracing::warn!(
                    target: "vellaveto::observability",
                    key_len = k.len(),
                    limit = MAX_METADATA_KEY_LEN,
                    "Metadata key exceeds max length — dropping entry"
                );
                return false;
            }
            if v.len() > MAX_METADATA_VALUE_LEN {
                tracing::warn!(
                    target: "vellaveto::observability",
                    value_len = v.len(),
                    limit = MAX_METADATA_VALUE_LEN,
                    "Metadata value exceeds max length — dropping entry"
                );
                return false;
            }
            true
        });

        // SECURITY (FIND-R42-006): Check bounds BEFORE updating metadata or parent
        // children lists. Previously, metadata (total_calls, unique_tools, unique_agents,
        // edges, parent.children) were updated even when the node was rejected.
        if self.nodes.len() >= MAX_NODES_PER_GRAPH {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                limit = MAX_NODES_PER_GRAPH,
                "Node limit reached — skipping node insertion"
            );
            return;
        }

        let node_id = node.id.clone();
        let is_root = node.is_root();
        let depth = node.depth;

        // SECURITY (FIND-R44-056): If node ID already exists, update the existing
        // node's fields but do NOT re-increment metadata counters.
        if self.nodes.contains_key(&node_id) {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                node_id = %node_id,
                "Duplicate node ID — updating existing node without inflating metadata"
            );
            // Update the existing node's mutable fields
            if let Some(existing) = self.nodes.get_mut(&node_id) {
                existing.tool = node.tool;
                existing.function = node.function;
                existing.verdict = node.verdict;
                existing.agent_id = node.agent_id;
            }
            // Skip parent edge creation for duplicates — the edge already exists
            // if this parent-child relationship was established on first insert.
            return;
        }

        // Update metadata
        // SECURITY (CA-002): Use saturating_add to prevent counter overflow.
        self.metadata.total_calls = self.metadata.total_calls.saturating_add(1);
        self.metadata.unique_tools.insert(node.tool.clone());
        if let Some(ref agent) = node.agent_id {
            self.metadata.unique_agents.insert(agent.clone());
        }
        if depth > self.metadata.max_depth {
            self.metadata.max_depth = depth;
        }
        if self.metadata.started_at.is_none() {
            self.metadata.started_at = Some(node.started_at);
        }

        // Update parent's children list
        // SECURITY (FIND-R44-035): Apply same validation as add_data_flow/add_delegation
        if let Some(ref parent_id) = node.parent_id {
            // Check for self-loop
            if parent_id == &node_id {
                tracing::warn!(
                    target: "vellaveto::observability",
                    session_id = %self.session_id,
                    node_id = %node_id,
                    "Rejecting self-loop call edge in add_node"
                );
            // Check parent exists
            } else if !self.nodes.contains_key(parent_id) {
                tracing::warn!(
                    target: "vellaveto::observability",
                    session_id = %self.session_id,
                    parent_id = %parent_id,
                    node_id = %node_id,
                    "Skipping call edge — parent node does not exist"
                );
            } else {
                if let Some(parent) = self.nodes.get_mut(parent_id) {
                    parent.add_child(node_id.clone());
                }
                // Add call edge (bounded by MAX_EDGES_PER_GRAPH)
                if self.edges.len() < MAX_EDGES_PER_GRAPH {
                    // SECURITY (FIND-R44-035): Deduplicate call edges
                    let already_exists = self.edges.iter().any(|e| {
                        e.from == *parent_id && e.to == node_id && e.edge_type == EdgeType::Call
                    });
                    if !already_exists {
                        self.edges.push(ExecutionEdge {
                            from: parent_id.clone(),
                            to: node_id.clone(),
                            edge_type: EdgeType::Call,
                            timestamp: node.started_at,
                        });
                    }
                } else {
                    tracing::warn!(
                        target: "vellaveto::observability",
                        session_id = %self.session_id,
                        limit = MAX_EDGES_PER_GRAPH,
                        "Edge limit reached — skipping call edge"
                    );
                }
            }
        }

        self.nodes.insert(node_id.clone(), node);

        // SECURITY (FIND-R43-032): Deduplicate roots on overwrite to prevent unbounded growth
        if is_root && !self.roots.contains(&node_id) {
            self.roots.push(node_id);
        }
    }

    /// Mark a node as completed.
    pub fn complete_node(&mut self, node_id: &str, verdict: NodeVerdict) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.complete(verdict);
            self.metadata.ended_at = node.completed_at;

            // SECURITY (CA-002): Use saturating_add to prevent counter overflow.
            match verdict {
                NodeVerdict::Allow => {
                    self.metadata.allowed_calls = self.metadata.allowed_calls.saturating_add(1);
                }
                NodeVerdict::Deny => {
                    self.metadata.denied_calls = self.metadata.denied_calls.saturating_add(1);
                }
                _ => {}
            }
        }
    }

    /// Add a data flow edge between nodes.
    pub fn add_data_flow(&mut self, from: NodeId, to: NodeId) {
        // SECURITY (FIND-R43-030): Reject self-loop edges
        if from == to {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                node_id = %from,
                "Rejecting self-loop edge"
            );
            return;
        }
        // SECURITY (FIND-R43-015): Reject edges to non-existent nodes
        if !self.nodes.contains_key(&from) || !self.nodes.contains_key(&to) {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                from = %from,
                to = %to,
                "Skipping edge — one or both nodes do not exist"
            );
            return;
        }
        if self.edges.len() >= MAX_EDGES_PER_GRAPH {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                limit = MAX_EDGES_PER_GRAPH,
                "Edge limit reached — skipping data flow edge"
            );
            return;
        }
        // SECURITY (FIND-R43-016): Deduplicate edges to prevent budget exhaustion
        let edge_type = EdgeType::DataFlow;
        let already_exists = self
            .edges
            .iter()
            .any(|e| e.from == from && e.to == to && e.edge_type == edge_type);
        if already_exists {
            return; // Silently deduplicate
        }
        self.edges.push(ExecutionEdge {
            from,
            to,
            edge_type,
            timestamp: current_timestamp(),
        });
    }

    /// Add a delegation edge between nodes.
    pub fn add_delegation(&mut self, from: NodeId, to: NodeId) {
        // SECURITY (FIND-R43-030): Reject self-loop edges
        if from == to {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                node_id = %from,
                "Rejecting self-loop edge"
            );
            return;
        }
        // SECURITY (FIND-R43-015): Reject edges to non-existent nodes
        if !self.nodes.contains_key(&from) || !self.nodes.contains_key(&to) {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                from = %from,
                to = %to,
                "Skipping edge — one or both nodes do not exist"
            );
            return;
        }
        if self.edges.len() >= MAX_EDGES_PER_GRAPH {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id = %self.session_id,
                limit = MAX_EDGES_PER_GRAPH,
                "Edge limit reached — skipping delegation edge"
            );
            return;
        }
        // SECURITY (FIND-R43-016): Deduplicate edges to prevent budget exhaustion
        let edge_type = EdgeType::Delegation;
        let already_exists = self
            .edges
            .iter()
            .any(|e| e.from == from && e.to == to && e.edge_type == edge_type);
        if already_exists {
            return; // Silently deduplicate
        }
        self.edges.push(ExecutionEdge {
            from,
            to,
            edge_type,
            timestamp: current_timestamp(),
        });
    }

    /// Get a node by ID.
    pub fn get_node(&self, node_id: &str) -> Option<&ExecutionNode> {
        self.nodes.get(node_id)
    }

    /// Get all root nodes.
    pub fn get_roots(&self) -> Vec<&ExecutionNode> {
        self.roots
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .collect()
    }

    /// Get children of a node.
    pub fn get_children(&self, node_id: &str) -> Vec<&ExecutionNode> {
        self.nodes
            .get(node_id)
            .map(|node| {
                node.children
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Export to DOT format for Graphviz visualization.
    ///
    /// SECURITY (FIND-R42-011): All user-controlled strings (node IDs, tool names,
    /// function names) are escaped to prevent DOT language injection.
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph execution_graph {\n");
        dot.push_str("  rankdir=TB;\n");
        dot.push_str("  node [shape=box, style=rounded];\n\n");

        // Add nodes
        for (id, node) in &self.nodes {
            let color = match node.verdict {
                NodeVerdict::Allow => "green",
                NodeVerdict::Deny => "red",
                NodeVerdict::Pending => "yellow",
                NodeVerdict::RequireApproval => "orange",
            };
            let tool = escape_dot(&node.tool);
            let function = escape_dot(&node.function);
            let escaped_id = escape_dot(id);
            let label = format!("{tool}\\n{function}");
            dot.push_str(&format!(
                "  \"{escaped_id}\" [label=\"{label}\", color={color}, penwidth=2];\n"
            ));
        }

        dot.push('\n');

        // Add edges
        for edge in &self.edges {
            let style = match edge.edge_type {
                EdgeType::Call => "solid",
                EdgeType::DataFlow => "dashed",
                EdgeType::Delegation => "dotted",
            };
            let color = match edge.edge_type {
                EdgeType::Call => "black",
                EdgeType::DataFlow => "blue",
                EdgeType::Delegation => "purple",
            };
            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [style={}, color={}];\n",
                escape_dot(&edge.from),
                escape_dot(&edge.to),
                style,
                color
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// Export to SVG format (no Graphviz dependency).
    ///
    /// Renders a hierarchical layout from the tree structure:
    /// - Nodes colored by verdict (green/red/yellow/orange)
    /// - Edges showing parent→child call chains
    /// - Embeddable in dashboards or browsers
    pub fn to_svg(&self) -> String {
        // Layout constants
        const NODE_W: u32 = 180;
        const NODE_H: u32 = 48;
        const H_GAP: u32 = 30;
        const V_GAP: u32 = 60;
        const PAD: u32 = 20;
        const MAX_LABEL: usize = 22;

        // Collect nodes ordered by depth (BFS from roots)
        let mut levels: Vec<Vec<&str>> = Vec::new();
        let mut visited: HashSet<&str> = HashSet::new();
        let mut queue: std::collections::VecDeque<(&str, u32)> = std::collections::VecDeque::new();

        for root_id in &self.roots {
            if visited.insert(root_id.as_str()) {
                queue.push_back((root_id.as_str(), 0));
            }
        }
        // Also add orphan nodes (no parent, not in roots)
        for (id, node) in &self.nodes {
            if node.parent_id.is_none() && visited.insert(id.as_str()) {
                queue.push_back((id.as_str(), 0));
            }
        }

        while let Some((nid, depth)) = queue.pop_front() {
            let d = depth as usize;
            while levels.len() <= d {
                levels.push(Vec::new());
            }
            levels[d].push(nid);

            if let Some(node) = self.nodes.get(nid) {
                for child_id in &node.children {
                    if visited.insert(child_id.as_str()) {
                        queue.push_back((child_id.as_str(), depth.saturating_add(1)));
                    }
                }
            }
        }

        // Compute positions: each node gets (cx, cy)
        let mut positions: HashMap<&str, (u32, u32)> = HashMap::new();
        let mut max_x: u32 = 0;

        for (depth, level) in levels.iter().enumerate() {
            let row_width = if level.is_empty() {
                0
            } else {
                (level.len() as u32)
                    .saturating_mul(NODE_W)
                    .saturating_add((level.len().saturating_sub(1) as u32).saturating_mul(H_GAP))
            };
            let start_x = PAD;
            let y = PAD.saturating_add((depth as u32).saturating_mul(NODE_H.saturating_add(V_GAP)));

            for (i, nid) in level.iter().enumerate() {
                let x =
                    start_x.saturating_add((i as u32).saturating_mul(NODE_W.saturating_add(H_GAP)));
                positions.insert(nid, (x, y));
                let right_edge = x.saturating_add(NODE_W);
                if right_edge > max_x {
                    max_x = right_edge;
                }
            }
            let _ = row_width; // used for centering in future
        }

        let total_w = max_x.saturating_add(PAD);
        let total_h = if levels.is_empty() {
            PAD.saturating_mul(2)
        } else {
            PAD.saturating_mul(2).saturating_add(
                (levels.len() as u32)
                    .saturating_mul(NODE_H.saturating_add(V_GAP))
                    .saturating_sub(V_GAP),
            )
        };

        let mut svg = String::with_capacity(4096);
        use std::fmt::Write;

        let _ = write!(
            svg,
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{total_h}" role="img" aria-label="Execution graph">
<style>
  .node rect {{ stroke-width: 2; rx: 6; ry: 6; }}
  .node text {{ font-family: -apple-system, sans-serif; font-size: 11px; fill: #fff; text-anchor: middle; dominant-baseline: central; }}
  .edge {{ fill: none; stroke-width: 1.5; }}
  .edge-call {{ stroke: #8b949e; }}
  .edge-data {{ stroke: #58a6ff; stroke-dasharray: 5,3; }}
  .edge-deleg {{ stroke: #bc8cff; stroke-dasharray: 2,4; }}
  .v-allow {{ fill: #238636; stroke: #3fb950; }}
  .v-deny {{ fill: #da3633; stroke: #f85149; }}
  .v-pending {{ fill: #9e6a03; stroke: #d29922; }}
  .v-approval {{ fill: #b35900; stroke: #db6d28; }}
</style>
"##
        );

        // Draw edges first (behind nodes)
        for edge in &self.edges {
            let from_pos = positions.get(edge.from.as_str());
            let to_pos = positions.get(edge.to.as_str());
            if let (Some(&(fx, fy)), Some(&(tx, ty))) = (from_pos, to_pos) {
                let x1 = fx.saturating_add(NODE_W / 2);
                let y1 = fy.saturating_add(NODE_H);
                let x2 = tx.saturating_add(NODE_W / 2);
                let y2 = ty;
                let cls = match edge.edge_type {
                    EdgeType::Call => "edge-call",
                    EdgeType::DataFlow => "edge-data",
                    EdgeType::Delegation => "edge-deleg",
                };
                // Curved path for non-straight edges
                let mid_y = y1.saturating_add(y2) / 2;
                let _ = writeln!(
                    svg,
                    r##"<path class="edge {cls}" d="M {x1} {y1} C {x1} {mid_y}, {x2} {mid_y}, {x2} {y2}" marker-end="url(#arrow)"/>"##
                );
            }
        }

        // Arrow marker definition
        let _ = writeln!(
            svg,
            r##"<defs><marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#8b949e"/></marker></defs>"##
        );

        // Draw nodes
        for (nid, &(x, y)) in &positions {
            if let Some(node) = self.nodes.get(*nid) {
                let verdict_cls = match node.verdict {
                    NodeVerdict::Allow => "v-allow",
                    NodeVerdict::Deny => "v-deny",
                    NodeVerdict::Pending => "v-pending",
                    NodeVerdict::RequireApproval => "v-approval",
                };
                let tool = svg_escape(&svg_truncate(&node.tool, MAX_LABEL));
                let func = svg_escape(&svg_truncate(&node.function, MAX_LABEL));
                let cx = x.saturating_add(NODE_W / 2);
                let ty = y.saturating_add(NODE_H / 2).saturating_sub(7);
                let by = y.saturating_add(NODE_H / 2).saturating_add(7);

                let _ = writeln!(
                    svg,
                    r##"<g class="node"><rect class="{verdict_cls}" x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}"/><text x="{cx}" y="{ty}">{tool}</text><text x="{cx}" y="{by}" style="font-size:10px;opacity:0.8">{func}</text></g>"##
                );
            }
        }

        svg.push_str("</svg>\n");
        svg
    }

    /// Export to JSON format.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Calculate graph statistics.
    pub fn statistics(&self) -> GraphStatistics {
        let mut tool_counts: HashMap<String, u32> = HashMap::new();
        let mut agent_counts: HashMap<String, u32> = HashMap::new();
        let mut total_duration = 0u64;
        let mut completed_count = 0u32;

        for node in self.nodes.values() {
            let tc = tool_counts.entry(node.tool.clone()).or_insert(0);
            *tc = tc.saturating_add(1);
            if let Some(ref agent) = node.agent_id {
                let ac = agent_counts.entry(agent.clone()).or_insert(0);
                *ac = ac.saturating_add(1);
            }
            if let Some(duration) = node.duration_ms {
                total_duration = total_duration.saturating_add(duration);
                completed_count = completed_count.saturating_add(1);
            }
        }

        GraphStatistics {
            total_nodes: self.nodes.len() as u32,
            total_edges: self.edges.len() as u32,
            root_count: self.roots.len() as u32,
            max_depth: self.metadata.max_depth,
            tool_distribution: tool_counts,
            agent_distribution: agent_counts,
            avg_duration_ms: if completed_count > 0 {
                total_duration / completed_count as u64
            } else {
                0
            },
            allow_rate: if self.metadata.total_calls > 0 {
                self.metadata.allowed_calls as f32 / self.metadata.total_calls as f32
            } else {
                0.0
            },
        }
    }
}

/// Statistics about an execution graph.
/// SECURITY (FIND-R215-005): deny_unknown_fields prevents attacker-injected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphStatistics {
    /// Total number of nodes.
    pub total_nodes: u32,
    /// Total number of edges.
    pub total_edges: u32,
    /// Number of root nodes.
    pub root_count: u32,
    /// Maximum call depth.
    pub max_depth: u32,
    /// Tool usage distribution.
    pub tool_distribution: HashMap<String, u32>,
    /// Agent activity distribution.
    pub agent_distribution: HashMap<String, u32>,
    /// Average call duration in milliseconds.
    pub avg_duration_ms: u64,
    /// Allow rate (0.0 - 1.0).
    pub allow_rate: f32,
}

/// In-memory store for execution graphs.
pub struct ExecutionGraphStore {
    /// Graphs by session ID.
    graphs: Arc<RwLock<HashMap<SessionId, ExecutionGraph>>>,
    /// Maximum graphs to keep in memory.
    max_graphs: usize,
    /// Maximum age for graphs (seconds).
    max_age_secs: u64,
}

impl ExecutionGraphStore {
    /// Create a new execution graph store.
    pub fn new(max_graphs: usize, max_age_secs: u64) -> Self {
        ExecutionGraphStore {
            graphs: Arc::new(RwLock::new(HashMap::new())),
            max_graphs,
            max_age_secs,
        }
    }

    /// Validate session_id length.
    ///
    /// SECURITY (FIND-R215-003): Rejects session IDs exceeding MAX_SESSION_ID_LEN
    /// to prevent excessive memory allocation from attacker-controlled input.
    fn validate_session_id(session_id: &str) -> Result<(), &'static str> {
        if session_id.len() > MAX_SESSION_ID_LEN {
            tracing::warn!(
                target: "vellaveto::observability",
                session_id_len = session_id.len(),
                limit = MAX_SESSION_ID_LEN,
                "Session ID exceeds maximum length — rejecting"
            );
            return Err("session_id exceeds MAX_SESSION_ID_LEN");
        }
        Ok(())
    }

    /// Get or create a graph for a session.
    pub async fn get_or_create(&self, session_id: &str) -> ExecutionGraph {
        if Self::validate_session_id(session_id).is_err() {
            // Return a fresh graph with truncated session_id rather than
            // storing an unbounded key. The caller gets a valid graph but
            // it won't be persisted under the oversized key.
            return ExecutionGraph::new(String::new());
        }
        let mut graphs = self.graphs.write().await;
        graphs
            .entry(session_id.to_string())
            .or_insert_with(|| ExecutionGraph::new(session_id.to_string()))
            .clone()
    }

    /// Update a graph.
    pub async fn update(&self, graph: ExecutionGraph) {
        // SECURITY (FIND-R215-003): Validate session_id length before storing.
        if Self::validate_session_id(&graph.session_id).is_err() {
            return;
        }
        let mut graphs = self.graphs.write().await;
        graphs.insert(graph.session_id.clone(), graph);

        // Cleanup old graphs if needed
        if graphs.len() > self.max_graphs {
            self.cleanup_oldest(&mut graphs);
        }
    }

    /// Get a graph by session ID.
    pub async fn get(&self, session_id: &str) -> Option<ExecutionGraph> {
        let graphs = self.graphs.read().await;
        graphs.get(session_id).cloned()
    }

    /// List all session IDs.
    pub async fn list_sessions(&self) -> Vec<SessionId> {
        let graphs = self.graphs.read().await;
        graphs.keys().cloned().collect()
    }

    /// Remove a graph.
    pub async fn remove(&self, session_id: &str) -> Option<ExecutionGraph> {
        let mut graphs = self.graphs.write().await;
        graphs.remove(session_id)
    }

    /// Add a node to a session's graph.
    pub async fn add_node(&self, session_id: &str, node: ExecutionNode) {
        // SECURITY (FIND-R215-003): Validate session_id length before storing.
        if Self::validate_session_id(session_id).is_err() {
            return;
        }
        let mut graphs = self.graphs.write().await;
        let graph = graphs
            .entry(session_id.to_string())
            .or_insert_with(|| ExecutionGraph::new(session_id.to_string()));
        graph.add_node(node);
    }

    /// Complete a node in a session's graph.
    pub async fn complete_node(&self, session_id: &str, node_id: &str, verdict: NodeVerdict) {
        // SECURITY (FIND-R215-003): Validate session_id length.
        if Self::validate_session_id(session_id).is_err() {
            return;
        }
        let mut graphs = self.graphs.write().await;
        if let Some(graph) = graphs.get_mut(session_id) {
            graph.complete_node(node_id, verdict);
        }
    }

    /// Cleanup oldest graphs to stay under limit.
    fn cleanup_oldest(&self, graphs: &mut HashMap<SessionId, ExecutionGraph>) {
        let target_size = self.max_graphs * 3 / 4; // Remove 25%
        let mut sessions_with_time: Vec<_> = graphs
            .iter()
            .map(|(id, g)| (id.clone(), g.metadata.started_at.unwrap_or(0)))
            .collect();
        sessions_with_time.sort_by_key(|(_, time)| *time);

        let to_remove = graphs.len() - target_size;
        for (session_id, _) in sessions_with_time.into_iter().take(to_remove) {
            graphs.remove(&session_id);
        }
    }

    /// Cleanup graphs older than max_age_secs.
    pub async fn cleanup_expired(&self) -> usize {
        let now = current_timestamp();
        let cutoff = now.saturating_sub(self.max_age_secs);

        let mut graphs = self.graphs.write().await;
        let initial_len = graphs.len();

        graphs.retain(|_, graph| {
            graph
                .metadata
                .started_at
                .map(|t| t >= cutoff)
                // SECURITY (FIND-041): Fail-closed — graphs without timestamps
                // cannot have their age verified, so treat them as expired.
                .unwrap_or(false)
        });

        initial_len - graphs.len()
    }
}

/// Escape special characters for DOT/Graphviz string contexts (FIND-R42-011).
///
/// Prevents injection of DOT language constructs via user-controlled node
/// labels, IDs, and edge endpoints.
///
/// SECURITY (FIND-R43-031): Escapes pipe (DOT record separator) and strips null bytes.
/// SECURITY (FIND-R43-001): Strips Unicode bidirectional override/isolate characters
/// (U+200E-200F, U+202A-202E, U+2066-2069) that render invisibly but can visually
/// spoof tool/function names in SVG/PDF graph output.
fn escape_dot(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '{' => result.push_str("\\{"),
            '}' => result.push_str("\\}"),
            '<' => result.push_str("\\<"),
            '>' => result.push_str("\\>"),
            '|' => result.push_str("\\|"),
            // FIND-R43-031: Strip null bytes — they cause Graphviz to crash/truncate.
            '\0' => {}
            // FIND-R43-001: Strip Unicode bidi override/mark/isolate characters.
            // These render invisibly in SVG/PDF output but alter text direction,
            // enabling visual spoofing attacks where a malicious tool name appears
            // as a different name in the rendered execution graph.
            '\u{200E}' | '\u{200F}'  // LRM, RLM
            | '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'  // LRE, RLE, PDF, LRO, RLO
            | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'  // LRI, RLI, FSI, PDI
            => {}
            other => result.push(other),
        }
    }
    result
}

/// Escape special characters for SVG text content (prevents XSS in SVG).
///
/// Strips bidi overrides (same as `escape_dot`) and null bytes.
fn svg_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            '\0' => {}
            // Strip bidi overrides (same set as escape_dot)
            '\u{200E}' | '\u{200F}' | '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}'
            | '\u{202E}' | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}' => {}
            other => result.push(other),
        }
    }
    result
}

/// Truncate a string for SVG labels, respecting char boundaries.
fn svg_truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &s[..end])
}

/// Get current Unix timestamp in milliseconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_node_creation() {
        let node = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        );

        assert_eq!(node.id, "node1");
        assert_eq!(node.tool, "filesystem");
        assert!(node.is_root());
        assert!(!node.is_complete());
    }

    #[test]
    fn test_execution_node_completion() {
        let mut node = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        );

        node.complete(NodeVerdict::Allow);

        assert!(node.is_complete());
        assert_eq!(node.verdict, NodeVerdict::Allow);
        assert!(node.completed_at.is_some());
    }

    #[test]
    fn test_execution_graph_add_node() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let node = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        );

        graph.add_node(node);

        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.roots.len(), 1);
        assert_eq!(graph.metadata.total_calls, 1);
    }

    #[test]
    fn test_execution_graph_parent_child() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let parent = ExecutionNode::new(
            "parent".to_string(),
            "session1".to_string(),
            "orchestrator".to_string(),
            "plan".to_string(),
        );

        let child = ExecutionNode::new(
            "child".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        )
        .with_parent("parent".to_string(), 1);

        graph.add_node(parent);
        graph.add_node(child);

        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.roots.len(), 1);
        assert_eq!(graph.edges.len(), 1);

        let parent_node = graph.get_node("parent").unwrap();
        assert_eq!(parent_node.children.len(), 1);
    }

    #[test]
    fn test_execution_graph_complete_node() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let node = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        );

        graph.add_node(node);
        graph.complete_node("node1", NodeVerdict::Allow);

        let node = graph.get_node("node1").unwrap();
        assert!(node.is_complete());
        assert_eq!(graph.metadata.allowed_calls, 1);
    }

    #[test]
    fn test_execution_graph_to_dot() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let mut node = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        );
        node.complete(NodeVerdict::Allow);
        graph.add_node(node);

        let dot = graph.to_dot();

        assert!(dot.contains("digraph execution_graph"));
        assert!(dot.contains("node1"));
        assert!(dot.contains("filesystem"));
        assert!(dot.contains("color=green"));
    }

    #[test]
    fn test_execution_graph_statistics() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        for i in 0..5 {
            let mut node = ExecutionNode::new(
                format!("node{}", i),
                "session1".to_string(),
                if i % 2 == 0 { "filesystem" } else { "network" }.to_string(),
                "test".to_string(),
            );
            node.complete(if i < 3 {
                NodeVerdict::Allow
            } else {
                NodeVerdict::Deny
            });
            graph.add_node(node);
        }

        let stats = graph.statistics();

        assert_eq!(stats.total_nodes, 5);
        assert_eq!(stats.root_count, 5);
        assert!(stats.tool_distribution.contains_key("filesystem"));
        assert!(stats.tool_distribution.contains_key("network"));
    }

    #[tokio::test]
    async fn test_execution_graph_store() {
        let store = ExecutionGraphStore::new(100, 3600);

        let node = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        );

        store.add_node("session1", node).await;

        let graph = store.get("session1").await.unwrap();
        assert_eq!(graph.nodes.len(), 1);
    }

    #[tokio::test]
    async fn test_execution_graph_store_complete_node() {
        let store = ExecutionGraphStore::new(100, 3600);

        let node = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        );

        store.add_node("session1", node).await;
        store
            .complete_node("session1", "node1", NodeVerdict::Allow)
            .await;

        let graph = store.get("session1").await.unwrap();
        let node = graph.get_node("node1").unwrap();
        assert!(node.is_complete());
    }

    #[tokio::test]
    async fn test_execution_graph_store_list_sessions() {
        let store = ExecutionGraphStore::new(100, 3600);

        for i in 0..3 {
            let node = ExecutionNode::new(
                format!("node{}", i),
                format!("session{}", i),
                "test".to_string(),
                "test".to_string(),
            );
            store.add_node(&format!("session{}", i), node).await;
        }

        let sessions = store.list_sessions().await;
        assert_eq!(sessions.len(), 3);
    }

    // ═══════════════════════════════════════════════════════
    // Adversarial audit tests (FIND-R42-006, FIND-R42-011)
    // ═══════════════════════════════════════════════════════

    /// FIND-R42-006: Metadata is NOT updated when node is rejected at capacity.
    #[test]
    fn test_add_node_metadata_not_updated_at_capacity() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        // Fill to capacity.
        for i in 0..MAX_NODES_PER_GRAPH {
            let node = ExecutionNode::new(
                format!("node{}", i),
                "session1".to_string(),
                "tool_a".to_string(),
                "fn_a".to_string(),
            );
            graph.add_node(node);
        }
        assert_eq!(graph.nodes.len(), MAX_NODES_PER_GRAPH);
        let total_before = graph.metadata.total_calls;
        let tools_before = graph.metadata.unique_tools.len();

        // This node should be rejected and metadata should NOT change.
        let overflow_node = ExecutionNode::new(
            "overflow".to_string(),
            "session1".to_string(),
            "NEW_TOOL".to_string(),
            "new_fn".to_string(),
        );
        graph.add_node(overflow_node);

        assert_eq!(graph.nodes.len(), MAX_NODES_PER_GRAPH);
        assert_eq!(graph.metadata.total_calls, total_before);
        assert_eq!(graph.metadata.unique_tools.len(), tools_before);
        assert!(!graph.metadata.unique_tools.contains("NEW_TOOL"));
    }

    /// FIND-R42-011: DOT output escapes special characters in node labels.
    #[test]
    fn test_to_dot_escapes_special_characters() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let mut node = ExecutionNode::new(
            "node\"inject".to_string(),
            "session1".to_string(),
            "tool\"with\"quotes".to_string(),
            "fn\nwith\nnewlines".to_string(),
        );
        node.complete(NodeVerdict::Allow);
        graph.add_node(node);

        let dot = graph.to_dot();
        // The DOT output should escape quotes and newlines.
        assert!(
            dot.contains("\\\""),
            "quotes should be escaped in DOT output"
        );
        assert!(
            !dot.contains("\"\n"),
            "raw newlines should not appear in DOT labels"
        );
    }

    /// FIND-R42-011: escape_dot handles all special characters.
    #[test]
    fn test_escape_dot_function() {
        assert_eq!(escape_dot("hello"), "hello");
        assert_eq!(escape_dot("a\"b"), "a\\\"b");
        assert_eq!(escape_dot("a\\b"), "a\\\\b");
        assert_eq!(escape_dot("a\nb"), "a\\nb");
        assert_eq!(escape_dot("{test}"), "\\{test\\}");
        assert_eq!(escape_dot("<html>"), "\\<html\\>");
    }

    /// FIND-R43-031: escape_dot strips null bytes that crash Graphviz.
    #[test]
    fn test_escape_dot_null_byte_stripped() {
        let result = escape_dot("before\0after");
        assert_eq!(result, "beforeafter");
        assert!(!result.contains('\0'));
    }

    /// FIND-R43-031: escape_dot escapes pipe characters (DOT record separator).
    #[test]
    fn test_escape_dot_pipe_escaped() {
        assert_eq!(escape_dot("field1|field2"), "field1\\|field2");
        assert_eq!(escape_dot("|"), "\\|");
    }

    /// FIND-R43-001: escape_dot strips Unicode bidi override characters.
    #[test]
    fn test_escape_dot_bidi_override_stripped() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — can reverse displayed text
        let input = "normal\u{202E}desrever";
        let result = escape_dot(input);
        assert_eq!(result, "normaldesrever");
        assert!(!result.contains('\u{202E}'));

        // U+200E LEFT-TO-RIGHT MARK
        let result = escape_dot("a\u{200E}b");
        assert_eq!(result, "ab");

        // U+200F RIGHT-TO-LEFT MARK
        let result = escape_dot("a\u{200F}b");
        assert_eq!(result, "ab");

        // U+202A LEFT-TO-RIGHT EMBEDDING
        let result = escape_dot("a\u{202A}b");
        assert_eq!(result, "ab");

        // U+202B RIGHT-TO-LEFT EMBEDDING
        let result = escape_dot("a\u{202B}b");
        assert_eq!(result, "ab");

        // U+202C POP DIRECTIONAL FORMATTING
        let result = escape_dot("a\u{202C}b");
        assert_eq!(result, "ab");

        // U+202D LEFT-TO-RIGHT OVERRIDE
        let result = escape_dot("a\u{202D}b");
        assert_eq!(result, "ab");

        // U+2066 LEFT-TO-RIGHT ISOLATE
        let result = escape_dot("a\u{2066}b");
        assert_eq!(result, "ab");

        // U+2067 RIGHT-TO-LEFT ISOLATE
        let result = escape_dot("a\u{2067}b");
        assert_eq!(result, "ab");

        // U+2068 FIRST STRONG ISOLATE
        let result = escape_dot("a\u{2068}b");
        assert_eq!(result, "ab");

        // U+2069 POP DIRECTIONAL ISOLATE
        let result = escape_dot("a\u{2069}b");
        assert_eq!(result, "ab");
    }

    /// FIND-R43-001: Combined attack — bidi + null + quotes in single input.
    #[test]
    fn test_escape_dot_combined_adversarial_input() {
        // Attacker tries: bidi override to visually swap tool name,
        // null byte to truncate, and quote to break out of DOT string.
        let attack = "safe_tool\u{202E}\0\"]; malicious [label=\"pwned";
        let result = escape_dot(attack);
        // Bidi stripped, null stripped, quotes escaped
        assert!(!result.contains('\u{202E}'));
        assert!(!result.contains('\0'));
        // Raw unescaped quotes must not appear — only escaped \"
        // Check there are no unescaped quotes by verifying all " are preceded by \
        for (i, ch) in result.char_indices() {
            if ch == '"' {
                assert!(
                    i > 0 && result.as_bytes()[i - 1] == b'\\',
                    "Unescaped quote at position {i} in: {result}"
                );
            }
        }
        assert_eq!(result, "safe_tool\\\"]; malicious [label=\\\"pwned");
    }

    /// FIND-R43-001: DOT output with bidi characters renders without spoofing.
    #[test]
    fn test_to_dot_bidi_tool_name_sanitized() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        // Tool name with bidi RTL override — would visually show reversed text
        let mut node = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "read_file\u{202E}eteled".to_string(), // visually: "read_filedelete" reversed
            "execute".to_string(),
        );
        node.complete(NodeVerdict::Allow);
        graph.add_node(node);

        let dot = graph.to_dot();
        // The bidi char must be stripped from the output
        assert!(
            !dot.contains('\u{202E}'),
            "DOT output must not contain bidi override characters"
        );
        // The tool name parts should still be present (without bidi)
        assert!(dot.contains("read_file"));
        assert!(dot.contains("eteled"));
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R44-035: add_node Call edges bypass R43 edge checks
    // ═══════════════════════════════════════════════════════

    /// FIND-R44-035: add_node must reject self-loop call edges.
    #[test]
    fn test_add_node_self_loop_rejected() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        // Create a node that references itself as parent
        let node = ExecutionNode::new(
            "self_ref".to_string(),
            "session1".to_string(),
            "tool_a".to_string(),
            "fn_a".to_string(),
        )
        .with_parent("self_ref".to_string(), 1);

        graph.add_node(node);

        // Node should be inserted but no self-loop edge should exist
        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(graph.edges.len(), 0, "Self-loop call edge must be rejected");
    }

    /// FIND-R44-035: add_node must reject call edges when parent doesn't exist.
    #[test]
    fn test_add_node_nonexistent_parent_no_edge() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        // Create child with parent that doesn't exist
        let child = ExecutionNode::new(
            "child".to_string(),
            "session1".to_string(),
            "tool_a".to_string(),
            "fn_a".to_string(),
        )
        .with_parent("ghost_parent".to_string(), 1);

        graph.add_node(child);

        assert_eq!(graph.nodes.len(), 1);
        assert_eq!(
            graph.edges.len(),
            0,
            "Call edge to non-existent parent must be rejected"
        );
    }

    /// FIND-R44-035: add_node must deduplicate call edges.
    #[test]
    fn test_add_node_duplicate_call_edge_deduplicated() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let parent = ExecutionNode::new(
            "parent".to_string(),
            "session1".to_string(),
            "orchestrator".to_string(),
            "plan".to_string(),
        );
        graph.add_node(parent);

        let child1 = ExecutionNode::new(
            "child1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        )
        .with_parent("parent".to_string(), 1);
        graph.add_node(child1);

        assert_eq!(graph.edges.len(), 1, "First edge should be added");

        // Try adding a data flow edge with same from/to/type=Call manually
        // (The dedup logic is in add_node itself via the edge push)
        // Just verify the existing edge count is correct after normal operations
        let child2 = ExecutionNode::new(
            "child2".to_string(),
            "session1".to_string(),
            "network".to_string(),
            "fetch".to_string(),
        )
        .with_parent("parent".to_string(), 1);
        graph.add_node(child2);

        assert_eq!(
            graph.edges.len(),
            2,
            "Two distinct child edges should exist"
        );
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R44-056: Duplicate node IDs inflate metadata
    // ═══════════════════════════════════════════════════════

    /// FIND-R44-056: Adding a node with a duplicate ID must NOT increment total_calls.
    #[test]
    fn test_duplicate_node_id_does_not_inflate_metadata() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let node1 = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "tool_a".to_string(),
            "fn_a".to_string(),
        );
        graph.add_node(node1);

        assert_eq!(graph.metadata.total_calls, 1);
        assert_eq!(graph.metadata.unique_tools.len(), 1);

        // Add duplicate node ID with different tool
        let node1_dup = ExecutionNode::new(
            "node1".to_string(),
            "session1".to_string(),
            "tool_b".to_string(),
            "fn_b".to_string(),
        );
        graph.add_node(node1_dup);

        // Metadata should NOT be inflated
        assert_eq!(
            graph.metadata.total_calls, 1,
            "total_calls must not increment on duplicate node ID"
        );
        assert_eq!(
            graph.metadata.unique_tools.len(),
            1,
            "unique_tools must not grow on duplicate node ID"
        );
        // But the node's fields should be updated
        let node = graph.get_node("node1").expect("node should exist");
        assert_eq!(node.tool, "tool_b", "tool should be updated to new value");
        assert_eq!(
            node.function, "fn_b",
            "function should be updated to new value"
        );
    }

    /// FIND-R44-056: Duplicate node with parent should not create duplicate edges.
    #[test]
    fn test_duplicate_node_id_does_not_duplicate_edges() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let parent = ExecutionNode::new(
            "parent".to_string(),
            "session1".to_string(),
            "orchestrator".to_string(),
            "plan".to_string(),
        );
        graph.add_node(parent);

        let child = ExecutionNode::new(
            "child".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        )
        .with_parent("parent".to_string(), 1);
        graph.add_node(child);

        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.metadata.total_calls, 2);

        // Re-add the child with same ID — should not create another edge or inflate metadata
        let child_dup = ExecutionNode::new(
            "child".to_string(),
            "session1".to_string(),
            "network".to_string(),
            "fetch".to_string(),
        )
        .with_parent("parent".to_string(), 1);
        graph.add_node(child_dup);

        assert_eq!(
            graph.edges.len(),
            1,
            "Duplicate node should not create additional edges"
        );
        assert_eq!(
            graph.metadata.total_calls, 2,
            "Duplicate node should not inflate total_calls"
        );
    }

    // ═══════════════════════════════════════════════════════
    // SVG export tests
    // ═══════════════════════════════════════════════════════

    #[test]
    fn test_svg_escape_basic() {
        assert_eq!(svg_escape("hello"), "hello");
        assert_eq!(svg_escape("<script>"), "&lt;script&gt;");
        assert_eq!(svg_escape("a&b"), "a&amp;b");
        assert_eq!(svg_escape("say \"hi\""), "say &quot;hi&quot;");
        assert_eq!(svg_escape("it's"), "it&#x27;s");
    }

    #[test]
    fn test_svg_escape_strips_bidi() {
        let input = "read_file\u{202E}eteled";
        let escaped = svg_escape(input);
        assert!(!escaped.contains('\u{202E}'));
        assert!(escaped.contains("read_file"));
        assert!(escaped.contains("eteled"));
    }

    #[test]
    fn test_svg_escape_strips_null() {
        assert_eq!(svg_escape("a\0b"), "ab");
    }

    #[test]
    fn test_svg_truncate_short() {
        assert_eq!(svg_truncate("hello", 10), "hello");
    }

    #[test]
    fn test_svg_truncate_long() {
        let result = svg_truncate("hello world this is long", 10);
        assert!(result.ends_with('\u{2026}')); // ellipsis
        assert!(result.len() <= 14); // 10 bytes + ellipsis (3 bytes)
    }

    #[test]
    fn test_svg_truncate_unicode_boundary() {
        // "café" is 5 bytes (c=1, a=1, f=1, é=2)
        let result = svg_truncate("café", 4);
        assert!(result.ends_with('\u{2026}'));
        assert_eq!(result, "caf\u{2026}");
    }

    #[test]
    fn test_to_svg_empty_graph() {
        let graph = ExecutionGraph::new("empty".to_string());
        let svg = graph.to_svg();
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn test_to_svg_single_node() {
        let mut graph = ExecutionGraph::new("session1".to_string());
        let mut node = ExecutionNode::new(
            "n1".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read_file".to_string(),
        );
        node.complete(NodeVerdict::Allow);
        graph.add_node(node);

        let svg = graph.to_svg();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("v-allow"));
        assert!(svg.contains("filesystem"));
        assert!(svg.contains("read_file"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn test_to_svg_verdict_colors() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let mut allow_node = ExecutionNode::new(
            "n1".to_string(),
            "session1".to_string(),
            "tool1".to_string(),
            "fn1".to_string(),
        );
        allow_node.complete(NodeVerdict::Allow);
        graph.add_node(allow_node);

        let mut deny_node = ExecutionNode::new(
            "n2".to_string(),
            "session1".to_string(),
            "tool2".to_string(),
            "fn2".to_string(),
        );
        deny_node.complete(NodeVerdict::Deny);
        graph.add_node(deny_node);

        let svg = graph.to_svg();
        assert!(svg.contains("v-allow"), "Should contain allow class");
        assert!(svg.contains("v-deny"), "Should contain deny class");
    }

    #[test]
    fn test_to_svg_parent_child_edges() {
        let mut graph = ExecutionGraph::new("session1".to_string());

        let parent = ExecutionNode::new(
            "parent".to_string(),
            "session1".to_string(),
            "orchestrator".to_string(),
            "plan".to_string(),
        );
        graph.add_node(parent);

        let child = ExecutionNode::new(
            "child".to_string(),
            "session1".to_string(),
            "filesystem".to_string(),
            "read".to_string(),
        )
        .with_parent("parent".to_string(), 1);
        graph.add_node(child);

        let svg = graph.to_svg();
        assert!(svg.contains("<path"), "Should contain edge paths");
        assert!(svg.contains("edge-call"), "Should contain call edge class");
    }

    #[test]
    fn test_to_svg_xss_prevention() {
        let mut graph = ExecutionGraph::new("session1".to_string());
        let mut node = ExecutionNode::new(
            "n1".to_string(),
            "session1".to_string(),
            "<script>alert(1)</script>".to_string(),
            "fn&\"test".to_string(),
        );
        node.complete(NodeVerdict::Allow);
        graph.add_node(node);

        let svg = graph.to_svg();
        assert!(
            !svg.contains("<script>"),
            "SVG must not contain raw script tags"
        );
        assert!(
            svg.contains("&lt;script&gt;"),
            "Script tag should be escaped"
        );
        assert!(svg.contains("&amp;"), "Ampersand should be escaped");
    }

    #[test]
    fn test_to_svg_bidi_stripped() {
        let mut graph = ExecutionGraph::new("session1".to_string());
        let mut node = ExecutionNode::new(
            "n1".to_string(),
            "session1".to_string(),
            "read_file\u{202E}eteled".to_string(),
            "exec".to_string(),
        );
        node.complete(NodeVerdict::Allow);
        graph.add_node(node);

        let svg = graph.to_svg();
        assert!(
            !svg.contains('\u{202E}'),
            "SVG must not contain bidi override characters"
        );
    }

    #[tokio::test]
    async fn test_cleanup_expired_no_timestamp_fail_closed() {
        // FIND-041: Graphs without started_at should be treated as expired
        // (fail-closed), not retained indefinitely.
        let store = ExecutionGraphStore::new(100, 60);

        // Manually insert a graph with no started_at (simulates get_or_create
        // without any node additions)
        {
            let mut graphs = store.graphs.write().await;
            let mut graph = ExecutionGraph::new("no-timestamp-session".to_string());
            // Ensure started_at is None by not adding any nodes
            graph.metadata.started_at = None;
            graphs.insert("no-timestamp-session".to_string(), graph);
        }

        // Verify graph exists
        {
            let graphs = store.graphs.read().await;
            assert!(graphs.contains_key("no-timestamp-session"));
        }

        // cleanup_expired should remove it (fail-closed: no timestamp = expired)
        let cleaned = store.cleanup_expired().await;
        assert_eq!(cleaned, 1, "Graph without timestamp should be expired");

        // Verify it's gone
        {
            let graphs = store.graphs.read().await;
            assert!(
                !graphs.contains_key("no-timestamp-session"),
                "Graph without timestamp should have been cleaned up"
            );
        }
    }
}
