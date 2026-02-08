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

/// Unique identifier for a graph node.
pub type NodeId = String;

/// Unique identifier for a session.
pub type SessionId = String;

/// A node in the execution graph representing a single tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn new(
        id: NodeId,
        session_id: SessionId,
        tool: String,
        function: String,
    ) -> Self {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    pub fn add_node(&mut self, node: ExecutionNode) {
        let node_id = node.id.clone();
        let is_root = node.is_root();
        let depth = node.depth;

        // Update metadata
        self.metadata.total_calls += 1;
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
        if let Some(ref parent_id) = node.parent_id {
            if let Some(parent) = self.nodes.get_mut(parent_id) {
                parent.add_child(node_id.clone());
            }
            // Add call edge
            self.edges.push(ExecutionEdge {
                from: parent_id.clone(),
                to: node_id.clone(),
                edge_type: EdgeType::Call,
                timestamp: node.started_at,
            });
        }

        self.nodes.insert(node_id.clone(), node);

        if is_root {
            self.roots.push(node_id);
        }
    }

    /// Mark a node as completed.
    pub fn complete_node(&mut self, node_id: &str, verdict: NodeVerdict) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.complete(verdict);
            self.metadata.ended_at = node.completed_at;

            match verdict {
                NodeVerdict::Allow => self.metadata.allowed_calls += 1,
                NodeVerdict::Deny => self.metadata.denied_calls += 1,
                _ => {}
            }
        }
    }

    /// Add a data flow edge between nodes.
    pub fn add_data_flow(&mut self, from: NodeId, to: NodeId) {
        self.edges.push(ExecutionEdge {
            from,
            to,
            edge_type: EdgeType::DataFlow,
            timestamp: current_timestamp(),
        });
    }

    /// Add a delegation edge between nodes.
    pub fn add_delegation(&mut self, from: NodeId, to: NodeId) {
        self.edges.push(ExecutionEdge {
            from,
            to,
            edge_type: EdgeType::Delegation,
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
            let label = format!("{}\\n{}", node.tool, node.function);
            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\", color={}, penwidth=2];\n",
                id, label, color
            ));
        }

        dot.push_str("\n");

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
                edge.from, edge.to, style, color
            ));
        }

        dot.push_str("}\n");
        dot
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
            *tool_counts.entry(node.tool.clone()).or_insert(0) += 1;
            if let Some(ref agent) = node.agent_id {
                *agent_counts.entry(agent.clone()).or_insert(0) += 1;
            }
            if let Some(duration) = node.duration_ms {
                total_duration += duration;
                completed_count += 1;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Get or create a graph for a session.
    pub async fn get_or_create(&self, session_id: &str) -> ExecutionGraph {
        let mut graphs = self.graphs.write().await;
        graphs
            .entry(session_id.to_string())
            .or_insert_with(|| ExecutionGraph::new(session_id.to_string()))
            .clone()
    }

    /// Update a graph.
    pub async fn update(&self, graph: ExecutionGraph) {
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
        let mut graphs = self.graphs.write().await;
        let graph = graphs
            .entry(session_id.to_string())
            .or_insert_with(|| ExecutionGraph::new(session_id.to_string()));
        graph.add_node(node);
    }

    /// Complete a node in a session's graph.
    pub async fn complete_node(&self, session_id: &str, node_id: &str, verdict: NodeVerdict) {
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
                .unwrap_or(true)
        });

        initial_len - graphs.len()
    }
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
}
