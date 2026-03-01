// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Topology graph data model.
//!
//! Defines the core graph structure that represents the MCP tool ecosystem:
//! servers, tools, resources, and the edges between them.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

use crate::error::DiscoveryError;

// ═══════════════════════════════════════════════════════════════════════════════
// BOUNDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum number of servers in a topology.
pub const MAX_SERVERS: usize = 1_000;

/// Maximum number of tools per server.
pub const MAX_TOOLS_PER_SERVER: usize = 10_000;

/// Maximum total nodes (servers + tools + resources) in the graph.
pub const MAX_NODES: usize = 100_000;

/// Maximum length of a server name.
pub const MAX_SERVER_NAME_LEN: usize = 256;

/// Maximum length of a tool name.
pub const MAX_TOOL_NAME_LEN: usize = 256;

/// Maximum length of a tool description.
pub const MAX_TOOL_DESCRIPTION_LEN: usize = 4096;

/// Maximum length of a resource URI template.
pub const MAX_URI_TEMPLATE_LEN: usize = 4096;

/// Maximum number of output hints per tool.
pub const MAX_OUTPUT_HINTS: usize = 100;

/// Maximum number of inferred dependencies per tool.
pub const MAX_INFERRED_DEPS: usize = 100;

// ═══════════════════════════════════════════════════════════════════════════════
// NODE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// A node in the topology graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum TopologyNode {
    /// An MCP server.
    Server {
        /// Server identifier.
        name: String,
        /// Server version, if reported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        /// Server capabilities.
        #[serde(default)]
        capabilities: ServerCapabilities,
    },
    /// A tool exposed by an MCP server.
    Tool {
        /// Owning server name.
        server: String,
        /// Tool name.
        name: String,
        /// Human-readable description.
        description: String,
        /// JSON Schema for input parameters.
        input_schema: serde_json::Value,
        /// Inferred output field names (populated by inference engine).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        output_hints: Vec<String>,
        /// Inferred parameter dependencies on other tools' outputs.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inferred_deps: Vec<String>,
    },
    /// A resource exposed by an MCP server.
    Resource {
        /// Owning server name.
        server: String,
        /// URI template for the resource.
        uri_template: String,
        /// Human-readable name.
        name: String,
        /// MIME type, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
    },
}

impl TopologyNode {
    /// Returns the qualified name of this node.
    ///
    /// For servers: the server name.
    /// For tools: "server::tool".
    /// For resources: "server::resource_name".
    pub fn qualified_name(&self) -> String {
        match self {
            TopologyNode::Server { name, .. } => name.clone(),
            TopologyNode::Tool { server, name, .. } => format!("{server}::{name}"),
            TopologyNode::Resource { server, name, .. } => format!("{server}::{name}"),
        }
    }

    /// Returns the unqualified name (tool/resource name without server prefix).
    pub fn name(&self) -> &str {
        match self {
            TopologyNode::Server { name, .. }
            | TopologyNode::Tool { name, .. }
            | TopologyNode::Resource { name, .. } => name,
        }
    }

    /// Returns true if this is a Server node.
    pub fn is_server(&self) -> bool {
        matches!(self, TopologyNode::Server { .. })
    }

    /// Returns true if this is a Tool node.
    pub fn is_tool(&self) -> bool {
        matches!(self, TopologyNode::Tool { .. })
    }

    /// Returns true if this is a Resource node.
    pub fn is_resource(&self) -> bool {
        matches!(self, TopologyNode::Resource { .. })
    }
}

/// Capabilities reported by an MCP server during the initialize handshake.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerCapabilities {
    /// Server supports tools/list.
    #[serde(default)]
    pub tools: bool,
    /// Server supports resources/list.
    #[serde(default)]
    pub resources: bool,
    /// Server supports prompts/list.
    #[serde(default)]
    pub prompts: bool,
    /// Server supports logging.
    #[serde(default)]
    pub logging: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// An edge in the topology graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum TopologyEdge {
    /// Server owns a tool or resource.
    Owns,
    /// Inferred data flow between tools.
    DataFlow {
        /// Output field name from the source tool.
        from_field: String,
        /// Input parameter name on the target tool.
        to_param: String,
        /// Confidence score in [0.0, 1.0].
        confidence: f32,
        /// Human-readable reason for this edge.
        reason: String,
    },
    /// Tool consumes a resource.
    Consumes {
        /// The parameter that takes the resource URI.
        param: String,
    },
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATIC DECLARATIONS (for building topology from config)
// ═══════════════════════════════════════════════════════════════════════════════

/// A statically declared MCP server (from config, not live crawling).
#[derive(Debug, Clone)]
pub struct StaticServerDecl {
    /// Server identifier.
    pub name: String,
    /// Tools exposed by this server.
    pub tools: Vec<StaticToolDecl>,
    /// Resources exposed by this server.
    pub resources: Vec<StaticResourceDecl>,
}

/// A statically declared tool.
#[derive(Debug, Clone)]
pub struct StaticToolDecl {
    /// Tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for input parameters.
    pub input_schema: serde_json::Value,
}

/// A statically declared resource.
#[derive(Debug, Clone)]
pub struct StaticResourceDecl {
    /// URI template.
    pub uri_template: String,
    /// Human-readable name.
    pub name: String,
    /// MIME type, if known.
    pub mime_type: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOPOLOGY GRAPH
// ═══════════════════════════════════════════════════════════════════════════════

/// The MCP tool topology graph.
///
/// Represents the complete set of MCP servers, their tools and resources,
/// and the inferred data flow relationships between them.
pub struct TopologyGraph {
    /// The underlying directed graph.
    graph: DiGraph<TopologyNode, TopologyEdge>,
    /// Maps qualified names ("server::tool") to node indices.
    index: HashMap<String, NodeIndex>,
    /// Maps server names to their server node indices.
    server_index: HashMap<String, NodeIndex>,
    /// When this topology was built.
    crawled_at: SystemTime,
    /// SHA-256 fingerprint of the topology (set lazily).
    fingerprint: [u8; 32],
}

impl TopologyGraph {
    /// Build a topology from statically declared servers.
    ///
    /// This does not require live MCP connections — it builds the graph
    /// from configuration data alone.
    pub fn from_static(servers: Vec<StaticServerDecl>) -> Result<Self, DiscoveryError> {
        if servers.len() > MAX_SERVERS {
            return Err(DiscoveryError::ValidationError(format!(
                "Server count {} exceeds max {}",
                servers.len(),
                MAX_SERVERS
            )));
        }

        let mut graph = DiGraph::new();
        let mut index = HashMap::new();
        let mut server_index = HashMap::new();

        for server_decl in &servers {
            if server_decl.name.is_empty() {
                return Err(DiscoveryError::ValidationError(
                    "Server name must not be empty".to_string(),
                ));
            }
            if server_decl.name.len() > MAX_SERVER_NAME_LEN {
                return Err(DiscoveryError::ValidationError(format!(
                    "Server name '{}' length {} exceeds max {}",
                    server_decl.name,
                    server_decl.name.len(),
                    MAX_SERVER_NAME_LEN
                )));
            }
            if vellaveto_types::has_dangerous_chars(&server_decl.name) {
                return Err(DiscoveryError::ValidationError(format!(
                    "Server name '{}' contains control or format characters",
                    server_decl.name
                )));
            }
            // SECURITY (R231-DISC-7): Reject '::' in server names to prevent
            // qualified name parsing ambiguity in guard and diff modules.
            if server_decl.name.contains("::") {
                return Err(DiscoveryError::ValidationError(format!(
                    "Server name '{}' must not contain '::'",
                    server_decl.name
                )));
            }
            if server_index.contains_key(&server_decl.name) {
                return Err(DiscoveryError::ValidationError(format!(
                    "Duplicate server name: '{}'",
                    server_decl.name
                )));
            }
            if server_decl.tools.len() > MAX_TOOLS_PER_SERVER {
                return Err(DiscoveryError::ValidationError(format!(
                    "Server '{}' tool count {} exceeds max {}",
                    server_decl.name,
                    server_decl.tools.len(),
                    MAX_TOOLS_PER_SERVER
                )));
            }

            // Add server node
            let server_node = graph.add_node(TopologyNode::Server {
                name: server_decl.name.clone(),
                version: None,
                capabilities: ServerCapabilities::default(),
            });
            server_index.insert(server_decl.name.clone(), server_node);
            index.insert(server_decl.name.clone(), server_node);

            // Add tool nodes
            for tool_decl in &server_decl.tools {
                if tool_decl.name.is_empty() {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Tool name must not be empty on server '{}'",
                        server_decl.name
                    )));
                }
                if tool_decl.name.len() > MAX_TOOL_NAME_LEN {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Tool name '{}' length {} exceeds max {}",
                        tool_decl.name,
                        tool_decl.name.len(),
                        MAX_TOOL_NAME_LEN
                    )));
                }
                if vellaveto_types::has_dangerous_chars(&tool_decl.name) {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Tool name '{}' on server '{}' contains control or format characters",
                        tool_decl.name, server_decl.name
                    )));
                }
                // SECURITY (R231-DISC-1): Enforce description length bound to prevent
                // O(N^2) amplification in inference engine token comparison.
                if tool_decl.description.len() > MAX_TOOL_DESCRIPTION_LEN {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Tool '{}' description length {} exceeds max {}",
                        tool_decl.name,
                        tool_decl.description.len(),
                        MAX_TOOL_DESCRIPTION_LEN
                    )));
                }

                let qualified = format!("{}::{}", server_decl.name, tool_decl.name);
                if index.contains_key(&qualified) {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Duplicate qualified tool name: '{qualified}'"
                    )));
                }

                let tool_node = graph.add_node(TopologyNode::Tool {
                    server: server_decl.name.clone(),
                    name: tool_decl.name.clone(),
                    description: tool_decl.description.clone(),
                    input_schema: tool_decl.input_schema.clone(),
                    output_hints: Vec::new(),
                    inferred_deps: Vec::new(),
                });
                index.insert(qualified, tool_node);

                // Owns edge: server → tool
                graph.add_edge(server_node, tool_node, TopologyEdge::Owns);
            }

            // Add resource nodes
            for resource_decl in &server_decl.resources {
                if resource_decl.name.is_empty() {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Resource name must not be empty on server '{}'",
                        server_decl.name
                    )));
                }
                // SECURITY (R231-DISC-2): Validate resource name length and chars,
                // mirroring tool name validation for consistency.
                if resource_decl.name.len() > MAX_TOOL_NAME_LEN {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Resource name '{}' length {} exceeds max {}",
                        resource_decl.name,
                        resource_decl.name.len(),
                        MAX_TOOL_NAME_LEN
                    )));
                }
                if vellaveto_types::has_dangerous_chars(&resource_decl.name) {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Resource name '{}' on server '{}' contains control or format characters",
                        resource_decl.name, server_decl.name
                    )));
                }
                // SECURITY (R231-DISC-1): Enforce URI template length bound.
                if resource_decl.uri_template.len() > MAX_URI_TEMPLATE_LEN {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Resource '{}' URI template length {} exceeds max {}",
                        resource_decl.name,
                        resource_decl.uri_template.len(),
                        MAX_URI_TEMPLATE_LEN
                    )));
                }

                let qualified = format!("{}::{}", server_decl.name, resource_decl.name);
                if index.contains_key(&qualified) {
                    return Err(DiscoveryError::ValidationError(format!(
                        "Duplicate qualified name: '{qualified}'"
                    )));
                }

                let resource_node = graph.add_node(TopologyNode::Resource {
                    server: server_decl.name.clone(),
                    uri_template: resource_decl.uri_template.clone(),
                    name: resource_decl.name.clone(),
                    mime_type: resource_decl.mime_type.clone(),
                });
                index.insert(qualified, resource_node);

                // Owns edge: server → resource
                graph.add_edge(server_node, resource_node, TopologyEdge::Owns);
            }
        }

        if graph.node_count() > MAX_NODES {
            return Err(DiscoveryError::ValidationError(format!(
                "Total node count {} exceeds max {}",
                graph.node_count(),
                MAX_NODES
            )));
        }

        let mut topo = Self {
            graph,
            index,
            server_index,
            crawled_at: SystemTime::now(),
            fingerprint: [0u8; 32],
        };
        topo.fingerprint = topo.compute_fingerprint();
        Ok(topo)
    }

    /// Build an empty topology.
    pub fn empty() -> Self {
        Self {
            graph: DiGraph::new(),
            index: HashMap::new(),
            server_index: HashMap::new(),
            crawled_at: SystemTime::now(),
            fingerprint: [0u8; 32],
        }
    }

    /// Look up a tool by qualified name ("server::tool").
    pub fn find_tool(&self, qualified: &str) -> Option<&TopologyNode> {
        let idx = self.index.get(qualified)?;
        let node = &self.graph[*idx];
        if node.is_tool() {
            Some(node)
        } else {
            None
        }
    }

    /// Look up by unqualified name — returns all matches across servers.
    ///
    /// Returns vec of (qualified_name, node) pairs.
    pub fn find_tool_unqualified(&self, name: &str) -> Vec<(String, &TopologyNode)> {
        let mut results = Vec::new();
        for (qualified, idx) in &self.index {
            let node = &self.graph[*idx];
            if node.is_tool() && node.name() == name {
                results.push((qualified.clone(), node));
            }
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        results
    }

    /// All tools owned by a server.
    pub fn server_tools(&self, server: &str) -> Vec<&TopologyNode> {
        let server_idx = match self.server_index.get(server) {
            Some(idx) => *idx,
            None => return Vec::new(),
        };
        self.graph
            .neighbors(server_idx)
            .filter_map(|idx| {
                let node = &self.graph[idx];
                if node.is_tool() {
                    Some(node)
                } else {
                    None
                }
            })
            .collect()
    }

    /// All resource nodes owned by a server.
    pub fn server_resources(&self, server: &str) -> Vec<&TopologyNode> {
        let server_idx = match self.server_index.get(server) {
            Some(idx) => *idx,
            None => return Vec::new(),
        };
        self.graph
            .neighbors(server_idx)
            .filter_map(|idx| {
                let node = &self.graph[idx];
                if node.is_resource() {
                    Some(node)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Downstream tools reachable via DataFlow edges (transitive).
    pub fn downstream(&self, qualified: &str) -> Vec<String> {
        let start = match self.index.get(qualified) {
            Some(idx) => *idx,
            None => return Vec::new(),
        };

        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        let mut result = Vec::new();

        // Seed with direct DataFlow neighbors
        for edge in self.graph.edges(start) {
            if matches!(edge.weight(), TopologyEdge::DataFlow { .. }) {
                let target = edge.target();
                if visited.insert(target) {
                    queue.push_back(target);
                }
            }
        }

        while let Some(node_idx) = queue.pop_front() {
            let node = &self.graph[node_idx];
            result.push(node.qualified_name());

            for edge in self.graph.edges(node_idx) {
                if matches!(edge.weight(), TopologyEdge::DataFlow { .. }) {
                    let target = edge.target();
                    if visited.insert(target) {
                        queue.push_back(target);
                    }
                }
            }
        }

        result.sort();
        result
    }

    /// Upstream tools that feed into this tool via DataFlow edges (transitive).
    pub fn upstream(&self, qualified: &str) -> Vec<String> {
        let target = match self.index.get(qualified) {
            Some(idx) => *idx,
            None => return Vec::new(),
        };

        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        let mut result = Vec::new();

        // Find all edges pointing TO this node
        for edge in self.graph.edge_references() {
            if EdgeRef::target(&edge) == target
                && matches!(EdgeRef::weight(&edge), TopologyEdge::DataFlow { .. })
            {
                let source = EdgeRef::source(&edge);
                if visited.insert(source) {
                    queue.push_back(source);
                }
            }
        }

        while let Some(node_idx) = queue.pop_front() {
            let node: &TopologyNode = &self.graph[node_idx];
            result.push(node.qualified_name());

            for edge in self.graph.edge_references() {
                if EdgeRef::target(&edge) == node_idx
                    && matches!(EdgeRef::weight(&edge), TopologyEdge::DataFlow { .. })
                {
                    let source = EdgeRef::source(&edge);
                    if visited.insert(source) {
                        queue.push_back(source);
                    }
                }
            }
        }

        result.sort();
        result
    }

    /// Total node count (servers + tools + resources).
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Total edge count (Owns + DataFlow + Consumes).
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Number of servers in the topology.
    pub fn server_count(&self) -> usize {
        self.server_index.len()
    }

    /// All qualified tool names in the topology.
    pub fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .index
            .iter()
            .filter(|(_, idx)| self.graph[**idx].is_tool())
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names
    }

    /// All server names in the topology.
    pub fn server_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.server_index.keys().cloned().collect();
        names.sort();
        names
    }

    /// Reconstitute [`StaticServerDecl`] list from graph nodes.
    ///
    /// Iterates server nodes and collects their owned tools and resources.
    /// Useful for incremental merge operations (read → modify → rebuild).
    pub fn to_static(&self) -> Vec<StaticServerDecl> {
        let mut decls = Vec::new();
        for server_name in self.server_names() {
            let tools: Vec<StaticToolDecl> = self
                .server_tools(&server_name)
                .into_iter()
                .filter_map(|node| {
                    if let TopologyNode::Tool {
                        name,
                        description,
                        input_schema,
                        ..
                    } = node
                    {
                        Some(StaticToolDecl {
                            name: name.clone(),
                            description: description.clone(),
                            input_schema: input_schema.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect();

            let resources: Vec<StaticResourceDecl> = self
                .server_resources(&server_name)
                .into_iter()
                .filter_map(|node| {
                    if let TopologyNode::Resource {
                        uri_template,
                        name,
                        mime_type,
                        ..
                    } = node
                    {
                        Some(StaticResourceDecl {
                            uri_template: uri_template.clone(),
                            name: name.clone(),
                            mime_type: mime_type.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect();

            decls.push(StaticServerDecl {
                name: server_name,
                tools,
                resources,
            });
        }
        decls
    }

    /// When this topology was crawled.
    pub fn crawled_at(&self) -> SystemTime {
        self.crawled_at
    }

    /// Set the crawled_at timestamp (for testing or deserialization).
    pub fn set_crawled_at(&mut self, time: SystemTime) {
        self.crawled_at = time;
    }

    /// The SHA-256 fingerprint of this topology.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Hex-encoded fingerprint string.
    pub fn fingerprint_hex(&self) -> String {
        hex_encode(&self.fingerprint)
    }

    /// Access the underlying petgraph (read-only, for advanced queries).
    pub fn graph(&self) -> &DiGraph<TopologyNode, TopologyEdge> {
        &self.graph
    }

    /// Mutable access to the underlying petgraph (for inference engine).
    pub(crate) fn graph_mut(&mut self) -> &mut DiGraph<TopologyNode, TopologyEdge> {
        &mut self.graph
    }

    /// Access the qualified-name index.
    pub fn name_index(&self) -> &HashMap<String, NodeIndex> {
        &self.index
    }

    /// Recompute and store the fingerprint.
    pub fn recompute_fingerprint(&mut self) {
        self.fingerprint = self.compute_fingerprint();
    }

    /// Compute a deterministic SHA-256 fingerprint of the topology.
    ///
    /// Sorted by qualified tool names to ensure order independence.
    fn compute_fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Sort all qualified names for determinism
        let mut names: Vec<&String> = self.index.keys().collect();
        names.sort();

        for name in &names {
            hasher.update(name.as_bytes());
            hasher.update(b"\x00");

            if let Some(idx) = self.index.get(*name) {
                let node = &self.graph[*idx];
                // Hash node type tag
                match node {
                    TopologyNode::Server { version, .. } => {
                        hasher.update(b"S");
                        if let Some(v) = version {
                            hasher.update(v.as_bytes());
                        }
                    }
                    TopologyNode::Tool {
                        description,
                        input_schema,
                        ..
                    } => {
                        hasher.update(b"T");
                        hasher.update(description.as_bytes());
                        // Canonical JSON for schema
                        if let Ok(json) = serde_json::to_string(input_schema) {
                            hasher.update(json.as_bytes());
                        }
                    }
                    TopologyNode::Resource {
                        uri_template,
                        mime_type,
                        ..
                    } => {
                        hasher.update(b"R");
                        hasher.update(uri_template.as_bytes());
                        if let Some(mt) = mime_type {
                            hasher.update(mt.as_bytes());
                        }
                    }
                }
                hasher.update(b"\x01");
            }
        }

        // Hash edges (sorted for determinism)
        let mut edge_strings: Vec<String> = self
            .graph
            .edge_references()
            .map(|e| {
                let src = self.graph[EdgeRef::source(&e)].qualified_name();
                let tgt = self.graph[EdgeRef::target(&e)].qualified_name();
                let edge_type = match EdgeRef::weight(&e) {
                    TopologyEdge::Owns => "Owns".to_string(),
                    TopologyEdge::DataFlow {
                        from_field,
                        to_param,
                        ..
                    } => format!("DataFlow:{from_field}->{to_param}"),
                    TopologyEdge::Consumes { param } => format!("Consumes:{param}"),
                };
                format!("{src}->{tgt}:{edge_type}")
            })
            .collect();
        edge_strings.sort();

        for edge_str in &edge_strings {
            hasher.update(edge_str.as_bytes());
            hasher.update(b"\x02");
        }

        hasher.finalize().into()
    }
}

impl std::fmt::Debug for TopologyGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopologyGraph")
            .field("node_count", &self.graph.node_count())
            .field("edge_count", &self.graph.edge_count())
            .field("server_count", &self.server_index.len())
            .field("fingerprint", &self.fingerprint_hex())
            .finish()
    }
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
