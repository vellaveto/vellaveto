// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Inventory-oriented control-plane routes.
//!
//! These endpoints provide buyer-facing asset inventory views built from the
//! existing topology graph and shadow-agent detector without requiring new
//! storage or control-plane backends.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum number of agent IDs returned by inventory endpoints.
const MAX_INVENTORY_AGENTS: usize = 1_000;
/// Maximum number of server records returned by inventory endpoints.
const MAX_INVENTORY_SERVERS: usize = 250;
/// Maximum number of tool records returned by inventory endpoints.
const MAX_INVENTORY_TOOLS: usize = 2_000;
/// Maximum node count before the graph endpoint returns summaries only.
const MAX_INVENTORY_GRAPH_NODES: usize = 5_000;
/// Maximum number of characters returned in tool descriptions.
const MAX_DESCRIPTION_PREVIEW_LEN: usize = 160;
/// Maximum number of audit entries scanned when inferring agent-to-tool edges.
const MAX_INVENTORY_AUDIT_ENTRIES: usize = 50_000;
/// Maximum number of relationship edges returned by the graph endpoint.
const MAX_INVENTORY_RELATIONSHIPS: usize = 5_000;

fn truncate_preview(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }

    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

#[derive(Serialize)]
struct InventoryAgentsResponse {
    enabled: bool,
    count: usize,
    total: usize,
    truncated: bool,
    agent_ids: Vec<String>,
}

#[derive(Serialize)]
struct InventoryServerSummary {
    name: String,
    tool_count: usize,
    resource_count: usize,
}

#[derive(Serialize)]
struct InventoryServersResponse {
    enabled: bool,
    loaded: bool,
    count: usize,
    total: usize,
    truncated: bool,
    fingerprint: Option<String>,
    crawled_at_epoch_secs: Option<u64>,
    servers: Vec<InventoryServerSummary>,
}

#[derive(Clone, Serialize)]
struct InventoryToolSummary {
    qualified_name: String,
    server: String,
    name: String,
    description_preview: String,
    ownership_label: String,
    exposure_label: String,
}

#[derive(Serialize)]
struct InventoryToolsResponse {
    enabled: bool,
    loaded: bool,
    count: usize,
    total: usize,
    truncated: bool,
    fingerprint: Option<String>,
    tools: Vec<InventoryToolSummary>,
}

#[derive(Serialize)]
struct InventoryGraphServer {
    name: String,
    ownership_label: String,
    exposure_label: String,
    tools: Vec<InventoryToolSummary>,
    resources: Vec<String>,
}

#[derive(Serialize)]
struct InventoryAgentSummary {
    id: String,
    status: String,
    ownership_label: String,
    exposure_label: String,
    observed_edges: usize,
}

#[derive(Serialize)]
struct InventoryRelationship {
    source: String,
    target: String,
    relationship: String,
    ownership_label: String,
    exposure_label: String,
    detail: String,
}

#[derive(Serialize)]
struct InventoryGraphResponse {
    topology_enabled: bool,
    topology_loaded: bool,
    shadow_agents_enabled: bool,
    audit_loaded: bool,
    known_agent_count: usize,
    relationship_count: usize,
    fingerprint: Option<String>,
    server_count: usize,
    tool_count: usize,
    node_count: usize,
    edge_count: usize,
    truncated: bool,
    agents: Vec<InventoryAgentSummary>,
    tools: Vec<InventoryToolSummary>,
    relationships: Vec<InventoryRelationship>,
    servers: Vec<InventoryGraphServer>,
}

fn build_topology_tool_summary(
    server_name: &str,
    tool_name: &str,
    description: &str,
) -> InventoryToolSummary {
    InventoryToolSummary {
        qualified_name: format!("{server_name}::{tool_name}"),
        server: server_name.to_string(),
        name: tool_name.to_string(),
        description_preview: truncate_preview(description, MAX_DESCRIPTION_PREVIEW_LEN),
        ownership_label: "platform-owned".to_string(),
        exposure_label: "topology-managed".to_string(),
    }
}

fn build_observed_tool_summary(
    qualified_name: &str,
    registered_in_topology: bool,
) -> InventoryToolSummary {
    let (server, name) = match qualified_name.split_once("::") {
        Some((server, name)) => (server.to_string(), name.to_string()),
        None => (
            "observed".to_string(),
            qualified_name
                .strip_prefix("observed::")
                .unwrap_or(qualified_name)
                .to_string(),
        ),
    };
    let (ownership_label, exposure_label, description) = if registered_in_topology {
        (
            "platform-owned",
            "topology-managed",
            "Observed in audit activity",
        )
    } else {
        (
            "externally-sourced",
            "observed-only",
            "Observed in audit activity (not declared in topology)",
        )
    };

    InventoryToolSummary {
        qualified_name: qualified_name.to_string(),
        server,
        name,
        description_preview: truncate_preview(description, MAX_DESCRIPTION_PREVIEW_LEN),
        ownership_label: ownership_label.to_string(),
        exposure_label: exposure_label.to_string(),
    }
}

fn serialize_inventory<T: Serialize>(
    value: &T,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    serde_json::to_value(value).map(Json).map_err(|e| {
        tracing::error!("Failed to serialize inventory response: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to serialize inventory response".to_string(),
            }),
        )
    })
}

fn resolve_observed_tool_target(tool: &str, topology_tools: &[String]) -> (String, String) {
    if tool.contains("::") {
        return (tool.to_string(), "topology-qualified".to_string());
    }

    let matches = topology_tools
        .iter()
        .filter(|qualified| qualified.rsplit("::").next() == Some(tool))
        .cloned()
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        (matches[0].clone(), "topology-resolved".to_string())
    } else {
        (format!("observed::{tool}"), "observed-only".to_string())
    }
}

async fn build_agent_tool_relationships(
    state: &AppState,
    topology_tools: &[String],
) -> (bool, Vec<InventoryAgentSummary>, Vec<InventoryRelationship>) {
    let mut known_agent_ids = state
        .shadow_agent
        .as_ref()
        .map(|detector| detector.known_ids())
        .unwrap_or_default();
    known_agent_ids.sort();

    let mut agent_nodes = known_agent_ids
        .iter()
        .map(|agent_id| {
            (
                agent_id.clone(),
                InventoryAgentSummary {
                    id: agent_id.clone(),
                    status: "known".to_string(),
                    ownership_label: "platform-enrolled".to_string(),
                    exposure_label: "registered".to_string(),
                    observed_edges: 0,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    let known_lookup = known_agent_ids.into_iter().collect::<HashSet<_>>();

    let entries = match state.audit.load_entries().await {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!("inventory_graph: failed to load audit entries: {}", error);
            let mut agents = agent_nodes.into_values().collect::<Vec<_>>();
            agents.sort_by(|left, right| left.id.cmp(&right.id));
            return (false, agents, Vec::new());
        }
    };

    let mut relationships = Vec::new();
    let mut seen_edges = HashSet::new();
    for entry in entries.iter().rev().take(MAX_INVENTORY_AUDIT_ENTRIES) {
        let Some(agent_id) = entry
            .metadata
            .get("agent_id")
            .and_then(|value| value.as_str())
        else {
            continue;
        };
        let trimmed = agent_id.trim();
        if trimmed.is_empty() || trimmed.chars().any(crate::routes::is_unsafe_char) {
            continue;
        }

        let function = truncate_preview(&entry.action.function, 48);
        let (tool_target, exposure_label) =
            resolve_observed_tool_target(&entry.action.tool, topology_tools);
        let edge_key = format!("{trimmed}|{tool_target}|{function}");
        if !seen_edges.insert(edge_key) {
            continue;
        }

        let agent_entry =
            agent_nodes
                .entry(trimmed.to_string())
                .or_insert_with(|| InventoryAgentSummary {
                    id: trimmed.to_string(),
                    status: "observed".to_string(),
                    ownership_label: "externally-observed".to_string(),
                    exposure_label: "observed-only".to_string(),
                    observed_edges: 0,
                });
        agent_entry.observed_edges += 1;
        if known_lookup.contains(trimmed) {
            agent_entry.status = "known".to_string();
            agent_entry.exposure_label = "registered-and-observed".to_string();
        }

        relationships.push(InventoryRelationship {
            source: format!("agent:{trimmed}"),
            target: format!("tool:{tool_target}"),
            relationship: "invokes".to_string(),
            ownership_label: "agent-driven".to_string(),
            exposure_label,
            detail: format!("observed function '{function}'"),
        });

        if relationships.len() >= MAX_INVENTORY_RELATIONSHIPS {
            break;
        }
    }

    let mut agents = agent_nodes.into_values().collect::<Vec<_>>();
    agents.sort_by(|left, right| left.id.cmp(&right.id));
    (true, agents, relationships)
}

/// `GET /api/inventory/agents` — List known agents from the shadow-agent detector.
pub async fn inventory_agents(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let response = if let Some(detector) = state.shadow_agent.as_ref() {
        let mut agent_ids = detector.known_ids();
        agent_ids.sort();
        let total = agent_ids.len();
        let bounded = agent_ids
            .into_iter()
            .take(MAX_INVENTORY_AGENTS)
            .collect::<Vec<_>>();
        InventoryAgentsResponse {
            enabled: true,
            count: bounded.len(),
            total,
            truncated: total > MAX_INVENTORY_AGENTS,
            agent_ids: bounded,
        }
    } else {
        InventoryAgentsResponse {
            enabled: false,
            count: 0,
            total: 0,
            truncated: false,
            agent_ids: Vec::new(),
        }
    };

    serialize_inventory(&response)
}

/// `GET /api/inventory/mcp-servers` — Summarize MCP servers from the topology graph.
pub async fn inventory_mcp_servers(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let Some(guard) = state.topology_guard.as_ref() else {
        return serialize_inventory(&InventoryServersResponse {
            enabled: false,
            loaded: false,
            count: 0,
            total: 0,
            truncated: false,
            fingerprint: None,
            crawled_at_epoch_secs: None,
            servers: Vec::new(),
        });
    };

    let Some(topology) = guard.current() else {
        return serialize_inventory(&InventoryServersResponse {
            enabled: true,
            loaded: false,
            count: 0,
            total: 0,
            truncated: false,
            fingerprint: None,
            crawled_at_epoch_secs: None,
            servers: Vec::new(),
        });
    };

    let server_decls = topology.to_static();
    let total = server_decls.len();
    let servers = server_decls
        .into_iter()
        .take(MAX_INVENTORY_SERVERS)
        .map(|server| InventoryServerSummary {
            name: server.name,
            tool_count: server.tools.len(),
            resource_count: server.resources.len(),
        })
        .collect::<Vec<_>>();
    let crawled_at_epoch_secs = topology
        .crawled_at()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs());

    serialize_inventory(&InventoryServersResponse {
        enabled: true,
        loaded: true,
        count: servers.len(),
        total,
        truncated: total > MAX_INVENTORY_SERVERS,
        fingerprint: Some(topology.fingerprint_hex()),
        crawled_at_epoch_secs,
        servers,
    })
}

/// `GET /api/inventory/tools` — Flatten discovered tools into an inventory list.
pub async fn inventory_tools(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let Some(guard) = state.topology_guard.as_ref() else {
        return serialize_inventory(&InventoryToolsResponse {
            enabled: false,
            loaded: false,
            count: 0,
            total: 0,
            truncated: false,
            fingerprint: None,
            tools: Vec::new(),
        });
    };

    let Some(topology) = guard.current() else {
        return serialize_inventory(&InventoryToolsResponse {
            enabled: true,
            loaded: false,
            count: 0,
            total: 0,
            truncated: false,
            fingerprint: None,
            tools: Vec::new(),
        });
    };

    let mut tools = topology
        .to_static()
        .into_iter()
        .flat_map(|server| {
            let server_name = server.name;
            server.tools.into_iter().map(move |tool| {
                build_topology_tool_summary(&server_name, &tool.name, &tool.description)
            })
        })
        .collect::<Vec<_>>();
    tools.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));
    let total = tools.len();
    let bounded = tools
        .into_iter()
        .take(MAX_INVENTORY_TOOLS)
        .collect::<Vec<_>>();

    serialize_inventory(&InventoryToolsResponse {
        enabled: true,
        loaded: true,
        count: bounded.len(),
        total,
        truncated: total > MAX_INVENTORY_TOOLS,
        fingerprint: Some(topology.fingerprint_hex()),
        tools: bounded,
    })
}

/// `GET /api/inventory/graph` — Return an inventory-oriented graph view.
pub async fn inventory_graph(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let shadow_agents_enabled = state.shadow_agent.is_some();
    let known_agent_count = state
        .shadow_agent
        .as_ref()
        .map(|detector| detector.known_count())
        .unwrap_or(0);

    let Some(guard) = state.topology_guard.as_ref() else {
        return serialize_inventory(&InventoryGraphResponse {
            topology_enabled: false,
            topology_loaded: false,
            shadow_agents_enabled,
            audit_loaded: false,
            known_agent_count,
            relationship_count: 0,
            fingerprint: None,
            server_count: 0,
            tool_count: 0,
            node_count: 0,
            edge_count: 0,
            truncated: false,
            agents: Vec::new(),
            tools: Vec::new(),
            relationships: Vec::new(),
            servers: Vec::new(),
        });
    };

    let Some(topology) = guard.current() else {
        return serialize_inventory(&InventoryGraphResponse {
            topology_enabled: true,
            topology_loaded: false,
            shadow_agents_enabled,
            audit_loaded: false,
            known_agent_count,
            relationship_count: 0,
            fingerprint: None,
            server_count: 0,
            tool_count: 0,
            node_count: 0,
            edge_count: 0,
            truncated: false,
            agents: Vec::new(),
            tools: Vec::new(),
            relationships: Vec::new(),
            servers: Vec::new(),
        });
    };

    let truncated = topology.node_count() > MAX_INVENTORY_GRAPH_NODES;
    let topology_tools = topology.tool_names();
    let topology_tool_set = topology_tools.iter().cloned().collect::<HashSet<_>>();
    let (audit_loaded, agents, mut relationships) =
        build_agent_tool_relationships(&state, &topology_tools).await;
    let mut graph_tools = Vec::new();
    let servers = if truncated {
        Vec::new()
    } else {
        topology
            .to_static()
            .into_iter()
            .take(MAX_INVENTORY_SERVERS)
            .map(|server| {
                let server_name = server.name;
                let tools = server
                    .tools
                    .into_iter()
                    .take(MAX_INVENTORY_TOOLS)
                    .map(|tool| {
                        build_topology_tool_summary(&server_name, &tool.name, &tool.description)
                    })
                    .collect::<Vec<_>>();
                graph_tools.extend(tools.clone());
                for tool in &tools {
                    if relationships.len() < MAX_INVENTORY_RELATIONSHIPS {
                        relationships.push(InventoryRelationship {
                            source: format!("server:{server_name}"),
                            target: format!("tool:{}", tool.qualified_name),
                            relationship: "owns".to_string(),
                            ownership_label: "platform-owned".to_string(),
                            exposure_label: "topology-managed".to_string(),
                            detail: "declared in topology graph".to_string(),
                        });
                    }
                }
                let resources = server
                    .resources
                    .into_iter()
                    .map(|resource| resource.name)
                    .collect::<Vec<_>>();

                InventoryGraphServer {
                    name: server_name,
                    ownership_label: "platform-owned".to_string(),
                    exposure_label: "topology-managed".to_string(),
                    tools,
                    resources,
                }
            })
            .collect::<Vec<_>>()
    };

    let mut known_tool_nodes = graph_tools
        .iter()
        .map(|tool| tool.qualified_name.clone())
        .collect::<HashSet<_>>();
    for relationship in &relationships {
        let Some(qualified_name) = relationship.target.strip_prefix("tool:") else {
            continue;
        };
        if known_tool_nodes.insert(qualified_name.to_string()) {
            graph_tools.push(build_observed_tool_summary(
                qualified_name,
                topology_tool_set.contains(qualified_name),
            ));
        }
    }
    graph_tools.sort_by(|left, right| left.qualified_name.cmp(&right.qualified_name));

    serialize_inventory(&InventoryGraphResponse {
        topology_enabled: true,
        topology_loaded: true,
        shadow_agents_enabled,
        audit_loaded,
        known_agent_count,
        relationship_count: relationships.len(),
        fingerprint: Some(topology.fingerprint_hex()),
        server_count: topology.server_count(),
        tool_count: topology_tools.len(),
        node_count: topology.node_count(),
        edge_count: topology.edge_count(),
        truncated,
        agents,
        tools: graph_tools,
        relationships,
        servers,
    })
}
