//! Gateway types for multi-backend MCP routing (Phase 20).
//!
//! These types define the building blocks for Vellaveto's gateway mode,
//! where tool calls are routed to different upstream MCP servers based
//! on tool name prefix matching.

use serde::{Deserialize, Serialize};

/// Health status of an upstream backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendHealth {
    /// Backend is responding normally.
    #[default]
    Healthy,
    /// Backend has experienced failures but is recovering.
    Degraded,
    /// Backend has exceeded the failure threshold and is excluded from routing.
    Unhealthy,
}

fn default_weight() -> u8 {
    100
}

/// An upstream MCP server backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamBackend {
    /// Unique identifier for this backend.
    pub id: String,
    /// URL of the upstream MCP server.
    pub url: String,
    /// Tool name prefixes this backend handles. Empty = catch-all default.
    pub tool_prefixes: Vec<String>,
    /// Routing weight (1-100). Higher weight = preferred when multiple
    /// backends match. Default: 100.
    #[serde(default = "default_weight")]
    pub weight: u8,
    /// Current health status. Skipped during serialization.
    #[serde(skip, default)]
    pub health: BackendHealth,
}

/// Result of a routing decision.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// ID of the selected backend.
    pub backend_id: String,
    /// URL to forward the request to.
    pub upstream_url: String,
}

/// A tool name conflict detected across multiple backends.
#[derive(Debug, Clone)]
pub struct ToolConflict {
    /// The conflicting tool name.
    pub tool_name: String,
    /// Backend IDs that advertise this tool.
    pub backends: Vec<String>,
}
