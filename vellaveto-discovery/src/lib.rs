//! MCP tool topology crawling and verification for VellaVeto.
//!
//! This crate provides:
//! - **Topology graph** — models MCP servers, tools, resources, and their relationships.
//! - **Topology guard** — pre-policy filter that blocks unknown/ambiguous tools.
//! - **Live crawling** — discovers tools from running MCP servers via the [`McpServerProbe`] trait.
//! - **Data flow inference** — analyzes schemas to infer tool-to-tool data dependencies.
//! - **Topology diffing** — detects changes between topology snapshots.
//! - **Recrawl scheduling** — periodic and event-triggered topology refreshes.
//! - **JSON serialization** — for caching and Foundation integration.
//!
//! # Architecture
//!
//! ```text
//! vellaveto-types (leaf)
//!        ↑
//! vellaveto-canonical (types only)
//!        ↑
//! vellaveto-discovery (types, canonical) ← THIS CRATE
//!        ↑
//! vellaveto-engine (types, canonical, discovery)
//! ```
//!
//! This crate has NO dependency on `vellaveto-mcp` or any transport layer.
//! Communication with MCP servers happens through the [`McpServerProbe`] trait,
//! which `vellaveto-mcp` implements.

pub mod crawler;
pub mod diff;
pub mod error;
pub mod guard;
pub mod inference;
pub mod schedule;
pub mod serialize;
pub mod topology;

// Re-export primary types for convenience.
pub use crawler::{
    CrawlConfig, CrawlResult, McpServerProbe, ResourceInfo, ServerCrawlResult, ServerInfo,
    ToolInfo, TopologyCrawler,
};
pub use diff::{QualifiedTool, ToolModification, TopologyDiff};
pub use error::DiscoveryError;
pub use guard::{TopologyGuard, TopologyVerdict};
pub use inference::{InferenceConfig, InferenceEngine, InferredMatch};
pub use schedule::{RecrawlConfig, RecrawlScheduler, TopologyAuditEvent};
pub use serialize::{SerializedEdge, TopologySnapshot};
pub use topology::{
    ServerCapabilities, StaticResourceDecl, StaticServerDecl, StaticToolDecl, TopologyEdge,
    TopologyGraph, TopologyNode,
};
