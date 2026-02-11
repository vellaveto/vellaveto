//! MCP stdio proxy bridge module.
//!
//! Provides the core [`ProxyBridge`] that sits between an agent (stdin/stdout) and
//! a child MCP server (spawned subprocess). Intercepts tool calls, evaluates them
//! against policies, and either forwards allowed calls or returns denial responses.
//!
//! # Main Types
//!
//! - [`ProxyBridge`] - Core proxy implementation
//! - [`ProxyDecision`] - Allow/deny decision with optional response
//! - [`ProxyError`] - Error types for proxy operations

mod bridge;
mod types;

// Re-export all public items for backwards compatibility
pub use bridge::ProxyBridge;
pub use bridge::ToolAnnotations;
pub use types::{ProxyDecision, ProxyError};
