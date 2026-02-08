//! Proxy types and error definitions.

use sentinel_types::Verdict;
use serde_json::Value;
use thiserror::Error;

use crate::framing::FramingError;

/// Decision after evaluating a tool call.
#[derive(Debug)]
pub enum ProxyDecision {
    /// Forward the message to the child MCP server.
    Forward,
    /// Block the message and return an error response to the agent.
    /// Carries both the JSON-RPC error response and the actual verdict for audit logging.
    Block(Value, Verdict),
}

/// Errors that can occur during proxy operation.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Framing error during JSON-RPC message handling.
    #[error("Framing error: {0}")]
    Framing(#[from] FramingError),
    /// IO error during message reading/writing.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
