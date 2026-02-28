// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Proxy types and error definitions.

use serde_json::Value;
use thiserror::Error;
use vellaveto_types::Verdict;

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
