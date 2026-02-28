// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Error types for the discovery crate.

use thiserror::Error;

/// Errors that can occur during topology discovery and evaluation.
#[derive(Error, Debug)]
pub enum DiscoveryError {
    /// An MCP server was not found in the registry.
    #[error("Server not found: {0}")]
    ServerNotFound(String),

    /// An MCP server returned an error during probing.
    #[error("Server '{server}' error: {reason}")]
    ServerError {
        /// The server identifier.
        server: String,
        /// A description of the error.
        reason: String,
    },

    /// A server probe timed out.
    #[error("Server '{server}' timed out after {timeout_ms}ms")]
    ServerTimeout {
        /// The server identifier.
        server: String,
        /// The timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// The crawl was aborted due to a server failure (continue_on_error=false).
    #[error("Crawl aborted: server '{server}' failed: {reason}")]
    CrawlAborted {
        /// The server that caused the abort.
        server: String,
        /// A description of the failure.
        reason: String,
    },

    /// A topology graph construction error.
    #[error("Graph error: {0}")]
    GraphError(String),

    /// A serialization or deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Validation failed on topology data.
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// The topology fingerprint does not match the expected value.
    #[error("Fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch {
        /// The expected fingerprint (hex-encoded).
        expected: String,
        /// The actual fingerprint (hex-encoded).
        actual: String,
    },
}
