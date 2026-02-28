// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Error types for the tool discovery service (Phase 34).

use thiserror::Error;

/// Errors from tool discovery operations.
#[derive(Error, Debug)]
pub enum DiscoveryError {
    /// Configuration validation failed.
    #[error("discovery config error: {0}")]
    ConfigError(String),

    /// Index is at capacity and cannot accept new entries.
    #[error("discovery index at capacity ({0} entries)")]
    IndexFull(usize),

    /// The provided tool metadata is invalid.
    #[error("invalid tool metadata: {0}")]
    InvalidMetadata(String),

    /// An internal concurrency error (RwLock poisoned).
    #[error("discovery internal error: lock poisoned")]
    LockPoisoned,

    /// JSON serialization/deserialization error.
    #[error("discovery serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
