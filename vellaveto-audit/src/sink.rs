// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Audit sink abstraction for dual-writing to external stores (Phase 43).
//!
//! The `AuditSink` trait defines the interface for receiving audit entries
//! after the file-based logger writes them. Implementations can forward
//! entries to PostgreSQL, message queues, or any other store.
//!
//! The sink is **non-fatal by default**: if it fails, the entry is still
//! recorded in the file log and a warning is emitted. Set `sink_failure_fatal`
//! in config to make sink failures block the caller.

use crate::types::AuditEntry;
use std::fmt::Debug;
use thiserror::Error;

/// Errors from audit sink operations.
#[derive(Error, Debug)]
pub enum SinkError {
    /// Connection to the external store failed.
    #[error("sink connection error: {0}")]
    Connection(String),

    /// Write to the external store failed.
    #[error("sink write error: {0}")]
    Write(String),

    /// Entry serialization failed.
    #[error("sink serialization error: {0}")]
    Serialization(String),

    /// The sink's internal buffer is full.
    #[error("sink buffer full ({0} pending entries)")]
    BufferFull(usize),

    /// The sink is shutting down and not accepting new entries.
    #[error("sink is shutting down")]
    ShuttingDown,
}

/// Trait for audit log sinks that receive entries after the file write.
///
/// Implementations must be thread-safe (`Send + Sync`) and should handle
/// backpressure gracefully. The recommended pattern is an mpsc channel
/// with a background writer task that batches inserts.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync + Debug {
    /// Accept a single audit entry for writing to the external store.
    ///
    /// This should be non-blocking (e.g., enqueue to a channel) to avoid
    /// slowing down the file-based logger. Returns `Ok(())` if the entry
    /// was accepted (not necessarily written yet).
    async fn sink(&self, entry: &AuditEntry) -> Result<(), SinkError>;

    /// Flush all buffered entries to the external store.
    ///
    /// Blocks until all pending entries are written or the operation times out.
    async fn flush(&self) -> Result<(), SinkError>;

    /// Gracefully shut down the sink, flushing remaining entries.
    ///
    /// After shutdown, subsequent `sink()` calls should return `ShuttingDown`.
    async fn shutdown(&self) -> Result<(), SinkError>;

    /// Whether the sink is currently healthy (connected and accepting entries).
    fn is_healthy(&self) -> bool;

    /// Number of entries pending write to the external store.
    fn pending_count(&self) -> usize;
}

// PostgreSQL sink is feature-gated
#[cfg(feature = "postgres-store")]
pub mod postgres;
