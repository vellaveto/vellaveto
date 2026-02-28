// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Service discovery trait (Phase 27.3).
//!
//! Provides an abstraction for discovering Vellaveto endpoints in the cluster.
//! Implementations include static (from config) and DNS-based discovery.
//! Kubernetes API-based discovery is a future feature-gated addition.

use async_trait::async_trait;
use vellaveto_types::ServiceEndpoint;

use crate::ClusterError;

/// Trait for service discovery implementations.
///
/// Implementations must be `Send + Sync` for use behind `Arc<dyn ServiceDiscovery>`.
#[async_trait]
pub trait ServiceDiscovery: Send + Sync {
    /// Perform a one-shot discovery, returning all known endpoints.
    async fn discover(&self) -> Result<Vec<ServiceEndpoint>, ClusterError>;

    /// Start watching for endpoint changes.
    ///
    /// Returns a receiver channel that emits `DiscoveryEvent`s when endpoints
    /// are added, removed, or updated. Returns `Ok(None)` if the implementation
    /// does not support watching (e.g., static discovery).
    async fn watch(
        &self,
    ) -> Result<Option<tokio::sync::mpsc::Receiver<vellaveto_types::DiscoveryEvent>>, ClusterError>;
}
