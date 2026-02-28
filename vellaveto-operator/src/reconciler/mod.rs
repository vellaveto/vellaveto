// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Reconciliation controllers for Vellaveto CRDs.
//!
//! Each CRD has its own reconciler that watches for changes and syncs
//! desired state to the Vellaveto server via its REST API.

pub mod cluster;
pub mod policy;
pub mod tenant;

use std::sync::Arc;

use kube::Client;

use crate::client::VellavetoApiClient;

/// Shared context passed to all reconcilers.
pub struct Context {
    /// Kubernetes API client.
    pub kube_client: Client,
    /// Optional pre-configured Vellaveto API client (for testing).
    pub vellaveto_client: Option<VellavetoApiClient>,
}

impl Context {
    /// Build the Vellaveto API client URL from a VellavetoCluster's Service.
    ///
    /// Uses in-cluster DNS: `{name}.{namespace}.svc.cluster.local:3000`
    pub fn build_server_url(cluster_name: &str, namespace: &str) -> String {
        format!("http://{cluster_name}.{namespace}.svc.cluster.local:3000")
    }

    /// Get or create a Vellaveto API client for the given cluster.
    pub fn get_api_client(
        self: &Arc<Self>,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<VellavetoApiClient, crate::error::OperatorError> {
        if let Some(ref client) = self.vellaveto_client {
            return Ok(client.clone());
        }
        let url = Self::build_server_url(cluster_name, namespace);
        VellavetoApiClient::new(&url)
    }
}
