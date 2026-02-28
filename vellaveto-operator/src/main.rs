// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Vellaveto Kubernetes Operator
//!
//! Watches three Custom Resource Definitions and reconciles them against
//! the Vellaveto server REST API:
//!
//! - `VellavetoCluster` — manages server deployments
//! - `VellavetoPolicy` — declarative policy management
//! - `VellavetoTenant` — declarative tenant management

use std::sync::Arc;

use futures::StreamExt;
use kube::api::Api;
use kube::runtime::Controller;
use kube::Client;
use tracing::{error, info};

use vellaveto_operator::crd::{VellavetoCluster, VellavetoPolicy, VellavetoTenant};
use vellaveto_operator::reconciler::cluster::{error_policy_cluster, reconcile_cluster};
use vellaveto_operator::reconciler::policy::{error_policy_policy, reconcile_policy};
use vellaveto_operator::reconciler::tenant::{error_policy_tenant, reconcile_tenant};
use vellaveto_operator::reconciler::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting vellaveto-operator"
    );

    // Connect to the Kubernetes API
    let client = Client::try_default().await?;

    // Build shared context
    let ctx = Arc::new(Context {
        kube_client: client.clone(),
        vellaveto_client: None,
    });

    // Build controllers for all three CRDs
    let cluster_api = Api::<VellavetoCluster>::all(client.clone());
    let policy_api = Api::<VellavetoPolicy>::all(client.clone());
    let tenant_api = Api::<VellavetoTenant>::all(client.clone());

    let cluster_ctrl = Controller::new(cluster_api, kube::runtime::watcher::Config::default())
        .run(reconcile_cluster, error_policy_cluster, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "VellavetoCluster reconciled"),
                Err(e) => error!(error = %e, "VellavetoCluster reconciliation failed"),
            }
        });

    let policy_ctrl = Controller::new(policy_api, kube::runtime::watcher::Config::default())
        .run(reconcile_policy, error_policy_policy, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "VellavetoPolicy reconciled"),
                Err(e) => error!(error = %e, "VellavetoPolicy reconciliation failed"),
            }
        });

    let tenant_ctrl = Controller::new(tenant_api, kube::runtime::watcher::Config::default())
        .run(reconcile_tenant, error_policy_tenant, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "VellavetoTenant reconciled"),
                Err(e) => error!(error = %e, "VellavetoTenant reconciliation failed"),
            }
        });

    info!("all controllers started, watching for CRD changes");

    // Run all controllers concurrently, shutdown on ctrl-c or if any controller exits
    tokio::select! {
        _ = cluster_ctrl => {
            error!("VellavetoCluster controller exited unexpectedly");
        }
        _ = policy_ctrl => {
            error!("VellavetoPolicy controller exited unexpectedly");
        }
        _ = tenant_ctrl => {
            error!("VellavetoTenant controller exited unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal, stopping operator");
        }
    }

    Ok(())
}
