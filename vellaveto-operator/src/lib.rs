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
//! - `VellavetoCluster` — manages server deployments (StatefulSet, Service, ConfigMap)
//! - `VellavetoPolicy` — declarative policy management with optional lifecycle versioning
//! - `VellavetoTenant` — declarative tenant management with quotas

pub mod client;
pub mod crd;
pub mod error;
pub mod reconciler;
