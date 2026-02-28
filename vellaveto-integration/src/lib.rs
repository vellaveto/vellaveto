// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration test harness for the Vellaveto workspace.
//!
//! This crate exercises the full pipeline: policy creation,
//! action evaluation through the engine, and audit logging/reporting.

// Re-export workspace crates for convenient test access
pub use vellaveto_audit;
pub use vellaveto_engine;
pub use vellaveto_types;
