// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Route handlers for the Vellaveto HTTP API.
//!
//! This module provides all HTTP route handlers for the Vellaveto server API.
//! The main router is built by `build_router()`.
//!
//! Submodules:
//! - `approval` - Human-in-the-loop approval workflow handlers
//! - `audit` - Audit log and checkpoint handlers
//! - `auth_level` - Step-up authentication level handlers
//! - `billing` - Billing webhook handlers
//! - `circuit_breaker` - Circuit breaker handlers (OWASP ASI08)
//! - `compliance` - Compliance framework handlers (EU AI Act, SOC 2, etc.)
//! - `deployment` - Deployment info and leader status handlers (Phase 27)
//! - `deputy` - Deputy validation handlers (OWASP ASI02)
//! - `discovery` - Tool discovery API handlers (Phase 34)
//! - `etdi` - ETDI cryptographic tool security handlers
//! - `exec_graph` - Execution graph export handlers (Phase 6)
//! - `federation` - Agent identity federation handlers (Phase 39)
//! - `governance` - Shadow AI governance handlers (Phase 26)
//! - `main` - Core evaluate/health/status handlers
//! - `memory` - Memory Injection Defense (MINJA) handlers
//! - `nhi` - Non-Human Identity (NHI) lifecycle handlers
//! - `observability` - AI observability platform handlers (Phase 15)
//! - `policy` - Policy CRUD and hot-reload handlers
//! - `policy_lifecycle` - Policy versioning, approval, staging, and rollback handlers (Phase 47)
//! - `projector` - Model projector API handlers (Phase 35)
//! - `registry` - Tool registry management handlers
//! - `sampling` - Sampling detection handlers
//! - `schema_lineage` - Schema lineage tracking handlers (OWASP ASI05)
//! - `shadow_agent` - Shadow agent detection handlers
//! - `signup` - Self-service tenant signup (Phase 53)
//! - `simulator` - Policy simulator API handlers (Phase 22)
//! - `task_state` - MCP async task state handlers
//! - `tenant` - Tenant management handlers (Phase 3)
//! - `zk_audit` - Zero-knowledge audit trail handlers (Phase 37)

pub mod approval;
pub mod audit;
pub mod audit_store;
pub mod auth_level;
pub mod billing;
pub mod circuit_breaker;
pub mod compliance;
pub mod deployment;
pub mod deputy;
pub mod discovery;
pub mod etdi;
pub mod exec_graph;
pub mod federation;
pub mod governance;
mod main;
pub mod memory;
pub mod nhi;
pub mod observability;
pub mod policy;
pub mod policy_lifecycle;
pub mod projector;
pub mod registry;
pub mod sampling;
pub mod schema_lineage;
pub mod shadow_agent;
pub mod signup;
pub mod simulator;
pub mod task_state;
pub mod tenant;
pub mod topology;
pub mod zk_audit;

pub use main::*;

/// Maximum length for path parameters (IDs, tool names, session IDs).
const MAX_PATH_PARAM_LEN: usize = 256;

/// SECURITY (FIND-R51-005, IMP-R126-003): Detect control characters AND Unicode
/// format characters. Delegates to canonical `is_unicode_format_char()` from
/// vellaveto-types, fixing the U+2065 gap that existed in the previous inline
/// range implementation.
pub(crate) fn is_unsafe_char(c: char) -> bool {
    c.is_control() || vellaveto_types::is_unicode_format_char(c)
}

/// Core path parameter validation: rejects values that are too long or
/// contain control/format characters.  Returns `Ok(())` on success or
/// `Err(error_message)` on failure.
///
/// SECURITY (FIND-R51-005): All path parameters from external input must
/// pass through this check before use.
fn validate_path_param_core(value: &str, field_name: &str) -> Result<(), String> {
    if value.len() > MAX_PATH_PARAM_LEN {
        return Err(format!("{} exceeds maximum length", field_name));
    }
    if value.chars().any(is_unsafe_char) {
        return Err(format!("{} contains invalid characters", field_name));
    }
    Ok(())
}

/// SECURITY (FIND-R51-005): Validate a path parameter — reject if too long
/// or contains control/format characters. Returns a `BAD_REQUEST` error
/// compatible with `(StatusCode, Json<ErrorResponse>)`.
pub fn validate_path_param(
    value: &str,
    field_name: &str,
) -> Result<(), (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    validate_path_param_core(value, field_name).map_err(|msg| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse { error: msg }),
        )
    })
}

/// SECURITY (FIND-R51-005): Validate a path parameter — same logic but
/// returns `(StatusCode, Json<serde_json::Value>)` for handlers that use
/// that error type instead of `ErrorResponse`.
pub fn validate_path_param_json(
    value: &str,
    field_name: &str,
) -> Result<(), (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    validate_path_param_core(value, field_name).map_err(|msg| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": msg })),
        )
    })
}
