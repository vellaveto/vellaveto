//! Route handlers for the Vellaveto HTTP API.
//!
//! This module provides all HTTP route handlers for the Vellaveto server API.
//! The main router is built by `build_router()`.
//!
//! Submodules:
//! - `approval` - Human-in-the-loop approval workflow handlers
//! - `audit` - Audit log and checkpoint handlers
//! - `auth_level` - Step-up authentication level handlers
//! - `circuit_breaker` - Circuit breaker handlers (OWASP ASI08)
//! - `deputy` - Deputy validation handlers (OWASP ASI02)
//! - `etdi` - ETDI cryptographic tool security handlers
//! - `exec_graph` - Execution graph export handlers (Phase 6)
//! - `memory` - Memory Injection Defense (MINJA) handlers
//! - `nhi` - Non-Human Identity (NHI) lifecycle handlers
//! - `observability` - AI observability platform handlers (Phase 15)
//! - `policy` - Policy CRUD and hot-reload handlers
//! - `registry` - Tool registry management handlers
//! - `sampling` - Sampling detection handlers
//! - `schema_lineage` - Schema lineage tracking handlers (OWASP ASI05)
//! - `shadow_agent` - Shadow agent detection handlers
//! - `task_state` - MCP async task state handlers
//! - `tenant` - Tenant management handlers (Phase 3)

pub mod approval;
pub mod audit;
pub mod auth_level;
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
pub mod projector;
pub mod registry;
pub mod sampling;
pub mod schema_lineage;
pub mod shadow_agent;
pub mod simulator;
pub mod task_state;
pub mod tenant;
pub mod zk_audit;

pub use main::*;

/// Maximum length for path parameters (IDs, tool names, session IDs).
const MAX_PATH_PARAM_LEN: usize = 256;

/// SECURITY (FIND-R51-005): Detect control characters AND Unicode format
/// characters that can bypass simple `is_control()` checks.
/// Mirrors `is_unsafe_char` from nhi.rs.
pub(crate) fn is_unsafe_char(c: char) -> bool {
    let cp = c as u32;
    c.is_control()
        || (0x200B..=0x200F).contains(&cp)
        || (0x202A..=0x202E).contains(&cp)
        || (0x2060..=0x2064).contains(&cp)
        || (0x2066..=0x2069).contains(&cp)
        || cp == 0xFEFF
        || (0xFFF9..=0xFFFB).contains(&cp)
        || (0xE0001..=0xE007F).contains(&cp)
        || cp == 0x00AD
}

/// SECURITY (FIND-R51-005): Validate a path parameter — reject if too long
/// or contains control/format characters. Returns a `BAD_REQUEST` error
/// compatible with `(StatusCode, Json<ErrorResponse>)`.
pub fn validate_path_param(
    value: &str,
    field_name: &str,
) -> Result<(), (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    if value.len() > MAX_PATH_PARAM_LEN {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: format!("{} exceeds maximum length", field_name),
            }),
        ));
    }
    if value.chars().any(is_unsafe_char) {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse {
                error: format!("{} contains invalid characters", field_name),
            }),
        ));
    }
    Ok(())
}

/// SECURITY (FIND-R51-005): Validate a path parameter — same logic but
/// returns `(StatusCode, Json<serde_json::Value>)` for handlers that use
/// that error type instead of `ErrorResponse`.
pub fn validate_path_param_json(
    value: &str,
    field_name: &str,
) -> Result<(), (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    if value.len() > MAX_PATH_PARAM_LEN {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": format!("{} exceeds maximum length", field_name)
            })),
        ));
    }
    if value.chars().any(is_unsafe_char) {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": format!("{} contains invalid characters", field_name)
            })),
        ));
    }
    Ok(())
}
