//! Route handlers for the Sentinel HTTP API.
//!
//! This module provides all HTTP route handlers for the Sentinel server API.
//! The main router is built by `build_router()`.
//!
//! Submodules:
//! - `audit` - Audit log and checkpoint handlers
//! - `auth_level` - Step-up authentication level handlers
//! - `circuit_breaker` - Circuit breaker handlers (OWASP ASI08)
//! - `deputy` - Deputy validation handlers (OWASP ASI02)
//! - `etdi` - ETDI cryptographic tool security handlers
//! - `exec_graph` - Execution graph export handlers (Phase 6)
//! - `memory` - Memory Injection Defense (MINJA) handlers
//! - `nhi` - Non-Human Identity (NHI) lifecycle handlers
//! - `observability` - AI observability platform handlers (Phase 15)
//! - `sampling` - Sampling detection handlers
//! - `schema_lineage` - Schema lineage tracking handlers (OWASP ASI05)
//! - `shadow_agent` - Shadow agent detection handlers
//! - `task_state` - MCP async task state handlers
//! - `tenant` - Tenant management handlers (Phase 3)

pub mod audit;
pub mod auth_level;
pub mod circuit_breaker;
pub mod deputy;
pub mod etdi;
pub mod exec_graph;
mod main;
pub mod memory;
pub mod nhi;
pub mod observability;
pub mod sampling;
pub mod schema_lineage;
pub mod shadow_agent;
pub mod task_state;
pub mod tenant;

pub use main::*;
