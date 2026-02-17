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
pub mod registry;
pub mod sampling;
pub mod schema_lineage;
pub mod shadow_agent;
pub mod simulator;
pub mod task_state;
pub mod projector;
pub mod tenant;
pub mod zk_audit;

pub use main::*;
