//! Route handlers for the Sentinel HTTP API.
//!
//! This module provides all HTTP route handlers for the Sentinel server API.
//! The main router is built by `build_router()`.
//!
//! Submodules:
//! - `circuit_breaker` - Circuit breaker handlers (OWASP ASI08)
//! - `etdi` - ETDI cryptographic tool security handlers
//! - `memory` - Memory Injection Defense (MINJA) handlers
//! - `nhi` - Non-Human Identity (NHI) lifecycle handlers
//! - `tenant` - Tenant management handlers (Phase 3)

pub mod circuit_breaker;
pub mod etdi;
mod main;
pub mod memory;
pub mod nhi;
pub mod tenant;

pub use main::*;
