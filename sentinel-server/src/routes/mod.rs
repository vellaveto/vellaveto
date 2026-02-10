//! Route handlers for the Sentinel HTTP API.
//!
//! This module provides all HTTP route handlers for the Sentinel server API.
//! The main router is built by `build_router()`.
//!
//! Submodules:
//! - `memory` - Memory Injection Defense (MINJA) handlers

mod main;
pub mod memory;

pub use main::*;
