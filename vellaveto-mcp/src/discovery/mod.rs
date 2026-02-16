//! Tool Discovery Service — intent-based tool search with TF-IDF scoring (Phase 34).
//!
//! Provides an in-memory search index over MCP tool metadata. Agents describe
//! what they need in natural language and receive ranked, policy-filtered tool
//! schemas within a configurable token budget.
//!
//! # Architecture
//!
//! - **`ToolIndex`**: In-memory TF-IDF inverted index over tool descriptions.
//! - **`DiscoveryEngine`**: Orchestrates search, policy filtering, and token budgets.
//! - **`DiscoveryError`**: Fail-closed error handling.
//!
//! # Feature Gate
//!
//! This module is behind the `discovery` feature flag:
//! ```toml
//! vellaveto-mcp = { path = "..", features = ["discovery"] }
//! ```

pub mod engine;
pub mod error;
pub mod index;

pub use engine::{DiscoveryEngine, IndexStats};
pub use error::DiscoveryError;
pub use index::ToolIndex;
