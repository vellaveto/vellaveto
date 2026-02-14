//! Integration test harness for the Vellaveto workspace.
//!
//! This crate exercises the full pipeline: policy creation,
//! action evaluation through the engine, and audit logging/reporting.

// Re-export workspace crates for convenient test access
pub use vellaveto_audit;
pub use vellaveto_engine;
pub use vellaveto_types;
