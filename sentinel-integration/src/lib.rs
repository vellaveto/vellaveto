//! Integration test harness for the Sentinel workspace.
//!
//! This crate exercises the full pipeline: policy creation,
//! action evaluation through the engine, and audit logging/reporting.

// Re-export workspace crates for convenient test access
pub use sentinel_audit;
pub use sentinel_engine;
pub use sentinel_types;
