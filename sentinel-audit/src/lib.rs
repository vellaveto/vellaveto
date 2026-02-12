// sentinel-audit: Append-only tamper-evident audit logging for policy decisions.
//
// Submodules:
//   types       — Error, entry, report, checkpoint, redaction-level types
//   redaction   — Sensitive-key and PII redaction logic
//   logger      — AuditLogger struct, constructors, builders, core log_entry
//   rotation    — Log rotation and cross-rotation verification
//   verification— Hash chain verification, duplicate detection, reports
//   checkpoints — Ed25519-signed checkpoint creation and verification
//   events      — Security event logging helpers (heartbeat, circuit breaker, etc.)
//   etdi_audit  — ETDI cryptographic tool security audit helpers

// ── New submodules (split from the former monolithic lib.rs) ──────────────────
mod checkpoints;
mod etdi_audit;
mod events;
pub mod logger;
mod redaction;
mod rotation;
mod types;
mod verification;

// ── Pre-existing submodules ──────────────────────────────────────────────────
pub mod aivss;
pub mod atlas;
pub mod exec_graph;
pub mod export;
pub mod iso27090;
pub mod nist_rmf;
pub mod observability;
pub mod pii;
pub mod streaming;

// ── Re-exports: preserve exact public API ────────────────────────────────────

// Types
pub use types::{
    AuditEntry, AuditError, AuditReport, ChainVerification, Checkpoint, CheckpointVerification,
    ErrorLogEntry, RedactionLevel, RotationVerification,
};

// Core logger
pub use logger::AuditLogger;

// Redaction (free function used by external crates)
pub use redaction::redact_keys_and_patterns;

// Observability re-exports
pub use observability::{
    ActionSummary, DetectionType, ObservabilityError, ObservabilityExporter,
    ObservabilityExporterConfig, RedactionConfig, SamplingConfig as ObservabilitySamplingConfig,
    SecurityDetection, SecuritySpan, SecuritySpanBuilder, SpanKind, SpanSampler, TraceContext,
    VerdictSummary,
};

// PII re-exports
pub use pii::{validate_regex_safety, CustomPiiPattern, PiiScanner};

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests;
