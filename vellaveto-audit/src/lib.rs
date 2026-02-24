// vellaveto-audit: Append-only tamper-evident audit logging for policy decisions.
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
pub mod merkle;
mod redaction;
mod rotation;
mod types;
mod verification;

// ── Phase 19: Immutable audit log archive ────────────────────────────────────
#[cfg(feature = "archive")]
pub mod archive;

// ── Phase 37: Zero-Knowledge Audit Trails ────────────────────────────────────
#[cfg(feature = "zk-audit")]
pub mod zk;

// ── Phase 43: Centralized Audit Store ────────────────────────────────────────
pub mod query;
pub mod sink;

// ── Phase 38: SOC 2 Type II Access Review Reports ───────────────────────────
pub mod access_review;

// ── Pre-existing submodules ──────────────────────────────────────────────────
pub mod aivss;
pub mod atlas;
pub mod eu_ai_act;
pub mod evidence_pack;
pub mod exec_graph;
pub mod export;
pub mod iso27090;
pub mod nist_rmf;
pub mod observability;
pub mod pii;
pub mod soc2;
pub mod streaming;

// ── Phase 19.3: CoSAI/Adversa threat coverage registries ────────────────────
pub mod adversa_top25;
pub mod cosai;
pub mod data_governance;
pub mod dora;
pub mod gap_analysis;
pub mod iso42001;
pub mod nis2;

// ── Phase 41: OWASP Agentic Security Index (ASI) registry ───────────────────
pub mod owasp_asi;

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

// Merkle tree re-exports
pub use merkle::{MerkleProof, MerkleTree, MerkleVerification, ProofStep};

// PII re-exports
pub use pii::{validate_regex_safety, CustomPiiPattern, PiiScanner};

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests;
