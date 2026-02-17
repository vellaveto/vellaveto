//! Zero-Knowledge Audit Trails (Phase 37).
//!
//! Provides:
//! - **Pedersen commitments** (~50µs per entry) for hiding audit entry contents
//!   while binding to them cryptographically
//! - **Witness accumulator** for collecting entry witnesses used in batch proofs
//! - **Groth16 circuit** for proving audit chain integrity in zero knowledge
//! - **Batch prover** for generating and verifying ZK proofs over entry batches
//! - **Batch scheduler** for periodic background proof generation
//!
//! Feature-gated behind `zk-audit`.

pub mod circuit;
pub mod pedersen;
pub mod prover;
pub mod scheduler;
pub mod witness;

#[cfg(test)]
mod tests;

use thiserror::Error;

/// Errors from ZK audit operations.
///
/// ## Error Handling (GAP-F03)
///
/// All ZK errors are propagated to callers — none are silently swallowed.
/// Lock poisoning on internal `Mutex` types (witness store, proof store) is
/// converted to the appropriate variant (`WitnessStore`, `Proof`) rather than
/// panicking, maintaining the fail-closed invariant.
#[derive(Error, Debug)]
pub enum ZkError {
    #[error("Commitment error: {0}")]
    Commitment(String),
    #[error("Witness store error: {0}")]
    WitnessStore(String),
    #[error("Proof error: {0}")]
    Proof(String),
    #[error("Verification error: {0}")]
    Verification(String),
    #[error("Key error: {0}")]
    Key(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}
