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

pub mod pedersen;
pub mod witness;
pub mod circuit;
pub mod prover;
pub mod scheduler;

#[cfg(test)]
mod tests;

use thiserror::Error;

/// Errors from ZK audit operations.
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
