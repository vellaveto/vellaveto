//! Background scheduler for batch ZK proof generation (Phase 37.2).
//!
//! Periodically drains the witness store and generates Groth16 batch proofs.
//! Supports both timer-based and on-demand proof generation.
//!
//! Proofs are stored in-memory with a bounded capacity (10K max) to prevent
//! unbounded growth. Oldest proofs are evicted when the cap is reached.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use vellaveto_types::ZkBatchProof;

use super::prover::ZkBatchProver;
use super::witness::WitnessStore;
use super::ZkError;

/// Maximum number of stored batch proofs before eviction.
const MAX_STORED_PROOFS: usize = 10_000;

/// Background scheduler for batch ZK proof generation.
///
/// Periodically drains the witness store and generates Groth16 batch proofs
/// via the configured `ZkBatchProver`. Proofs are stored in-memory.
pub struct ZkBatchScheduler {
    prover: Arc<ZkBatchProver>,
    witness_store: Arc<WitnessStore>,
    batch_size: usize,
    batch_interval_secs: u64,
    proof_store: Mutex<Vec<ZkBatchProof>>,
}

impl ZkBatchScheduler {
    /// Create a new batch scheduler.
    ///
    /// - `prover`: The Groth16 batch prover (shared via Arc).
    /// - `witness_store`: The witness accumulator (shared via Arc).
    /// - `batch_size`: Maximum number of witnesses to drain per batch.
    /// - `batch_interval_secs`: Seconds between automatic batch attempts.
    pub fn new(
        prover: Arc<ZkBatchProver>,
        witness_store: Arc<WitnessStore>,
        batch_size: usize,
        batch_interval_secs: u64,
    ) -> Self {
        Self {
            prover,
            witness_store,
            batch_size,
            batch_interval_secs,
            proof_store: Mutex::new(Vec::new()),
        }
    }

    /// Run the batch proving loop until shutdown.
    ///
    /// Generates a batch proof every `batch_interval_secs` if there are
    /// pending witnesses. Also generates a final batch on shutdown.
    pub async fn run(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let interval_duration = Duration::from_secs(self.batch_interval_secs);
        let mut interval = tokio::time::interval(interval_duration);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.try_prove_batch() {
                        tracing::warn!(error = %e, "Batch proving attempt failed");
                    }
                }
                result = shutdown.changed() => {
                    if result.is_ok() {
                        // Final batch before shutdown
                        if let Err(e) = self.try_prove_batch() {
                            tracing::warn!(error = %e, "Final batch proving failed");
                        }
                    }
                    break;
                }
            }
        }
    }

    /// Force an immediate batch proof generation.
    ///
    /// Returns `Ok(Some(proof))` if a batch was proved, `Ok(None)` if
    /// there were no pending witnesses, or `Err` on failure.
    pub fn prove_now(&self) -> Result<Option<ZkBatchProof>, ZkError> {
        self.try_prove_batch()
    }

    /// Get all stored batch proofs.
    pub fn proofs(&self) -> Result<Vec<ZkBatchProof>, ZkError> {
        let guard = self.proof_store.lock().map_err(|e| {
            ZkError::Proof(format!("Proof store lock poisoned: {}", e))
        })?;
        Ok(guard.clone())
    }

    /// Get the number of pending witnesses.
    pub fn pending_witnesses(&self) -> Result<usize, ZkError> {
        self.witness_store.len()
    }

    /// Get the number of stored proofs.
    pub fn proof_count(&self) -> Result<usize, ZkError> {
        let guard = self.proof_store.lock().map_err(|e| {
            ZkError::Proof(format!("Proof store lock poisoned: {}", e))
        })?;
        Ok(guard.len())
    }

    /// Internal: drain witnesses and attempt to generate a batch proof.
    fn try_prove_batch(&self) -> Result<Option<ZkBatchProof>, ZkError> {
        let witnesses = self.witness_store.drain(self.batch_size)?;
        if witnesses.is_empty() {
            return Ok(None);
        }

        let proof = self.prover.prove(&witnesses)?;

        let mut guard = self.proof_store.lock().map_err(|e| {
            ZkError::Proof(format!("Proof store lock poisoned: {}", e))
        })?;

        // Evict oldest proofs if at capacity
        if guard.len() >= MAX_STORED_PROOFS {
            let excess = guard.len().saturating_sub(MAX_STORED_PROOFS) + 1;
            guard.drain(..excess);
        }

        guard.push(proof.clone());
        Ok(Some(proof))
    }
}
