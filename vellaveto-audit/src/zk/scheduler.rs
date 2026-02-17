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

    /// Maximum backoff duration on consecutive failures (GAP-F01).
    /// Prevents unbounded exponential growth of the backoff timer.
    const MAX_BACKOFF_SECS: u64 = 300;

    /// Run the batch proving loop until shutdown.
    ///
    /// Generates a batch proof every `batch_interval_secs` if there are
    /// pending witnesses. Also generates a final batch on shutdown.
    ///
    /// ## Backoff (GAP-F01)
    ///
    /// On consecutive proving failures, the scheduler applies exponential backoff
    /// (doubling the interval up to `MAX_BACKOFF_SECS`). A successful batch resets
    /// the backoff to the configured interval. This prevents tight-loop retries
    /// when the prover is consistently failing (e.g., out of memory).
    pub async fn run(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let base_interval = Duration::from_secs(self.batch_interval_secs);
        let mut current_interval = base_interval;
        let mut interval = tokio::time::interval(current_interval);
        let mut consecutive_failures: u32 = 0;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.try_prove_batch() {
                        Ok(_) => {
                            // Reset backoff on success
                            if consecutive_failures > 0 {
                                consecutive_failures = 0;
                                current_interval = base_interval;
                                interval = tokio::time::interval(current_interval);
                            }
                        }
                        Err(e) => {
                            // GAP-F01: Exponential backoff on consecutive failures,
                            // capped at MAX_BACKOFF_SECS to prevent overflow.
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            let backoff_secs = self.batch_interval_secs
                                .saturating_mul(1u64 << consecutive_failures.min(20))
                                .min(Self::MAX_BACKOFF_SECS);
                            current_interval = Duration::from_secs(backoff_secs);
                            interval = tokio::time::interval(current_interval);
                            tracing::warn!(
                                error = %e,
                                consecutive_failures = consecutive_failures,
                                next_attempt_secs = backoff_secs,
                                "Batch proving attempt failed, backing off"
                            );
                        }
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
        let guard = self
            .proof_store
            .lock()
            .map_err(|e| ZkError::Proof(format!("Proof store lock poisoned: {}", e)))?;
        Ok(guard.clone())
    }

    /// Get the number of pending witnesses.
    pub fn pending_witnesses(&self) -> Result<usize, ZkError> {
        self.witness_store.len()
    }

    /// Get the number of stored proofs.
    pub fn proof_count(&self) -> Result<usize, ZkError> {
        let guard = self
            .proof_store
            .lock()
            .map_err(|e| ZkError::Proof(format!("Proof store lock poisoned: {}", e)))?;
        Ok(guard.len())
    }

    /// Internal: drain witnesses and attempt to generate a batch proof.
    ///
    /// SECURITY (FIND-P1-1): Witnesses are drained into a temporary buffer.
    /// If proving fails, the witnesses are restored to the front of the store
    /// so they are not permanently lost. The sequence range of the failed
    /// batch is logged at error level for forensic investigation.
    fn try_prove_batch(&self) -> Result<Option<ZkBatchProof>, ZkError> {
        let witnesses = self.witness_store.drain(self.batch_size)?;
        if witnesses.is_empty() {
            return Ok(None);
        }

        let first_seq = witnesses.first().map(|w| w.sequence).unwrap_or(0);
        let last_seq = witnesses.last().map(|w| w.sequence).unwrap_or(0);
        let witness_count = witnesses.len();

        let proof = match self.prover.prove(&witnesses) {
            Ok(proof) => proof,
            Err(e) => {
                tracing::error!(
                    first_sequence = first_seq,
                    last_sequence = last_seq,
                    witness_count = witness_count,
                    error = %e,
                    "Batch proving failed, restoring {} witnesses (seq {}..={})",
                    witness_count,
                    first_seq,
                    last_seq,
                );

                // Attempt to restore the witnesses to the front of the store
                if let Err(restore_err) = self.witness_store.restore(witnesses) {
                    tracing::error!(
                        first_sequence = first_seq,
                        last_sequence = last_seq,
                        witness_count = witness_count,
                        error = %restore_err,
                        "CRITICAL: Failed to restore witnesses after proving failure — \
                         {} witnesses (seq {}..={}) permanently lost",
                        witness_count,
                        first_seq,
                        last_seq,
                    );
                }

                return Err(e);
            }
        };

        let mut guard = self
            .proof_store
            .lock()
            .map_err(|e| ZkError::Proof(format!("Proof store lock poisoned: {}", e)))?;

        // Evict oldest proofs if at capacity
        if guard.len() >= MAX_STORED_PROOFS {
            let excess = guard.len().saturating_sub(MAX_STORED_PROOFS) + 1;
            guard.drain(..excess);
        }

        guard.push(proof.clone());
        Ok(Some(proof))
    }
}
