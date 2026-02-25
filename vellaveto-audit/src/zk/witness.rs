//! Witness accumulator for ZK batch proving.
//!
//! Collects entry witnesses (hash, prev_hash, blinding factor, commitment)
//! that are later consumed by the batch prover to generate Groth16 proofs.
//!
//! Thread-safe via `std::sync::Mutex` with fail-closed semantics on
//! lock poisoning (returns `ZkError` instead of panicking).

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use std::sync::Mutex;

use super::ZkError;

/// A single audit entry witness for batch proving.
///
/// SECURITY (IMP-R118-006): Custom Debug impl redacts the `blinding` scalar,
/// which is the secret blinding factor for Pedersen commitments. If Debug
/// were derived, the blinding factor bytes would leak to logs/error messages.
#[derive(Clone)]
pub struct EntryWitness {
    /// Monotonic sequence number of the entry.
    pub sequence: u64,
    /// SHA-256 hash of the entry contents.
    pub entry_hash: [u8; 32],
    /// SHA-256 hash of the previous entry (zero for the first entry).
    pub prev_hash: [u8; 32],
    /// Blinding factor used in the Pedersen commitment.
    pub blinding: Scalar,
    /// Compressed Ristretto point of the Pedersen commitment.
    pub commitment: CompressedRistretto,
}

impl std::fmt::Debug for EntryWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryWitness")
            .field("sequence", &self.sequence)
            .field("entry_hash", &hex::encode(self.entry_hash))
            .field("prev_hash", &hex::encode(self.prev_hash))
            .field("blinding", &"[REDACTED]")
            .field("commitment", &self.commitment)
            .finish()
    }
}

/// Thread-safe witness accumulator with bounded capacity.
///
/// Witnesses are appended as audit entries are logged. The batch prover
/// periodically drains the store to generate batch proofs.
///
/// ## Backpressure (Witness Backpressure)
///
/// The store enforces a hard capacity limit (`max_capacity`, default 100K).
/// When the store is full, `append()` returns `Err(ZkError::WitnessStore)`
/// instead of growing unboundedly. The caller (audit logger) should log
/// a warning but must NOT block the audit entry write — ZK witness
/// accumulation is best-effort and must not compromise audit availability.
pub struct WitnessStore {
    witnesses: Mutex<Vec<EntryWitness>>,
    max_capacity: usize,
}

/// Default maximum witness capacity (100K entries ≈ 12MB).
const DEFAULT_MAX_WITNESS_CAPACITY: usize = 100_000;

impl WitnessStore {
    /// Create a new witness store with the default capacity.
    pub fn new() -> Self {
        Self {
            witnesses: Mutex::new(Vec::new()),
            max_capacity: DEFAULT_MAX_WITNESS_CAPACITY,
        }
    }

    /// Create a new witness store with a custom capacity.
    ///
    /// SECURITY (FIND-R176-007): If `max_capacity` is 0, it is silently
    /// clamped to 1 and a warning is logged to prevent a permanently full
    /// store that disables ZK audit without any startup error.
    pub fn with_capacity(max_capacity: usize) -> Self {
        let effective = if max_capacity == 0 {
            tracing::warn!(
                "WitnessStore::with_capacity(0) is invalid — clamping to 1"
            );
            1
        } else {
            max_capacity
        };
        Self {
            witnesses: Mutex::new(Vec::new()),
            max_capacity: effective,
        }
    }

    /// Append a witness to the store.
    ///
    /// Returns `Err` if the store is at capacity (fail-closed: the caller
    /// should log a warning but the audit entry is still written).
    pub fn append(&self, witness: EntryWitness) -> Result<(), ZkError> {
        let mut guard = self
            .witnesses
            .lock()
            .map_err(|e| ZkError::WitnessStore(format!("Witness store lock poisoned: {}", e)))?;

        if guard.len() >= self.max_capacity {
            return Err(ZkError::WitnessStore(format!(
                "Witness store at capacity ({} entries)",
                self.max_capacity
            )));
        }

        guard.push(witness);
        Ok(())
    }

    /// Drain up to `count` witnesses from the front of the store.
    ///
    /// Returns the drained witnesses in order. If fewer than `count`
    /// witnesses are available, returns all available witnesses.
    pub fn drain(&self, count: usize) -> Result<Vec<EntryWitness>, ZkError> {
        let mut guard = self
            .witnesses
            .lock()
            .map_err(|e| ZkError::WitnessStore(format!("Witness store lock poisoned: {}", e)))?;

        let drain_count = count.min(guard.len());
        let drained: Vec<EntryWitness> = guard.drain(..drain_count).collect();
        Ok(drained)
    }

    /// Restore witnesses to the front of the store.
    ///
    /// Used to re-insert witnesses that were drained but could not be proved
    /// (e.g., due to prover failure). The witnesses are prepended in order so
    /// they will be the first to be drained on the next attempt.
    ///
    /// SECURITY (FIND-R222-006): Capacity is enforced after restoration.
    /// If concurrent appends during the drain+prove cycle caused the store
    /// to grow, the total is capped at `max_capacity`. Restored (older)
    /// witnesses are prioritized; excess newer witnesses are dropped with
    /// a warning. This prevents unbounded growth on persistent prover failure.
    pub fn restore(&self, witnesses: Vec<EntryWitness>) -> Result<(), ZkError> {
        let mut guard = self
            .witnesses
            .lock()
            .map_err(|e| ZkError::WitnessStore(format!("Witness store lock poisoned: {}", e)))?;

        // Splice witnesses to the front: prepend the restored witnesses
        // before the existing ones.
        let mut restored = witnesses;
        restored.append(&mut *guard);
        // Cap at max_capacity: restored (older) witnesses at the front are
        // kept; excess newer witnesses at the back are dropped.
        if restored.len() > self.max_capacity {
            let dropped = restored.len() - self.max_capacity;
            tracing::warn!(
                dropped_count = dropped,
                max_capacity = self.max_capacity,
                "WitnessStore::restore() exceeded capacity — dropping {} newest witnesses",
                dropped,
            );
            restored.truncate(self.max_capacity);
        }
        *guard = restored;
        Ok(())
    }

    /// Return the number of pending witnesses.
    pub fn len(&self) -> Result<usize, ZkError> {
        let guard = self
            .witnesses
            .lock()
            .map_err(|e| ZkError::WitnessStore(format!("Witness store lock poisoned: {}", e)))?;
        Ok(guard.len())
    }

    /// Return whether the store is empty.
    pub fn is_empty(&self) -> Result<bool, ZkError> {
        Ok(self.len()? == 0)
    }

    /// Return the maximum capacity.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }
}

impl Default for WitnessStore {
    fn default() -> Self {
        Self::new()
    }
}
