//! Zero-Knowledge Audit Trail types (Phase 37).
//!
//! Defines the public types for Pedersen commitments and ZK batch proofs.
//! These types are serialized into audit entries and API responses.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A Pedersen commitment to an audit entry hash.
///
/// The commitment binds the entry contents without revealing them:
/// `C = entry_hash * G + blinding * H`
///
/// The `blinding_hint` is the hex-encoded blinding factor, stored
/// for the commitment holder only (not shared with verifiers).
/// It is redacted from Debug output and excluded from serialization
/// to prevent accidental exposure.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PedersenCommitment {
    /// Hex-encoded compressed Ristretto point (64 hex chars = 32 bytes).
    pub commitment: String,
    /// Hex-encoded blinding factor (64 hex chars = 32 bytes).
    /// For the holder only — not shared with external verifiers.
    /// SECURITY: Excluded from serialization and redacted in Debug.
    #[serde(default, skip_serializing)]
    pub blinding_hint: String,
}

impl PedersenCommitment {
    /// Maximum length for hex-encoded commitment (64 hex chars for 32-byte Ristretto point, with margin).
    const MAX_COMMITMENT_LEN: usize = 128;
    /// Maximum length for hex-encoded blinding hint.
    const MAX_BLINDING_HINT_LEN: usize = 128;

    /// Validate structural bounds on string fields.
    ///
    /// SECURITY (IMP-R118-001): Prevents memory exhaustion from oversized
    /// commitment strings deserialized from untrusted input.
    pub fn validate(&self) -> Result<(), String> {
        if self.commitment.len() > Self::MAX_COMMITMENT_LEN {
            return Err(format!(
                "PedersenCommitment commitment length {} exceeds max {}",
                self.commitment.len(),
                Self::MAX_COMMITMENT_LEN,
            ));
        }
        if self.blinding_hint.len() > Self::MAX_BLINDING_HINT_LEN {
            return Err(format!(
                "PedersenCommitment blinding_hint length {} exceeds max {}",
                self.blinding_hint.len(),
                Self::MAX_BLINDING_HINT_LEN,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for PedersenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PedersenCommitment")
            .field("commitment", &self.commitment)
            .field("blinding_hint", &"[REDACTED]")
            .finish()
    }
}

/// A batch ZK proof covering a range of audit entries.
///
/// Proves that a sequence of audit entries forms a valid hash chain
/// and that their Pedersen commitments match, without revealing the
/// entry contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkBatchProof {
    /// Hex-encoded Groth16 proof bytes.
    pub proof: String,
    /// Unique batch identifier (UUID).
    pub batch_id: String,
    /// Inclusive range of entry sequence numbers covered by this proof.
    pub entry_range: (u64, u64),
    /// Hex-encoded Merkle root at the end of the batch.
    pub merkle_root: String,
    /// Hex-encoded prev_hash of the first entry (public input).
    pub first_prev_hash: String,
    /// Hex-encoded entry_hash of the last entry (public input).
    pub final_entry_hash: String,
    /// ISO 8601 timestamp when the proof was created.
    pub created_at: String,
    /// Number of entries in the batch.
    pub entry_count: usize,
}

impl ZkBatchProof {
    /// Maximum length for hex-encoded proof bytes.
    const MAX_PROOF_LEN: usize = 65_536;
    /// Maximum length for batch_id (UUID string).
    const MAX_BATCH_ID_LEN: usize = 256;
    /// Maximum length for hex-encoded hash strings.
    const MAX_HASH_LEN: usize = 256;
    /// Maximum length for ISO 8601 timestamp strings.
    const MAX_TIMESTAMP_LEN: usize = 64;

    /// Validate structural bounds on string fields.
    ///
    /// SECURITY: Prevents memory exhaustion from oversized proof payloads
    /// deserialized from untrusted API input.
    pub fn validate(&self) -> Result<(), String> {
        if self.proof.len() > Self::MAX_PROOF_LEN {
            return Err(format!(
                "ZkBatchProof proof length {} exceeds max {}",
                self.proof.len(),
                Self::MAX_PROOF_LEN,
            ));
        }
        if self.batch_id.len() > Self::MAX_BATCH_ID_LEN {
            return Err(format!(
                "ZkBatchProof batch_id length {} exceeds max {}",
                self.batch_id.len(),
                Self::MAX_BATCH_ID_LEN,
            ));
        }
        // SECURITY (FIND-R115-003): Reject control/format chars in identity fields.
        if self
            .batch_id
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "ZkBatchProof batch_id contains control or format characters".to_string(),
            );
        }
        if self.merkle_root.len() > Self::MAX_HASH_LEN {
            return Err(format!(
                "ZkBatchProof merkle_root length {} exceeds max {}",
                self.merkle_root.len(),
                Self::MAX_HASH_LEN,
            ));
        }
        if self.first_prev_hash.len() > Self::MAX_HASH_LEN {
            return Err(format!(
                "ZkBatchProof first_prev_hash length {} exceeds max {}",
                self.first_prev_hash.len(),
                Self::MAX_HASH_LEN,
            ));
        }
        if self.final_entry_hash.len() > Self::MAX_HASH_LEN {
            return Err(format!(
                "ZkBatchProof final_entry_hash length {} exceeds max {}",
                self.final_entry_hash.len(),
                Self::MAX_HASH_LEN,
            ));
        }
        if self.created_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "ZkBatchProof created_at length {} exceeds max {}",
                self.created_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        // SECURITY (FIND-R115-003): Reject control/format chars in timestamp fields.
        if self
            .created_at
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "ZkBatchProof created_at contains control or format characters".to_string(),
            );
        }
        Ok(())
    }
}

/// Result of verifying a ZK batch proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkVerifyResult {
    /// Whether the proof is valid.
    pub valid: bool,
    /// The batch ID that was verified.
    pub batch_id: String,
    /// The entry range that was verified.
    pub entry_range: (u64, u64),
    /// ISO 8601 timestamp when verification was performed.
    pub verified_at: String,
    /// Error message if verification failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ZkVerifyResult {
    /// Maximum length for batch_id.
    const MAX_BATCH_ID_LEN: usize = 256;
    /// Maximum length for ISO 8601 timestamp.
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for error messages.
    const MAX_ERROR_LEN: usize = 4096;

    /// Validate structural bounds on string fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.batch_id.len() > Self::MAX_BATCH_ID_LEN {
            return Err(format!(
                "ZkVerifyResult batch_id length {} exceeds max {}",
                self.batch_id.len(),
                Self::MAX_BATCH_ID_LEN,
            ));
        }
        if self.verified_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "ZkVerifyResult verified_at length {} exceeds max {}",
                self.verified_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if let Some(ref err) = self.error {
            if err.len() > Self::MAX_ERROR_LEN {
                return Err(format!(
                    "ZkVerifyResult error length {} exceeds max {}",
                    err.len(),
                    Self::MAX_ERROR_LEN,
                ));
            }
        }
        Ok(())
    }
}

/// Status of the ZK audit scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkSchedulerStatus {
    /// Whether the batch prover is active.
    pub active: bool,
    /// Number of pending witnesses awaiting batch proof.
    pub pending_witnesses: usize,
    /// Number of completed batch proofs.
    pub completed_proofs: usize,
    /// Sequence number of the last proved entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_proved_sequence: Option<u64>,
    /// ISO 8601 timestamp of the last batch proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_proof_at: Option<String>,
}

impl ZkSchedulerStatus {
    /// Maximum length for ISO 8601 timestamp.
    const MAX_TIMESTAMP_LEN: usize = 64;

    /// Validate structural bounds on string fields.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref ts) = self.last_proof_at {
            if ts.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "ZkSchedulerStatus last_proof_at length {} exceeds max {}",
                    ts.len(),
                    Self::MAX_TIMESTAMP_LEN,
                ));
            }
        }
        Ok(())
    }
}
