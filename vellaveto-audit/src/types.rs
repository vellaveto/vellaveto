use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use vellaveto_types::{Action, Verdict};

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub action: Action,
    pub verdict: Verdict,
    pub timestamp: String,
    pub metadata: serde_json::Value,
    /// Monotonic sequence number within this audit log file.
    /// SECURITY (R33-001): Prevents hash collision under high load even if
    /// timestamps collide. Combined with UUID id, ensures unique hash inputs.
    #[serde(default)]
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    /// Pedersen commitment to the entry hash (Phase 37: ZK Audit Trails).
    /// Present only when the `zk-audit` feature is enabled and commitments
    /// are configured. Hex-encoded compressed Ristretto point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub total_entries: usize,
    pub allow_count: usize,
    pub deny_count: usize,
    pub require_approval_count: usize,
    pub entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLogEntry {
    pub timestamp: String,
    pub error: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub valid: bool,
    pub entries_checked: usize,
    pub first_broken_at: Option<usize>,
}

/// Result of verifying chain integrity across rotated log files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationVerification {
    /// Whether all rotated files pass verification.
    pub valid: bool,
    /// Number of rotated files checked.
    pub files_checked: usize,
    /// Description of the first failure, if any.
    pub first_failure: Option<String>,
}

/// A signed checkpoint that periodically attests to the audit chain state.
///
/// Checkpoints provide non-repudiation: even if an attacker compromises the
/// server and modifies audit entries, they cannot forge valid Ed25519 signatures
/// without the signing key. Checkpoints are stored in a separate JSONL file
/// alongside the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Unique checkpoint identifier.
    pub id: String,
    /// ISO 8601 timestamp when the checkpoint was created.
    pub timestamp: String,
    /// Number of entries in the audit log at checkpoint time.
    pub entry_count: usize,
    /// SHA-256 hash of the last entry at checkpoint time (chain head).
    /// None if the audit log is empty.
    pub chain_head_hash: Option<String>,
    /// Ed25519 signature over the canonical checkpoint content.
    /// Hex-encoded 64-byte signature.
    pub signature: String,
    /// Ed25519 verifying key (public key) for this checkpoint.
    /// Hex-encoded 32-byte key.
    pub verifying_key: String,
    /// Merkle tree root hash at checkpoint time (hex-encoded SHA-256).
    /// None if Merkle tree is not enabled or the tree is empty.
    /// Backward compatible: old checkpoints without this field still verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
}

impl Checkpoint {
    /// Compute the canonical content that is signed.
    ///
    /// Content = SHA-256(id || timestamp || entry_count_le || chain_head_hash)
    /// Each field is length-prefixed with u64 LE to prevent boundary collisions.
    pub(crate) fn signing_content(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        Self::hash_field(&mut hasher, self.id.as_bytes());
        Self::hash_field(&mut hasher, self.timestamp.as_bytes());
        Self::hash_field(&mut hasher, &(self.entry_count as u64).to_le_bytes());
        Self::hash_field(
            &mut hasher,
            self.chain_head_hash.as_deref().unwrap_or("").as_bytes(),
        );
        // Include merkle_root only when present (backward compat: old
        // checkpoints without merkle_root still produce the same content).
        if let Some(ref mr) = self.merkle_root {
            Self::hash_field(&mut hasher, mr.as_bytes());
        }
        hasher.finalize().to_vec()
    }

    pub(crate) fn hash_field(hasher: &mut Sha256, data: &[u8]) {
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
    }
}

/// Result of verifying all checkpoints against the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointVerification {
    /// Whether all checkpoints are valid.
    pub valid: bool,
    /// Number of checkpoints checked.
    pub checkpoints_checked: usize,
    /// Index of the first invalid checkpoint, if any.
    pub first_invalid_at: Option<usize>,
    /// Reason for the first failure, if any.
    pub failure_reason: Option<String>,
}

/// Controls how aggressively the audit logger redacts sensitive data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedactionLevel {
    /// No redaction — raw values are logged as-is.
    Off,
    /// Redact sensitive keys (passwords, tokens, etc.) and known value prefixes.
    KeysOnly,
    /// Redact keys, value prefixes, and PII-like patterns (default).
    #[default]
    KeysAndPatterns,
}
