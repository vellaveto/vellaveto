//! Incremental append-only Merkle tree for audit log inclusion proofs.
//!
//! Uses RFC 6962 domain separation to prevent second-preimage attacks:
//! - Leaf hash: `SHA-256(0x00 || data)`
//! - Internal hash: `SHA-256(0x01 || left || right)`
//!
//! The tree is maintained as a set of O(log n) "peaks" (the top-level hashes
//! of complete binary sub-trees), enabling O(log n) amortized append and
//! O(log n) proof generation.
//!
//! Leaf hashes are persisted to a binary file (32 bytes per leaf) for
//! crash recovery and proof generation without replaying the full log.

use crate::types::AuditError;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Domain separation byte for leaf hashes (RFC 6962).
const LEAF_PREFIX: u8 = 0x00;
/// Domain separation byte for internal node hashes (RFC 6962).
const INTERNAL_PREFIX: u8 = 0x01;
/// Size of a SHA-256 hash in bytes.
const HASH_SIZE: usize = 32;

/// Default maximum number of leaves allowed in a single Merkle tree.
/// SECURITY (FIND-R46-001): Prevents OOM when loading large leaf files.
const DEFAULT_MAX_LEAF_COUNT: u64 = 1_000_000;

/// Incremental append-only Merkle tree.
///
/// Stores leaf hashes in a binary file and maintains O(log n) peaks
/// in memory for efficient root computation and proof generation.
pub struct MerkleTree {
    /// Number of leaves appended to the tree.
    leaf_count: u64,
    /// Peaks of complete binary sub-trees. `peaks[i]` is the root of a
    /// sub-tree of size 2^i, or `None` if no such sub-tree exists in the
    /// current decomposition.
    peaks: Vec<Option<[u8; 32]>>,
    /// Path to the binary file storing leaf hashes (32 bytes per leaf).
    leaf_file_path: PathBuf,
    /// Maximum number of leaves allowed in the tree.
    /// SECURITY (FIND-R46-001): Prevents OOM from unbounded leaf accumulation.
    max_leaf_count: u64,
}

/// Inclusion proof for a single leaf in the Merkle tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf being proved (0-based).
    pub leaf_index: u64,
    /// Total number of leaves when the proof was generated.
    pub tree_size: u64,
    /// Bottom-up list of sibling hashes needed to reconstruct the root.
    pub siblings: Vec<ProofStep>,
    /// Root hash at `tree_size` (hex-encoded).
    pub root_hash: String,
}

/// A single step in a Merkle inclusion proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofStep {
    /// Hex-encoded sibling hash.
    pub hash: String,
    /// Whether this sibling is on the left side of the concatenation.
    pub is_left: bool,
}

/// Result of verifying a Merkle inclusion proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleVerification {
    /// Whether the proof is valid.
    pub valid: bool,
    /// Reason for failure, if any.
    pub failure_reason: Option<String>,
}

/// Compute a leaf hash with RFC 6962 domain separation.
///
/// `hash_leaf(data) = SHA-256(0x00 || data)`
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute an internal node hash with RFC 6962 domain separation.
///
/// `hash_internal(left, right) = SHA-256(0x01 || left || right)`
///
/// The `0x01` prefix is the RFC 6962 domain separation byte for internal
/// (non-leaf) nodes. This prevents second-preimage attacks where an
/// attacker tries to reinterpret a leaf as an internal node or vice versa.
///
/// This function is public so that external verifiers can reconstruct
/// Merkle proofs independently using the same domain-separated hash.
pub fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

impl MerkleTree {
    /// Create a new empty Merkle tree that stores leaf hashes at the given path.
    pub fn new(leaf_file_path: PathBuf) -> Self {
        Self {
            leaf_count: 0,
            peaks: Vec::new(),
            leaf_file_path,
            max_leaf_count: DEFAULT_MAX_LEAF_COUNT,
        }
    }

    /// Set a custom maximum leaf count.
    /// SECURITY (FIND-R46-001): Configure the OOM protection threshold.
    pub fn with_max_leaf_count(mut self, max: u64) -> Self {
        self.max_leaf_count = max;
        self
    }

    /// Return the number of leaves in the tree.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Append a leaf hash to the tree.
    ///
    /// The leaf hash is persisted to the binary leaf file and the in-memory
    /// peaks are updated. This is O(log n) amortized.
    pub fn append(&mut self, leaf_hash: [u8; 32]) -> Result<(), AuditError> {
        // SECURITY (FIND-R46-001): Reject appends that would exceed the max leaf count.
        if self.leaf_count >= self.max_leaf_count {
            return Err(AuditError::Validation(format!(
                "Merkle tree leaf count limit reached ({} >= {})",
                self.leaf_count, self.max_leaf_count
            )));
        }

        // Persist the leaf hash to the binary file
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.leaf_file_path)
            .inspect_err(|_| {
                if let Some(parent) = self.leaf_file_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
            })
            .or_else(|_| {
                if let Some(parent) = self.leaf_file_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.leaf_file_path)
            })?;
        file.write_all(&leaf_hash)?;
        file.flush()?;
        // SECURITY (FIND-R46-010): fsync leaf file to ensure crash durability.
        file.sync_data()?;

        // SECURITY (FIND-R170-001): Restrict Merkle leaf file permissions to
        // owner-only (0o600), matching audit log (logger.rs:460) and checkpoint
        // (checkpoints.rs:103) permission policies.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(
                &self.leaf_file_path,
                std::fs::Permissions::from_mode(0o600),
            ) {
                tracing::warn!(
                    error = %e,
                    "Failed to set Merkle leaf file permissions to 0o600"
                );
            }
        }

        // Update peaks: carry-merge like binary addition
        let mut carry = leaf_hash;
        let mut level = 0usize;
        loop {
            if level >= self.peaks.len() {
                self.peaks.push(Some(carry));
                break;
            }
            match self.peaks[level].take() {
                Some(existing) => {
                    // Merge: existing is the left child, carry is the right
                    carry = hash_internal(&existing, &carry);
                    level += 1;
                }
                None => {
                    self.peaks[level] = Some(carry);
                    break;
                }
            }
        }

        // SECURITY (FIND-R186-006): saturating_add for coding standard compliance.
        self.leaf_count = self.leaf_count.saturating_add(1);
        Ok(())
    }

    /// Compute the current root hash.
    ///
    /// Folds peaks low-to-high: the smallest sub-tree (lowest peak) starts
    /// as the accumulator, and each higher peak is placed on the left.
    /// This matches the RFC 6962 / standard binary Merkle tree structure
    /// where the split is at the largest power of 2 less than n.
    /// Returns `None` if the tree is empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.leaf_count == 0 {
            return None;
        }

        let mut root: Option<[u8; 32]> = None;
        // Iterate from lowest peak to highest; accumulator goes on the right
        for p in self.peaks.iter().flatten() {
            root = Some(match root {
                Some(r) => hash_internal(p, &r),
                None => *p,
            });
        }
        root
    }

    /// Return the current root hash as a hex string, or `None` if empty.
    pub fn root_hex(&self) -> Option<String> {
        self.root().map(hex::encode)
    }

    /// Reset the tree state for log rotation.
    ///
    /// Clears in-memory peaks and leaf count. Does NOT delete the leaf file
    /// (the caller is responsible for renaming it alongside the rotated log).
    pub fn reset(&mut self) {
        self.leaf_count = 0;
        self.peaks.clear();
    }

    /// Rebuild the in-memory peaks from an existing leaf file.
    ///
    /// Call this at startup to recover state after a crash. If the leaf file
    /// has a partial write (not a multiple of 32 bytes), the trailing bytes
    /// are truncated.
    pub fn initialize(&mut self) -> Result<(), AuditError> {
        self.leaf_count = 0;
        self.peaks.clear();

        // SECURITY (FIND-R46-001/002): Check file size before reading to prevent OOM.
        match std::fs::metadata(&self.leaf_file_path) {
            Ok(meta) => {
                let max_file_size = self.max_leaf_count * HASH_SIZE as u64;
                if meta.len() > max_file_size {
                    return Err(AuditError::Validation(format!(
                        "Merkle leaf file too large ({} bytes, max {} bytes for {} leaves)",
                        meta.len(),
                        max_file_size,
                        self.max_leaf_count
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(AuditError::Io(e)),
        }

        let data = match std::fs::read(&self.leaf_file_path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        // Truncate partial writes
        let valid_len = (data.len() / HASH_SIZE) * HASH_SIZE;
        if valid_len < data.len() {
            tracing::warn!(
                path = %self.leaf_file_path.display(),
                file_len = data.len(),
                valid_len = valid_len,
                "Merkle leaf file has partial write, truncating to last complete hash"
            );
            // Truncate the file to remove partial write
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&self.leaf_file_path)?;
            file.set_len(valid_len as u64)?;
        }

        // SECURITY (FIND-R46-001): Check leaf count before replaying.
        let leaf_count = (valid_len / HASH_SIZE) as u64;
        if leaf_count > self.max_leaf_count {
            return Err(AuditError::Validation(format!(
                "Merkle leaf file contains too many leaves ({} > {})",
                leaf_count, self.max_leaf_count
            )));
        }

        // Replay leaf hashes into peaks (without re-writing to file)
        for chunk in data[..valid_len].chunks_exact(HASH_SIZE) {
            let mut leaf_hash = [0u8; 32];
            leaf_hash.copy_from_slice(chunk);
            self.replay_leaf(leaf_hash);
        }

        Ok(())
    }

    /// Replay a leaf hash into peaks without writing to the leaf file.
    /// Used during initialization from an existing leaf file.
    fn replay_leaf(&mut self, leaf_hash: [u8; 32]) {
        let mut carry = leaf_hash;
        let mut level = 0usize;
        loop {
            if level >= self.peaks.len() {
                self.peaks.push(Some(carry));
                break;
            }
            match self.peaks[level].take() {
                Some(existing) => {
                    carry = hash_internal(&existing, &carry);
                    level += 1;
                }
                None => {
                    self.peaks[level] = Some(carry);
                    break;
                }
            }
        }
        // SECURITY (FIND-R186-006): saturating_add for coding standard compliance.
        self.leaf_count = self.leaf_count.saturating_add(1);
    }

    /// Generate an inclusion proof for the leaf at `index`.
    ///
    /// Reads leaf hashes from the binary file and computes the sibling
    /// path from the leaf to the root. The proof can be verified without
    /// access to the full tree.
    pub fn generate_proof(&self, index: u64) -> Result<MerkleProof, AuditError> {
        if index >= self.leaf_count {
            return Err(AuditError::Validation(format!(
                "Leaf index {} out of range (tree has {} leaves)",
                index, self.leaf_count
            )));
        }

        let root = self.root().ok_or_else(|| {
            AuditError::Validation("Cannot generate proof for empty tree".to_string())
        })?;

        // SECURITY (FIND-R46-004): Check file size before reading to prevent OOM.
        let file_meta = std::fs::metadata(&self.leaf_file_path)?;
        let max_file_size = self.max_leaf_count * HASH_SIZE as u64;
        if file_meta.len() > max_file_size {
            return Err(AuditError::Validation(format!(
                "Merkle leaf file too large for proof generation ({} bytes, max {} bytes)",
                file_meta.len(),
                max_file_size
            )));
        }

        // Read all leaf hashes from the file
        let data = std::fs::read(&self.leaf_file_path)?;
        let n = self.leaf_count as usize;
        if data.len() < n * HASH_SIZE {
            return Err(AuditError::Validation(
                "Leaf file is shorter than expected".to_string(),
            ));
        }

        let leaves: Vec<[u8; 32]> = data[..n * HASH_SIZE]
            .chunks_exact(HASH_SIZE)
            .map(|chunk| {
                let mut h = [0u8; 32];
                h.copy_from_slice(chunk);
                h
            })
            .collect();

        // Build the proof by walking up the tree
        let siblings = self.compute_siblings(&leaves, index as usize)?;

        Ok(MerkleProof {
            leaf_index: index,
            tree_size: self.leaf_count,
            siblings,
            root_hash: hex::encode(root),
        })
    }

    /// Compute the sibling path for a leaf at the given index.
    ///
    /// This handles the general case of non-power-of-2 trees by
    /// building sub-trees from the binary decomposition of n.
    ///
    /// ## Edge Cases (GAP-S07)
    ///
    /// - **Empty tree** (`n == 0`): returns empty sibling list.
    /// - **Single leaf** (`n == 1`): returns empty sibling list (the leaf IS the root).
    /// - **Odd node at level boundary**: promoted without a sibling, so no ProofStep
    ///   is emitted for that level.
    fn compute_siblings(
        &self,
        leaves: &[[u8; 32]],
        index: usize,
    ) -> Result<Vec<ProofStep>, AuditError> {
        let n = leaves.len();
        if n == 0 || n == 1 {
            return Ok(Vec::new());
        }

        // Build the full hash tree level by level
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
        levels.push(leaves.to_vec());

        let mut current = leaves.to_vec();
        while current.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i + 1 < current.len() {
                next.push(hash_internal(&current[i], &current[i + 1]));
                i += 2;
            }
            // Odd node promoted
            if i < current.len() {
                next.push(current[i]);
            }
            levels.push(next.clone());
            current = next;
        }

        // Walk from the leaf level upward, collecting siblings
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &levels[..levels.len() - 1] {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            if sibling_idx < level.len() {
                siblings.push(ProofStep {
                    hash: hex::encode(level[sibling_idx]),
                    is_left: idx % 2 == 1,
                });
            }
            // If sibling_idx >= level.len(), this node is promoted (odd one out)
            // and has no sibling at this level — skip.
            idx /= 2;
        }

        Ok(siblings)
    }

    /// Verify a Merkle inclusion proof against a trusted root.
    ///
    /// This is a static method — it requires no disk access, only the
    /// leaf hash, the proof, and a trusted root hash (hex-encoded) obtained
    /// from the Merkle tree state or a signed checkpoint.
    ///
    /// SECURITY (FIND-R46-MRK-002): The `trusted_root` parameter MUST come
    /// from a trusted source (e.g., the live Merkle tree or a signed checkpoint),
    /// NOT from the proof itself. Comparing against the proof's own `root_hash`
    /// would allow an attacker to forge self-consistent proofs.
    pub fn verify_proof(
        leaf_hash: [u8; 32],
        proof: &MerkleProof,
        trusted_root: &str,
    ) -> Result<MerkleVerification, AuditError> {
        // SECURITY (FIND-R52-AUDIT-003): Bound proof siblings to 64. A tree with
        // 2^64 leaves is physically impossible, so any proof claiming more siblings
        // is malicious or corrupt. This prevents CPU waste iterating forged proofs.
        const MAX_PROOF_SIBLINGS: usize = 64;
        if proof.siblings.len() > MAX_PROOF_SIBLINGS {
            return Err(AuditError::Validation(format!(
                "Proof has too many siblings ({}, max {})",
                proof.siblings.len(),
                MAX_PROOF_SIBLINGS
            )));
        }

        if proof.tree_size == 0 {
            return Ok(MerkleVerification {
                valid: false,
                failure_reason: Some("Proof has zero tree size".to_string()),
            });
        }

        if proof.leaf_index >= proof.tree_size {
            return Ok(MerkleVerification {
                valid: false,
                failure_reason: Some(format!(
                    "Leaf index {} >= tree size {}",
                    proof.leaf_index, proof.tree_size
                )),
            });
        }

        let mut current = leaf_hash;
        for step in &proof.siblings {
            let sibling = hex::decode(&step.hash)
                .map_err(|e| AuditError::Validation(format!("Invalid sibling hash hex: {}", e)))?;
            if sibling.len() != HASH_SIZE {
                return Ok(MerkleVerification {
                    valid: false,
                    failure_reason: Some(format!(
                        "Sibling hash has wrong length: {} (expected {})",
                        sibling.len(),
                        HASH_SIZE
                    )),
                });
            }
            let mut sibling_arr = [0u8; 32];
            sibling_arr.copy_from_slice(&sibling);

            current = if step.is_left {
                hash_internal(&sibling_arr, &current)
            } else {
                hash_internal(&current, &sibling_arr)
            };
        }

        let computed_root = hex::encode(current);
        if computed_root == trusted_root {
            Ok(MerkleVerification {
                valid: true,
                failure_reason: None,
            })
        } else {
            Ok(MerkleVerification {
                valid: false,
                failure_reason: Some(format!(
                    "Root mismatch: computed {} but trusted root is {}",
                    computed_root, trusted_root
                )),
            })
        }
    }

    /// Return the path to the leaf file.
    pub fn leaf_file_path(&self) -> &std::path::Path {
        &self.leaf_file_path
    }
}
