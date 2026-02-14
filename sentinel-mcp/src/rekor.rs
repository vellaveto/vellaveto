//! Sigstore/Rekor Transparency Log Integration (Phase 23.4).
//!
//! Provides Rekor transparency log types and offline verification for tool
//! signature provenance. Integrates with the ETDI `ToolSignatureVerifier`
//! to verify that tool signatures were recorded in a transparency log.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════
// Rekor Entry Types
// ═══════════════════════════════════════════════════════════════════

/// A Rekor log entry for tool signature transparency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorEntry {
    /// Index of this entry in the log.
    pub log_index: u64,
    /// Log ID (hex-encoded hash of the log's public key).
    pub log_id: String,
    /// Unix timestamp when the entry was integrated into the log.
    pub integrated_time: u64,
    /// Entry body.
    pub body: RekorBody,
    /// Optional inclusion proof for offline verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<RekorInclusionProof>,
}

/// Body of a Rekor log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorBody {
    /// API version (e.g., "0.0.1").
    pub api_version: String,
    /// Entry kind (e.g., "hashedrekord").
    pub kind: String,
    /// Entry specification.
    pub spec: RekorSpec,
}

/// Specification of a Rekor hashedrekord entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorSpec {
    /// Signature information.
    pub signature: RekorSignature,
    /// Data that was signed.
    pub data: RekorData,
}

/// Signature within a Rekor entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorSignature {
    /// Base64-encoded signature bytes.
    pub content: String,
    /// Public key of the signer.
    pub public_key: RekorPublicKey,
}

/// Public key in a Rekor entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorPublicKey {
    /// Base64-encoded public key (PEM or raw).
    pub content: String,
}

/// Data reference in a Rekor entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorData {
    /// Hash of the signed data.
    pub hash: RekorHash,
}

/// Hash in a Rekor entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorHash {
    /// Hash algorithm (e.g., "sha256").
    pub algorithm: String,
    /// Hex-encoded hash value.
    pub value: String,
}

/// Merkle tree inclusion proof from Rekor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorInclusionProof {
    /// Log index of this entry.
    pub log_index: u64,
    /// Hex-encoded root hash of the Merkle tree.
    pub root_hash: String,
    /// Total tree size at time of proof.
    pub tree_size: u64,
    /// Hex-encoded intermediate hashes (path from leaf to root).
    pub hashes: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════
// Verification
// ═══════════════════════════════════════════════════════════════════

/// Offline Rekor entry verifier.
///
/// Verifies inclusion proofs and tool hash matches without contacting
/// the Rekor server.
pub struct RekorVerifier {
    /// Optional known Rekor log public key for signature verification.
    _rekor_public_key: Option<Vec<u8>>,
}

/// Result of a full Rekor verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorVerification {
    /// Whether the inclusion proof is valid.
    pub inclusion_valid: bool,
    /// Whether the tool hash matches the entry.
    pub hash_matches: bool,
    /// Unix timestamp of log integration.
    pub timestamp: u64,
    /// Log index of the entry.
    pub log_index: u64,
}

/// Errors from Rekor operations.
#[derive(Error, Debug)]
pub enum RekorError {
    #[error("Invalid inclusion proof: {0}")]
    InvalidProof(String),
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("Missing inclusion proof")]
    MissingProof,
    #[error("Invalid hash format: {0}")]
    InvalidHash(String),
    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

impl RekorVerifier {
    /// Create a new verifier without a log public key (proof verification only).
    pub fn new() -> Self {
        Self {
            _rekor_public_key: None,
        }
    }

    /// Create a verifier with a known Rekor log public key.
    pub fn with_public_key(key: Vec<u8>) -> Self {
        Self {
            _rekor_public_key: Some(key),
        }
    }

    /// Verify a Rekor inclusion proof (Merkle tree path).
    ///
    /// Walks the proof hashes from the leaf to the root, using RFC 6962
    /// domain separation (`0x01 || left || right`), and compares the
    /// computed root to the declared root hash.
    ///
    /// Uses canonical JSON (RFC 8785) for the leaf hash to ensure deterministic
    /// hashing regardless of serialization key order (FIND-P23-K02).
    pub fn verify_inclusion_proof(&self, entry: &RekorEntry) -> Result<bool, RekorError> {
        let proof = entry
            .inclusion_proof
            .as_ref()
            .ok_or(RekorError::MissingProof)?;

        if proof.tree_size == 0 {
            return Err(RekorError::InvalidProof("tree_size is 0".to_string()));
        }

        // Validate proof length is consistent with tree_size (FIND-P23-K04).
        // For a tree of size N, the inclusion proof should have at most ceil(log2(N)) hashes.
        // An empty proof is only valid for tree_size == 1.
        if proof.tree_size > 1 && proof.hashes.is_empty() {
            return Err(RekorError::InvalidProof(
                "Empty proof for tree_size > 1".to_string(),
            ));
        }
        let max_proof_len = 64; // ceil(log2(u64::MAX)) = 64
        if proof.hashes.len() > max_proof_len {
            return Err(RekorError::InvalidProof(format!(
                "Proof has {} hashes (max {})",
                proof.hashes.len(),
                max_proof_len
            )));
        }

        // Validate log_index < tree_size
        if proof.log_index >= proof.tree_size {
            return Err(RekorError::InvalidProof(format!(
                "log_index {} >= tree_size {}",
                proof.log_index, proof.tree_size
            )));
        }

        // Compute leaf hash using canonical JSON (RFC 8785) for deterministic hashing
        let body_json = serde_json::to_value(&entry.body)
            .map_err(|e| RekorError::InvalidProof(format!("Failed to serialize body: {}", e)))?;
        let canonical_bytes = serde_json_canonicalizer::to_vec(&body_json)
            .map_err(|e| RekorError::InvalidProof(format!("Failed to canonicalize body: {}", e)))?;
        let mut leaf_hasher = Sha256::new();
        leaf_hasher.update([0x00]); // RFC 6962 leaf domain separator
        leaf_hasher.update(&canonical_bytes);
        let mut current = leaf_hasher.finalize().to_vec();

        // Walk the proof path
        let mut index = proof.log_index;
        for hash_hex in &proof.hashes {
            let sibling = hex::decode(hash_hex)
                .map_err(|e| RekorError::InvalidHash(format!("Bad hex in proof: {}", e)))?;

            if sibling.len() != 32 {
                return Err(RekorError::InvalidHash(format!(
                    "Hash has {} bytes, expected 32",
                    sibling.len()
                )));
            }

            // RFC 6962 interior node: SHA-256(0x01 || left || right)
            let mut hasher = Sha256::new();
            hasher.update([0x01]); // Interior node domain separator
            if index % 2 == 0 {
                hasher.update(&current);
                hasher.update(&sibling);
            } else {
                hasher.update(&sibling);
                hasher.update(&current);
            }
            current = hasher.finalize().to_vec();
            index /= 2;
        }

        let computed_root = hex::encode(&current);
        Ok(computed_root == proof.root_hash)
    }

    /// Verify that a tool hash matches the Rekor entry's data hash.
    pub fn verify_tool_hash(
        &self,
        tool_hash: &str,
        entry: &RekorEntry,
    ) -> Result<bool, RekorError> {
        if entry.body.spec.data.hash.algorithm != "sha256" {
            return Err(RekorError::UnsupportedAlgorithm(
                entry.body.spec.data.hash.algorithm.clone(),
            ));
        }

        Ok(tool_hash == entry.body.spec.data.hash.value)
    }

    /// Full offline verification: inclusion proof + tool hash match.
    pub fn verify_entry(
        &self,
        tool_hash: &str,
        entry: &RekorEntry,
    ) -> Result<RekorVerification, RekorError> {
        let inclusion_valid = self.verify_inclusion_proof(entry)?;
        let hash_matches = self.verify_tool_hash(tool_hash, entry)?;

        Ok(RekorVerification {
            inclusion_valid,
            hash_matches,
            timestamp: entry.integrated_time,
            log_index: entry.log_index,
        })
    }
}

impl Default for RekorVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_entry(data_hash: &str) -> RekorEntry {
        RekorEntry {
            log_index: 42,
            log_id: "test-log".to_string(),
            integrated_time: 1700000000,
            body: RekorBody {
                api_version: "0.0.1".to_string(),
                kind: "hashedrekord".to_string(),
                spec: RekorSpec {
                    signature: RekorSignature {
                        content: "dGVzdA==".to_string(),
                        public_key: RekorPublicKey {
                            content: "dGVzdA==".to_string(),
                        },
                    },
                    data: RekorData {
                        hash: RekorHash {
                            algorithm: "sha256".to_string(),
                            value: data_hash.to_string(),
                        },
                    },
                },
            },
            inclusion_proof: None,
        }
    }

    #[test]
    fn test_rekor_entry_serialization() {
        let entry = make_test_entry("abc123");
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: RekorEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.log_index, 42);
        assert_eq!(deserialized.body.spec.data.hash.value, "abc123");
    }

    #[test]
    fn test_tool_hash_matching() {
        let verifier = RekorVerifier::new();
        let entry = make_test_entry("abc123def456");

        assert!(verifier.verify_tool_hash("abc123def456", &entry).unwrap());
        assert!(!verifier.verify_tool_hash("wrong_hash", &entry).unwrap());
    }

    #[test]
    fn test_tool_hash_unsupported_algorithm() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("abc");
        entry.body.spec.data.hash.algorithm = "md5".to_string();

        let result = verifier.verify_tool_hash("abc", &entry);
        assert!(matches!(result, Err(RekorError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_missing_inclusion_proof() {
        let verifier = RekorVerifier::new();
        let entry = make_test_entry("abc");

        let result = verifier.verify_inclusion_proof(&entry);
        assert!(matches!(result, Err(RekorError::MissingProof)));
    }

    /// Helper to compute the canonical leaf hash for a Rekor entry body.
    fn compute_leaf_hash(body: &RekorBody) -> Vec<u8> {
        let body_json = serde_json::to_value(body).unwrap();
        let canonical_bytes = serde_json_canonicalizer::to_vec(&body_json).unwrap();
        let mut leaf_hasher = Sha256::new();
        leaf_hasher.update([0x00]);
        leaf_hasher.update(&canonical_bytes);
        leaf_hasher.finalize().to_vec()
    }

    #[test]
    fn test_inclusion_proof_with_known_good_proof() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("abc");

        // Compute the leaf hash using canonical JSON
        let leaf = compute_leaf_hash(&entry.body);

        // Single-element tree: root = leaf hash (empty proof valid for tree_size=1)
        entry.inclusion_proof = Some(RekorInclusionProof {
            log_index: 0,
            root_hash: hex::encode(&leaf),
            tree_size: 1,
            hashes: vec![],
        });

        assert!(verifier.verify_inclusion_proof(&entry).unwrap());
    }

    #[test]
    fn test_inclusion_proof_rejected_with_tampered_hash() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("abc");

        entry.inclusion_proof = Some(RekorInclusionProof {
            log_index: 0,
            root_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            tree_size: 1,
            hashes: vec![],
        });

        // Should not match because root_hash doesn't match computed leaf
        assert!(!verifier.verify_inclusion_proof(&entry).unwrap());
    }

    #[test]
    fn test_full_offline_verification() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("tool_hash_123");

        // Set up valid proof (single leaf) using canonical JSON
        let leaf = compute_leaf_hash(&entry.body);

        entry.inclusion_proof = Some(RekorInclusionProof {
            log_index: 0,
            root_hash: hex::encode(&leaf),
            tree_size: 1,
            hashes: vec![],
        });

        let result = verifier.verify_entry("tool_hash_123", &entry).unwrap();
        assert!(result.inclusion_valid);
        assert!(result.hash_matches);
        assert_eq!(result.log_index, 42);
        assert_eq!(result.timestamp, 1700000000);
    }

    #[test]
    fn test_full_verification_hash_mismatch() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("correct_hash");

        // Valid proof using canonical JSON
        let leaf = compute_leaf_hash(&entry.body);

        entry.inclusion_proof = Some(RekorInclusionProof {
            log_index: 0,
            root_hash: hex::encode(&leaf),
            tree_size: 1,
            hashes: vec![],
        });

        let result = verifier.verify_entry("wrong_hash", &entry).unwrap();
        assert!(result.inclusion_valid);
        assert!(!result.hash_matches);
    }

    #[test]
    fn test_empty_proof_hashes_with_tree_size_zero() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("abc");

        entry.inclusion_proof = Some(RekorInclusionProof {
            log_index: 0,
            root_hash: "abc".to_string(),
            tree_size: 0,
            hashes: vec![],
        });

        let result = verifier.verify_inclusion_proof(&entry);
        assert!(matches!(result, Err(RekorError::InvalidProof(_))));
    }

    #[test]
    fn test_verifier_with_public_key() {
        let verifier = RekorVerifier::with_public_key(vec![1, 2, 3]);
        // Verifier should construct without error
        let entry = make_test_entry("abc");
        let result = verifier.verify_inclusion_proof(&entry);
        assert!(matches!(result, Err(RekorError::MissingProof)));
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = RekorVerification {
            inclusion_valid: true,
            hash_matches: true,
            timestamp: 1700000000,
            log_index: 42,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: RekorVerification = serde_json::from_str(&json).unwrap();
        assert!(deserialized.inclusion_valid);
        assert!(deserialized.hash_matches);
    }

    #[test]
    fn test_inclusion_proof_with_sibling() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("abc");

        // Compute leaf hash using canonical JSON
        let leaf = compute_leaf_hash(&entry.body);

        // Create a sibling hash (32 bytes)
        let sibling = hex::encode(Sha256::digest(b"sibling"));

        // Compute root: SHA-256(0x01 || leaf || sibling) since log_index=0 (even)
        let mut root_hasher = Sha256::new();
        root_hasher.update([0x01]);
        root_hasher.update(&leaf);
        root_hasher.update(hex::decode(&sibling).unwrap());
        let root = hex::encode(root_hasher.finalize());

        entry.inclusion_proof = Some(RekorInclusionProof {
            log_index: 0,
            root_hash: root,
            tree_size: 2,
            hashes: vec![sibling],
        });

        assert!(verifier.verify_inclusion_proof(&entry).unwrap());
    }

    #[test]
    fn test_empty_proof_rejected_for_large_tree() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("abc");

        // Empty proof with tree_size > 1 should be rejected (FIND-P23-K04)
        entry.inclusion_proof = Some(RekorInclusionProof {
            log_index: 0,
            root_hash: "abc".to_string(),
            tree_size: 100,
            hashes: vec![],
        });

        let result = verifier.verify_inclusion_proof(&entry);
        assert!(matches!(result, Err(RekorError::InvalidProof(_))));
    }

    #[test]
    fn test_log_index_exceeds_tree_size() {
        let verifier = RekorVerifier::new();
        let mut entry = make_test_entry("abc");

        entry.inclusion_proof = Some(RekorInclusionProof {
            log_index: 10,
            root_hash: "abc".to_string(),
            tree_size: 5,
            hashes: vec!["aa".repeat(32)],
        });

        let result = verifier.verify_inclusion_proof(&entry);
        assert!(matches!(result, Err(RekorError::InvalidProof(_))));
    }
}
