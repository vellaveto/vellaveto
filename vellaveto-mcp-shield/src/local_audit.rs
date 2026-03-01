// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Encrypted local audit manager combining AuditLogger with EncryptedAuditStore.

use crate::crypto::EncryptedAuditStore;
use crate::error::ShieldError;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use vellaveto_audit::{AuditLogger, MerkleTree};

/// Local audit manager that writes encrypted, hash-chained audit entries.
pub struct LocalAuditManager {
    audit_logger: AuditLogger,
    store: EncryptedAuditStore,
    merkle: Option<MerkleTree>,
    /// Optional Pedersen committer for zero-knowledge commitments.
    #[cfg(feature = "zk-audit")]
    zk_committer: Option<vellaveto_audit::zk::pedersen::PedersenCommitter>,
}

impl LocalAuditManager {
    /// Create a new local audit manager.
    pub fn new(audit_path: PathBuf, store: EncryptedAuditStore) -> Self {
        Self {
            audit_logger: AuditLogger::new(audit_path),
            store,
            merkle: None,
            #[cfg(feature = "zk-audit")]
            zk_committer: None,
        }
    }

    /// Enable Merkle tree proofs. Uses a sibling file for leaf storage.
    pub fn with_merkle(mut self) -> Self {
        let merkle_path = self.store.path().with_extension("merkle");
        self.merkle = Some(MerkleTree::new(merkle_path));
        self
    }

    /// Enable zero-knowledge Pedersen commitments for audit entries.
    ///
    /// When enabled, each logged event produces a Pedersen commitment
    /// that hides the entry content while binding to it cryptographically.
    /// Commitment generation is advisory: failures are logged but don't
    /// block the audit entry.
    #[cfg(feature = "zk-audit")]
    pub fn with_zk_commitments(mut self) -> Self {
        self.zk_committer = Some(vellaveto_audit::zk::pedersen::PedersenCommitter::new());
        self
    }

    /// Log a shield event: hash-chain -> Merkle append -> encrypt -> write.
    pub async fn log_shield_event(
        &mut self,
        event_type: &str,
        details: &str,
    ) -> Result<(), ShieldError> {
        // Create audit entry JSON
        let entry = serde_json::json!({
            "type": "shield_event",
            "event": event_type,
            "details": details,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        let entry_bytes = serde_json::to_vec(&entry)
            .map_err(|e| ShieldError::Audit(format!("serialize: {e}")))?;

        // Compute entry hash (used by both Merkle and ZK)
        let mut hasher = Sha256::new();
        hasher.update(&entry_bytes);
        let hash: [u8; 32] = hasher.finalize().into();

        // Append to Merkle tree if enabled
        if let Some(ref mut merkle) = self.merkle {
            merkle
                .append(hash)
                .map_err(|e| ShieldError::Audit(format!("merkle append: {e}")))?;
        }

        // Generate ZK commitment if enabled (advisory — warn on failure, don't block)
        #[cfg(feature = "zk-audit")]
        if let Some(ref committer) = self.zk_committer {
            match committer.commit(&hash) {
                Ok((_commitment, _blinding)) => {
                    tracing::trace!("ZK commitment generated for shield event");
                }
                Err(e) => {
                    tracing::warn!("ZK commitment generation failed (advisory): {}", e);
                }
            }
        }

        // Encrypt and write
        self.store.write_encrypted_entry(&entry_bytes)?;

        Ok(())
    }

    /// Read and decrypt all audit entries.
    pub fn read_entries(&self) -> Result<Vec<serde_json::Value>, ShieldError> {
        let raw_entries = self.store.read_all_entries()?;
        let mut entries = Vec::with_capacity(raw_entries.len());
        for raw in raw_entries {
            let value: serde_json::Value = serde_json::from_slice(&raw)
                .map_err(|e| ShieldError::Audit(format!("deserialize: {e}")))?;
            entries.push(value);
        }
        Ok(entries)
    }

    /// Generate a Merkle inclusion proof for entry at the given index.
    pub fn generate_proof(&self, index: u64) -> Result<vellaveto_audit::MerkleProof, ShieldError> {
        let merkle = self
            .merkle
            .as_ref()
            .ok_or_else(|| ShieldError::Audit("Merkle tree not enabled".to_string()))?;
        merkle
            .generate_proof(index)
            .map_err(|e| ShieldError::Audit(format!("proof generation: {e}")))
    }

    /// Get the Merkle root hash as hex string.
    pub fn merkle_root(&self) -> Option<String> {
        self.merkle.as_ref().and_then(|m| m.root_hex())
    }

    /// Get the underlying audit logger.
    pub fn audit_logger(&self) -> &AuditLogger {
        &self.audit_logger
    }
}

impl std::fmt::Debug for LocalAuditManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAuditManager")
            .field("store", &self.store)
            .field("merkle_enabled", &self.merkle.is_some())
            .finish()
    }
}
