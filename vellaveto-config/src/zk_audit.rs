//! Zero-Knowledge Audit Trail configuration (Phase 37).
//!
//! Controls Pedersen commitments (inline, ~50µs per entry) and optional
//! Groth16 batch proofs (offline, async). Feature-gated behind `zk-audit`.

use serde::{Deserialize, Serialize};

/// Maximum batch size for ZK batch proofs.
pub const MAX_ZK_BATCH_SIZE: usize = 10_000;

/// Minimum batch size for ZK batch proofs.
pub const MIN_ZK_BATCH_SIZE: usize = 10;

/// Maximum batch interval in seconds (24 hours).
pub const MAX_ZK_BATCH_INTERVAL_SECS: u64 = 86_400;

/// Zero-Knowledge Audit Trail configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ZkAuditConfig {
    /// Enable the ZK audit trail.
    /// Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Enable Pedersen commitments on each audit entry.
    /// Default: true (when `enabled` is true).
    #[serde(default = "crate::default_true")]
    pub pedersen_commitments: bool,

    /// Enable periodic Groth16 batch proofs.
    /// Default: false.
    #[serde(default)]
    pub batch_proof_enabled: bool,

    /// Number of entries per batch proof.
    /// Default: 100. Range: [10, 10_000].
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Interval in seconds between batch proofs.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_batch_interval_secs")]
    pub batch_interval_secs: u64,

    /// Path to the serialized proving key file.
    /// Required when `batch_proof_enabled` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proving_key_path: Option<String>,

    /// Path to the serialized verifying key file.
    /// Required when `batch_proof_enabled` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_key_path: Option<String>,
}

fn default_batch_size() -> usize {
    100
}

fn default_batch_interval_secs() -> u64 {
    300
}

impl Default for ZkAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pedersen_commitments: true,
            batch_proof_enabled: false,
            batch_size: default_batch_size(),
            batch_interval_secs: default_batch_interval_secs(),
            proving_key_path: None,
            verifying_key_path: None,
        }
    }
}

impl ZkAuditConfig {
    /// Validate ZK audit configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.batch_size < MIN_ZK_BATCH_SIZE {
            return Err(format!(
                "zk_audit.batch_size must be >= {}, got {}",
                MIN_ZK_BATCH_SIZE, self.batch_size
            ));
        }
        if self.batch_size > MAX_ZK_BATCH_SIZE {
            return Err(format!(
                "zk_audit.batch_size must be <= {}, got {}",
                MAX_ZK_BATCH_SIZE, self.batch_size
            ));
        }

        if self.batch_interval_secs == 0 {
            return Err("zk_audit.batch_interval_secs must be > 0".to_string());
        }
        if self.batch_interval_secs > MAX_ZK_BATCH_INTERVAL_SECS {
            return Err(format!(
                "zk_audit.batch_interval_secs must be <= {} (24 hours), got {}",
                MAX_ZK_BATCH_INTERVAL_SECS, self.batch_interval_secs
            ));
        }

        // Validate key paths don't contain path traversal
        if let Some(ref pk_path) = self.proving_key_path {
            validate_key_path("zk_audit.proving_key_path", pk_path)?;
        }
        if let Some(ref vk_path) = self.verifying_key_path {
            validate_key_path("zk_audit.verifying_key_path", vk_path)?;
        }

        Ok(())
    }
}

/// Validate a key file path does not contain path traversal.
fn validate_key_path(field: &str, path: &str) -> Result<(), String> {
    use std::path::{Component, Path};
    let p = Path::new(path);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "{} must not contain '..' components, got '{}'",
            field, path
        ));
    }
    Ok(())
}
