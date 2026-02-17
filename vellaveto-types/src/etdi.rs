//! ETDI (Enhanced Tool Definition Interface) types — cryptographic verification
//! of MCP tool definitions based on arxiv:2506.01333.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Signature algorithm for tool definitions (ETDI).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// Ed25519 signatures (recommended, default).
    #[default]
    Ed25519,
    /// ECDSA with P-256 curve.
    EcdsaP256,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureAlgorithm::Ed25519 => write!(f, "ed25519"),
            SignatureAlgorithm::EcdsaP256 => write!(f, "ecdsa_p256"),
        }
    }
}

/// A cryptographic signature on a tool definition.
///
/// Part of the ETDI (Enhanced Tool Definition Interface) system.
/// Tool providers sign their tool definitions, and Vellaveto verifies
/// these signatures before allowing tool registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSignature {
    /// Unique identifier for this signature.
    pub signature_id: String,
    /// Hex-encoded cryptographic signature.
    pub signature: String,
    /// Algorithm used to create the signature.
    pub algorithm: SignatureAlgorithm,
    /// Hex-encoded public key of the signer.
    pub public_key: String,
    /// Optional fingerprint of the public key (for key management).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<String>,
    /// ISO 8601 timestamp when the signature was created.
    pub signed_at: String,
    /// ISO 8601 timestamp when the signature expires (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// SPIFFE ID of the signer for workload identity (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_spiffe_id: Option<String>,
    /// Optional Rekor transparency log entry for tool provenance (Phase 23.4).
    /// Contains a serialized `RekorEntry` for offline inclusion proof verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekor_entry: Option<serde_json::Value>,
}

impl ToolSignature {
    /// Returns true if the signature has expired.
    ///
    /// SAFETY: Lexicographic comparison is correct for ISO 8601 timestamps
    /// in the canonical format `YYYY-MM-DDTHH:MM:SSZ` because:
    /// - All fields are fixed-width with zero-padding
    /// - Fields are ordered from most significant (year) to least (second)
    /// - The character ordering of digits matches numeric ordering
    ///
    /// This holds for any consistent ISO 8601 format (with or without 'Z',
    /// with or without fractional seconds) as long as both timestamps use
    /// the same format and timezone.
    pub fn is_expired(&self, now: &str) -> bool {
        // SECURITY (FIND-R49-004): Reject non-UTC timestamps as expired (fail-closed).
        if !now.ends_with('Z') {
            return true;
        }
        self.expires_at.as_ref().is_some_and(|exp| {
            if !exp.ends_with('Z') {
                return true;
            }
            now >= exp.as_str()
        })
    }
}

/// Verification result for a tool signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureVerification {
    /// Whether the cryptographic signature is valid.
    pub valid: bool,
    /// Whether the signer is in the trusted signers list.
    pub signer_trusted: bool,
    /// Whether the signature has expired.
    pub expired: bool,
    /// Human-readable message about the verification result.
    pub message: String,
}

impl SignatureVerification {
    /// Returns true if the signature passes all checks.
    pub fn is_fully_verified(&self) -> bool {
        self.valid && self.signer_trusted && !self.expired
    }
}

/// An attestation record in a tool's provenance chain.
///
/// Attestations form a chain of custody for tool definitions,
/// allowing verification that a tool has not been modified
/// since it was first registered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolAttestation {
    /// Unique identifier for this attestation.
    pub attestation_id: String,
    /// Type of attestation (e.g., "initial", "version_update", "security_audit").
    pub attestation_type: String,
    /// Entity that created this attestation.
    pub attester: String,
    /// ISO 8601 timestamp when the attestation was created.
    pub timestamp: String,
    /// SHA-256 hash of the tool definition at attestation time.
    pub tool_hash: String,
    /// ID of the previous attestation in the chain (None for first attestation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_attestation: Option<String>,
    /// Cryptographic signature on this attestation.
    pub signature: ToolSignature,
    /// Optional reference to a transparency log entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_log_entry: Option<String>,
}

impl ToolAttestation {
    /// Returns true if this is the first attestation in the chain.
    pub fn is_initial(&self) -> bool {
        self.previous_attestation.is_none()
    }
}

/// Version pinning record for a tool.
///
/// Pins allow administrators to lock tools to specific versions
/// or version constraints, preventing unauthorized updates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolVersionPin {
    /// Name of the tool being pinned.
    pub tool_name: String,
    /// Exact version to pin to (e.g., "1.2.3").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_version: Option<String>,
    /// Semver constraint (e.g., "^1.2.0", ">=1.0,<2.0").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_constraint: Option<String>,
    /// SHA-256 hash of the pinned tool definition.
    pub definition_hash: String,
    /// ISO 8601 timestamp when the pin was created.
    pub pinned_at: String,
    /// Identity of who created this pin.
    pub pinned_by: String,
}

impl ToolVersionPin {
    /// Returns true if the pin uses an exact version match.
    pub fn is_exact(&self) -> bool {
        self.pinned_version.is_some()
    }

    /// Returns true if the pin uses a constraint.
    pub fn is_constraint(&self) -> bool {
        self.version_constraint.is_some()
    }
}

/// Result of version drift detection.
///
/// Generated when a tool's version or definition changes
/// from the pinned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionDriftAlert {
    /// Name of the tool with drift.
    pub tool: String,
    /// Expected version or hash from the pin.
    pub expected_version: String,
    /// Actual version or hash observed.
    pub actual_version: String,
    /// Type of drift detected (e.g., "version_mismatch", "hash_mismatch").
    pub drift_type: String,
    /// Whether this drift should block the tool from being used.
    pub blocking: bool,
    /// ISO 8601 timestamp when the drift was detected.
    pub detected_at: String,
}

impl VersionDriftAlert {
    /// Create a version mismatch alert.
    pub fn version_mismatch(
        tool: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
        blocking: bool,
        detected_at: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            expected_version: expected.into(),
            actual_version: actual.into(),
            drift_type: "version_mismatch".to_string(),
            blocking,
            detected_at: detected_at.into(),
        }
    }

    /// Create a hash mismatch alert.
    pub fn hash_mismatch(
        tool: impl Into<String>,
        expected_hash: impl Into<String>,
        actual_hash: impl Into<String>,
        blocking: bool,
        detected_at: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            expected_version: expected_hash.into(),
            actual_version: actual_hash.into(),
            drift_type: "hash_mismatch".to_string(),
            blocking,
            detected_at: detected_at.into(),
        }
    }
}
