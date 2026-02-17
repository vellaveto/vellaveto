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

/// SECURITY (FIND-R51-002): Validate that a string is a well-formed ISO 8601
/// basic timestamp in the format `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Checks structure, character classes, and value ranges for all components.
/// Returns `false` for any malformed input, which callers use for fail-closed
/// behavior (treating malformed timestamps as expired).
fn is_valid_iso8601_basic(s: &str) -> bool {
    // Must be exactly 20 bytes: "YYYY-MM-DDTHH:MM:SSZ"
    if s.len() != 20 {
        return false;
    }
    let b = s.as_bytes();

    // Structural checks: separators at fixed positions
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return false;
    }

    // All digit positions must be ASCII digits
    let digit_positions = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    for &pos in &digit_positions {
        if !b[pos].is_ascii_digit() {
            return false;
        }
    }

    // Parse and validate numeric ranges
    // Safe: we verified all positions are ASCII digits above, so from_utf8 and parse cannot fail.
    let year: u16 = s[0..4].parse().unwrap_or(0);
    let month: u8 = s[5..7].parse().unwrap_or(0);
    let day: u8 = s[8..10].parse().unwrap_or(0);
    let hour: u8 = s[11..13].parse().unwrap_or(0);
    let minute: u8 = s[14..16].parse().unwrap_or(0);
    let second: u8 = s[17..19].parse().unwrap_or(0);

    if year < 1970 {
        return false;
    }
    if !(1..=12).contains(&month) {
        return false;
    }
    if !(1..=31).contains(&day) {
        return false;
    }
    if hour > 23 {
        return false;
    }
    if minute > 59 {
        return false;
    }
    if second > 59 {
        return false;
    }

    true
}

/// A cryptographic signature on a tool definition.
///
/// Part of the ETDI (Enhanced Tool Definition Interface) system.
/// Tool providers sign their tool definitions, and Vellaveto verifies
/// these signatures before allowing tool registration.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
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

// SECURITY (FIND-R52-016): Custom Debug to redact signature and public_key.
impl std::fmt::Debug for ToolSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolSignature")
            .field("signature_id", &self.signature_id)
            .field("signature", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("public_key", &"[REDACTED]")
            .field("key_fingerprint", &self.key_fingerprint)
            .field("signed_at", &self.signed_at)
            .field("expires_at", &self.expires_at)
            .field("signer_spiffe_id", &self.signer_spiffe_id)
            .field("rekor_entry", &self.rekor_entry.as_ref().map(|_| "[PRESENT]"))
            .finish()
    }
}

impl ToolSignature {
    /// Maximum serialized size of `rekor_entry` in bytes.
    pub const MAX_REKOR_ENTRY_SIZE: usize = 65_536;

    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R52-002): Validate all string field lengths.
        if self.signature_id.len() > 256 {
            return Err(format!(
                "ToolSignature signature_id length {} exceeds max 256",
                self.signature_id.len()
            ));
        }
        if self.signature.len() > 512 {
            return Err(format!(
                "ToolSignature signature length {} exceeds max 512",
                self.signature.len()
            ));
        }
        if self.public_key.len() > 512 {
            return Err(format!(
                "ToolSignature public_key length {} exceeds max 512",
                self.public_key.len()
            ));
        }
        if self.signed_at.len() > 64 {
            return Err(format!(
                "ToolSignature signed_at length {} exceeds max 64",
                self.signed_at.len()
            ));
        }
        if let Some(ref ea) = self.expires_at {
            if ea.len() > 64 {
                return Err(format!(
                    "ToolSignature expires_at length {} exceeds max 64",
                    ea.len()
                ));
            }
        }
        if let Some(ref kf) = self.key_fingerprint {
            if kf.len() > 256 {
                return Err(format!(
                    "ToolSignature key_fingerprint length {} exceeds max 256",
                    kf.len()
                ));
            }
        }
        if let Some(ref spiffe) = self.signer_spiffe_id {
            if spiffe.len() > 2048 {
                return Err(format!(
                    "ToolSignature signer_spiffe_id length {} exceeds max 2048",
                    spiffe.len()
                ));
            }
        }
        if let Some(ref entry) = self.rekor_entry {
            let size = serde_json::to_string(entry)
                .map_err(|e| format!("rekor_entry serialization failed: {e}"))?
                .len();
            if size > Self::MAX_REKOR_ENTRY_SIZE {
                return Err(format!(
                    "rekor_entry serialized size {} exceeds max {}",
                    size,
                    Self::MAX_REKOR_ENTRY_SIZE
                ));
            }
        }
        Ok(())
    }

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
        // SECURITY (FIND-R51-002): Reject malformed `now` timestamps as expired (fail-closed).
        if !is_valid_iso8601_basic(now) {
            return true;
        }
        self.expires_at.as_ref().is_some_and(|exp| {
            if !exp.ends_with('Z') {
                return true;
            }
            // SECURITY (FIND-R51-002): Reject malformed `expires_at` as expired (fail-closed).
            if !is_valid_iso8601_basic(exp) {
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
    /// Maximum attestation chain depth to prevent DoS during chain traversal.
    pub const MAX_ATTESTATION_CHAIN_DEPTH: usize = 64;

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
