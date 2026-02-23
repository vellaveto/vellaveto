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
    if b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
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
#[serde(deny_unknown_fields)]
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
            .field(
                "rekor_entry",
                &self.rekor_entry.as_ref().map(|_| "[PRESENT]"),
            )
            .finish()
    }
}

impl ToolSignature {
    /// Maximum serialized size of `rekor_entry` in bytes.
    pub const MAX_REKOR_ENTRY_SIZE: usize = 65_536;

    /// Maximum length for `signature_id` (bytes).
    const MAX_SIGNATURE_ID_LEN: usize = 256;
    /// Maximum length for `signature` hex string (bytes).
    const MAX_SIGNATURE_LEN: usize = 512;
    /// Maximum length for `public_key` hex string (bytes).
    const MAX_PUBLIC_KEY_LEN: usize = 512;
    /// Maximum length for ISO 8601 timestamp fields (`signed_at`, `expires_at`).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `key_fingerprint` (bytes).
    const MAX_KEY_FINGERPRINT_LEN: usize = 256;
    /// Maximum length for `signer_spiffe_id` URI (bytes).
    const MAX_SPIFFE_ID_LEN: usize = 2048;

    /// Validate structural bounds on all string fields.
    ///
    /// SECURITY (FIND-R52-002): Prevents memory exhaustion from oversized
    /// signature payloads deserialized from untrusted input.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R52-002): Validate all string field lengths.
        if self.signature_id.len() > Self::MAX_SIGNATURE_ID_LEN {
            return Err(format!(
                "ToolSignature signature_id length {} exceeds max {}",
                self.signature_id.len(),
                Self::MAX_SIGNATURE_ID_LEN,
            ));
        }
        if self.signature.len() > Self::MAX_SIGNATURE_LEN {
            return Err(format!(
                "ToolSignature signature length {} exceeds max {}",
                self.signature.len(),
                Self::MAX_SIGNATURE_LEN,
            ));
        }
        if self.public_key.len() > Self::MAX_PUBLIC_KEY_LEN {
            return Err(format!(
                "ToolSignature public_key length {} exceeds max {}",
                self.public_key.len(),
                Self::MAX_PUBLIC_KEY_LEN,
            ));
        }
        if self.signed_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "ToolSignature signed_at length {} exceeds max {}",
                self.signed_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if let Some(ref ea) = self.expires_at {
            if ea.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "ToolSignature expires_at length {} exceeds max {}",
                    ea.len(),
                    Self::MAX_TIMESTAMP_LEN,
                ));
            }
        }
        if let Some(ref kf) = self.key_fingerprint {
            if kf.len() > Self::MAX_KEY_FINGERPRINT_LEN {
                return Err(format!(
                    "ToolSignature key_fingerprint length {} exceeds max {}",
                    kf.len(),
                    Self::MAX_KEY_FINGERPRINT_LEN,
                ));
            }
        }
        if let Some(ref spiffe) = self.signer_spiffe_id {
            if spiffe.len() > Self::MAX_SPIFFE_ID_LEN {
                return Err(format!(
                    "ToolSignature signer_spiffe_id length {} exceeds max {}",
                    spiffe.len(),
                    Self::MAX_SPIFFE_ID_LEN,
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
        // SECURITY (FIND-R141-003): Validate control and Unicode format characters
        // in all string fields. Without this, a signature_id containing newlines could
        // cause log injection, and a signer_spiffe_id with zero-width chars could bypass
        // SPIFFE-based identity matching. This matches the pattern in ToolVersionPin::validate().
        for (name, value) in [
            ("signature_id", Some(&self.signature_id)),
            ("signed_at", Some(&self.signed_at)),
        ] {
            if let Some(v) = value {
                if v.chars()
                    .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
                {
                    return Err(format!(
                        "ToolSignature {} contains control or format characters",
                        name
                    ));
                }
            }
        }
        for (name, value) in [
            ("expires_at", self.expires_at.as_ref()),
            ("key_fingerprint", self.key_fingerprint.as_ref()),
            ("signer_spiffe_id", self.signer_spiffe_id.as_ref()),
        ] {
            if let Some(v) = value {
                if v.chars()
                    .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
                {
                    return Err(format!(
                        "ToolSignature {} contains control or format characters",
                        name
                    ));
                }
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
#[serde(deny_unknown_fields)]
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
    /// Maximum length for `message` field (bytes).
    const MAX_MESSAGE_LEN: usize = 4096;

    /// Returns true if the signature passes all checks.
    pub fn is_fully_verified(&self) -> bool {
        self.valid && self.signer_trusted && !self.expired
    }

    /// Validate structural bounds on string fields.
    ///
    /// SECURITY (FIND-R146-TE-002): Prevents memory exhaustion from oversized
    /// message fields and control/format character injection from untrusted payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.message.len() > Self::MAX_MESSAGE_LEN {
            return Err(format!(
                "SignatureVerification message length {} exceeds max {}",
                self.message.len(),
                Self::MAX_MESSAGE_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.message) {
            return Err(
                "SignatureVerification message contains control or format characters".to_string(),
            );
        }
        Ok(())
    }
}

/// An attestation record in a tool's provenance chain.
///
/// Attestations form a chain of custody for tool definitions,
/// allowing verification that a tool has not been modified
/// since it was first registered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

    /// Maximum length for `attestation_id`.
    const MAX_ATTESTATION_ID_LEN: usize = 256;
    /// Maximum length for `attestation_type`.
    const MAX_ATTESTATION_TYPE_LEN: usize = 128;
    /// Maximum length for `attester`.
    const MAX_ATTESTER_LEN: usize = 512;
    /// Maximum length for ISO 8601 timestamp fields.
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `tool_hash` (hex-encoded SHA-256 = 64 chars).
    const MAX_TOOL_HASH_LEN: usize = 256;
    /// Maximum length for `previous_attestation` ID.
    const MAX_PREV_ATTESTATION_LEN: usize = 256;
    /// Maximum length for `transparency_log_entry` reference.
    const MAX_LOG_ENTRY_LEN: usize = 2048;

    /// Validate structural bounds on string fields and the nested signature.
    ///
    /// SECURITY: Prevents memory exhaustion from oversized attestation payloads
    /// deserialized from untrusted input. Delegates to [`ToolSignature::validate()`]
    /// for the inner signature.
    pub fn validate(&self) -> Result<(), String> {
        if self.attestation_id.len() > Self::MAX_ATTESTATION_ID_LEN {
            return Err(format!(
                "ToolAttestation attestation_id length {} exceeds max {}",
                self.attestation_id.len(),
                Self::MAX_ATTESTATION_ID_LEN,
            ));
        }
        if self.attestation_type.len() > Self::MAX_ATTESTATION_TYPE_LEN {
            return Err(format!(
                "ToolAttestation attestation_type length {} exceeds max {}",
                self.attestation_type.len(),
                Self::MAX_ATTESTATION_TYPE_LEN,
            ));
        }
        if self.attester.len() > Self::MAX_ATTESTER_LEN {
            return Err(format!(
                "ToolAttestation attester length {} exceeds max {}",
                self.attester.len(),
                Self::MAX_ATTESTER_LEN,
            ));
        }
        if self.timestamp.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "ToolAttestation timestamp length {} exceeds max {}",
                self.timestamp.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if self.tool_hash.len() > Self::MAX_TOOL_HASH_LEN {
            return Err(format!(
                "ToolAttestation tool_hash length {} exceeds max {}",
                self.tool_hash.len(),
                Self::MAX_TOOL_HASH_LEN,
            ));
        }
        if let Some(ref prev) = self.previous_attestation {
            if prev.len() > Self::MAX_PREV_ATTESTATION_LEN {
                return Err(format!(
                    "ToolAttestation previous_attestation length {} exceeds max {}",
                    prev.len(),
                    Self::MAX_PREV_ATTESTATION_LEN,
                ));
            }
        }
        if let Some(ref entry) = self.transparency_log_entry {
            if entry.len() > Self::MAX_LOG_ENTRY_LEN {
                return Err(format!(
                    "ToolAttestation transparency_log_entry length {} exceeds max {}",
                    entry.len(),
                    Self::MAX_LOG_ENTRY_LEN,
                ));
            }
        }
        // SECURITY (FIND-R141-004): Validate control and Unicode format characters
        // in all string fields. Without this, an attestation_id or attester with
        // newlines could cause log injection, and a tool_hash with zero-width chars
        // could cause integrity check inconsistencies. Matches ToolVersionPin::validate() pattern.
        for (name, value) in [
            ("attestation_id", &self.attestation_id as &str),
            ("attestation_type", &self.attestation_type),
            ("attester", &self.attester),
            ("timestamp", &self.timestamp),
            ("tool_hash", &self.tool_hash),
        ] {
            if value
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(format!(
                    "ToolAttestation {} contains control or format characters",
                    name
                ));
            }
        }
        for (name, value) in [
            ("previous_attestation", self.previous_attestation.as_ref()),
            (
                "transparency_log_entry",
                self.transparency_log_entry.as_ref(),
            ),
        ] {
            if let Some(v) = value {
                if v.chars()
                    .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
                {
                    return Err(format!(
                        "ToolAttestation {} contains control or format characters",
                        name
                    ));
                }
            }
        }
        self.signature.validate()?;
        Ok(())
    }

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
#[serde(deny_unknown_fields)]
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
    /// Maximum length for `tool_name` (bytes).
    const MAX_TOOL_NAME_LEN: usize = 256;
    /// Maximum length for `pinned_version` (bytes).
    const MAX_VERSION_LEN: usize = 128;
    /// Maximum length for `version_constraint` (bytes).
    const MAX_CONSTRAINT_LEN: usize = 256;
    /// Maximum length for `definition_hash` (bytes).
    const MAX_HASH_LEN: usize = 256;
    /// Maximum length for ISO 8601 timestamp fields (bytes).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `pinned_by` (bytes).
    const MAX_PINNED_BY_LEN: usize = 256;

    /// Returns true if the pin uses an exact version match.
    pub fn is_exact(&self) -> bool {
        self.pinned_version.is_some()
    }

    /// Returns true if the pin uses a constraint.
    pub fn is_constraint(&self) -> bool {
        self.version_constraint.is_some()
    }

    /// Validate structural bounds on fields.
    ///
    /// SECURITY (FIND-R53-P3-008): Prevents memory exhaustion and control character
    /// injection from untrusted `ToolVersionPin` payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.tool_name.is_empty() {
            return Err("ToolVersionPin tool_name must not be empty".to_string());
        }
        if self.tool_name.len() > Self::MAX_TOOL_NAME_LEN {
            return Err(format!(
                "ToolVersionPin tool_name length {} exceeds max {}",
                self.tool_name.len(),
                Self::MAX_TOOL_NAME_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.tool_name)
        {
            return Err(
                "ToolVersionPin tool_name contains control or format characters".to_string(),
            );
        }
        if let Some(ref ver) = self.pinned_version {
            if ver.len() > Self::MAX_VERSION_LEN {
                return Err(format!(
                    "ToolVersionPin pinned_version length {} exceeds max {}",
                    ver.len(),
                    Self::MAX_VERSION_LEN,
                ));
            }
            // SECURITY: Reject control/format chars in pinned_version to prevent
            // version comparison bypass via zero-width characters.
            if crate::core::has_dangerous_chars(ver) {
                return Err(
                    "ToolVersionPin pinned_version contains control or format characters"
                        .to_string(),
                );
            }
        }
        if let Some(ref constraint) = self.version_constraint {
            if constraint.len() > Self::MAX_CONSTRAINT_LEN {
                return Err(format!(
                    "ToolVersionPin version_constraint length {} exceeds max {}",
                    constraint.len(),
                    Self::MAX_CONSTRAINT_LEN,
                ));
            }
            // SECURITY: Reject control/format chars in version_constraint to prevent
            // constraint parsing bypass via invisible characters.
            if crate::core::has_dangerous_chars(constraint) {
                return Err(
                    "ToolVersionPin version_constraint contains control or format characters"
                        .to_string(),
                );
            }
        }
        if self.definition_hash.len() > Self::MAX_HASH_LEN {
            return Err(format!(
                "ToolVersionPin definition_hash length {} exceeds max {}",
                self.definition_hash.len(),
                Self::MAX_HASH_LEN,
            ));
        }
        // SECURITY: Reject control/format chars in definition_hash to prevent
        // integrity check inconsistencies via zero-width characters in hash comparison.
        if crate::core::has_dangerous_chars(&self.definition_hash) {
            return Err(
                "ToolVersionPin definition_hash contains control or format characters".to_string(),
            );
        }
        if self.pinned_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "ToolVersionPin pinned_at length {} exceeds max {}",
                self.pinned_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        // SECURITY: Reject control/format chars in pinned_at to prevent
        // log injection and timestamp comparison bypass.
        if crate::core::has_dangerous_chars(&self.pinned_at) {
            return Err(
                "ToolVersionPin pinned_at contains control or format characters".to_string(),
            );
        }
        if self.pinned_by.is_empty() {
            return Err("ToolVersionPin pinned_by must not be empty".to_string());
        }
        if self.pinned_by.len() > Self::MAX_PINNED_BY_LEN {
            return Err(format!(
                "ToolVersionPin pinned_by length {} exceeds max {}",
                self.pinned_by.len(),
                Self::MAX_PINNED_BY_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.pinned_by)
        {
            return Err(
                "ToolVersionPin pinned_by contains control or format characters".to_string(),
            );
        }
        Ok(())
    }
}

/// Result of version drift detection.
///
/// Generated when a tool's version or definition changes
/// from the pinned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VersionDriftAlert {
    /// Name of the tool with drift.
    pub tool: String,
    /// Expected version string or definition hash from the pin.
    ///
    /// When `drift_type` is `"version_mismatch"`, this holds the pinned semver
    /// version (e.g., `"1.2.3"`). When `drift_type` is `"hash_mismatch"`, this
    /// holds the pinned SHA-256 definition hash.
    pub expected_version: String,
    /// Actual version string or definition hash observed at evaluation time.
    ///
    /// Interpretation depends on `drift_type` — see [`Self::expected_version`].
    pub actual_version: String,
    /// Type of drift detected: `"version_mismatch"` (semver changed) or
    /// `"hash_mismatch"` (definition content changed while version stayed the same).
    pub drift_type: String,
    /// Whether this drift should block the tool from being used.
    pub blocking: bool,
    /// ISO 8601 timestamp when the drift was detected.
    pub detected_at: String,
}

impl VersionDriftAlert {
    /// Maximum length for string fields (`tool`, `expected_version`,
    /// `actual_version`, `drift_type`, `detected_at`).
    const MAX_FIELD_LEN: usize = 512;

    /// Validate structural bounds on all string fields.
    ///
    /// SECURITY (FIND-R146-TE-001): Prevents memory exhaustion from oversized
    /// fields and control/format character injection from untrusted payloads.
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("tool", &self.tool),
            ("expected_version", &self.expected_version),
            ("actual_version", &self.actual_version),
            ("drift_type", &self.drift_type),
            ("detected_at", &self.detected_at),
        ] {
            if value.is_empty() {
                return Err(format!("VersionDriftAlert {} must not be empty", name));
            }
            if value.len() > Self::MAX_FIELD_LEN {
                return Err(format!(
                    "VersionDriftAlert {} length {} exceeds max {}",
                    name,
                    value.len(),
                    Self::MAX_FIELD_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(value) {
                return Err(format!(
                    "VersionDriftAlert {} contains control or format characters",
                    name
                ));
            }
        }
        Ok(())
    }

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
