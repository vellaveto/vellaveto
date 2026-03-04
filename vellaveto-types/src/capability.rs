// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Capability-based delegation token types.
//!
//! Capability tokens enable fine-grained, attenuatable delegation of tool
//! access between agents. Each token grants specific permissions (tools,
//! paths, domains) and can be delegated with monotonically decreasing
//! privileges (depth decrements, grants narrow, expiry clamps).
//!
//! # Security Properties
//!
//! - **Monotonic attenuation:** delegated tokens can only narrow permissions
//! - **Bounded delegation depth:** prevents infinite delegation chains
//! - **Fail-closed:** missing or invalid tokens produce `Deny`
//! - **Ed25519 signed:** prevents token forgery

use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum number of grants per token.
pub const MAX_GRANTS: usize = 64;
/// Maximum delegation depth (0 = terminal, cannot delegate further).
pub const MAX_DELEGATION_DEPTH: u8 = 16;
/// Maximum serialized token size in bytes.
pub const MAX_TOKEN_SIZE: usize = 65536;

/// A capability-based delegation token granting specific tool permissions.
///
/// Tokens form a delegation chain: each token can optionally reference a
/// parent token, and its grants must be a subset of the parent's grants.
/// The `remaining_depth` decrements with each delegation, preventing
/// unbounded chains.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityToken {
    /// Unique token identifier (UUID v4).
    pub token_id: String,
    /// Parent token ID if this was delegated (None for root tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_token_id: Option<String>,
    /// Identity of the token issuer (who signed it).
    pub issuer: String,
    /// Identity of the token holder (who can use it).
    pub holder: String,
    /// Permissions granted by this token.
    pub grants: Vec<CapabilityGrant>,
    /// Remaining delegation depth (0 = terminal, cannot delegate further).
    pub remaining_depth: u8,
    /// ISO 8601 timestamp when the token was issued.
    pub issued_at: String,
    /// ISO 8601 timestamp when the token expires.
    pub expires_at: String,
    /// Ed25519 signature over the canonical token content (hex-encoded).
    pub signature: String,
    /// Ed25519 public key of the issuer (hex-encoded).
    pub issuer_public_key: String,
}

impl fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapabilityToken")
            .field("token_id", &self.token_id)
            .field("parent_token_id", &self.parent_token_id)
            .field("issuer", &self.issuer)
            .field("holder", &self.holder)
            .field("grants", &self.grants)
            .field("remaining_depth", &self.remaining_depth)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("signature", &"[REDACTED]")
            // SECURITY (FIND-R216-001): Redact issuer_public_key — cryptographic
            // material must not leak into logs or debug output.
            .field("issuer_public_key", &"[REDACTED]")
            .finish()
    }
}

/// A single permission grant within a capability token.
///
/// Each grant specifies which tools/functions the holder can invoke,
/// optionally restricted to specific paths and domains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    /// Tool name pattern (exact or glob, e.g., "file_system" or "db_*").
    pub tool_pattern: String,
    /// Function name pattern (exact or glob, e.g., "read_file" or "*").
    pub function_pattern: String,
    /// Allowed path globs (empty = no path restriction).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_paths: Vec<String>,
    /// Allowed domain patterns (empty = no domain restriction).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// Maximum number of invocations (0 = unlimited).
    #[serde(default)]
    pub max_invocations: u64,
}

impl CapabilityGrant {
    /// Maximum entries in `allowed_paths` or `allowed_domains`.
    pub const MAX_ENTRIES: usize = 1000;
    /// Maximum byte length per path or domain entry.
    pub const MAX_ENTRY_LEN: usize = 2048;
    /// SECURITY (FIND-R174-005): Maximum byte length for pattern fields.
    pub const MAX_PATTERN_LEN: usize = 1024;

    pub fn validate(&self) -> Result<(), CapabilityError> {
        // SECURITY (FIND-R174-005): Validate pattern field lengths.
        if self.tool_pattern.len() > Self::MAX_PATTERN_LEN {
            return Err(CapabilityError::ValidationFailed(format!(
                "CapabilityGrant tool_pattern length {} exceeds maximum {}",
                self.tool_pattern.len(),
                Self::MAX_PATTERN_LEN
            )));
        }
        if self.function_pattern.len() > Self::MAX_PATTERN_LEN {
            return Err(CapabilityError::ValidationFailed(format!(
                "CapabilityGrant function_pattern length {} exceeds maximum {}",
                self.function_pattern.len(),
                Self::MAX_PATTERN_LEN
            )));
        }
        // SECURITY (FIND-R113-007): Validate control/format chars on pattern fields.
        if crate::core::has_dangerous_chars(&self.tool_pattern) {
            return Err(CapabilityError::ValidationFailed(
                "CapabilityGrant tool_pattern contains control or format characters".to_string(),
            ));
        }
        if crate::core::has_dangerous_chars(&self.function_pattern) {
            return Err(CapabilityError::ValidationFailed(
                "CapabilityGrant function_pattern contains control or format characters"
                    .to_string(),
            ));
        }
        if self.allowed_paths.len() > Self::MAX_ENTRIES {
            return Err(CapabilityError::ValidationFailed(format!(
                "allowed_paths count {} exceeds max {}",
                self.allowed_paths.len(),
                Self::MAX_ENTRIES
            )));
        }
        if self.allowed_domains.len() > Self::MAX_ENTRIES {
            return Err(CapabilityError::ValidationFailed(format!(
                "allowed_domains count {} exceeds max {}",
                self.allowed_domains.len(),
                Self::MAX_ENTRIES
            )));
        }
        for (i, p) in self.allowed_paths.iter().enumerate() {
            if p.len() > Self::MAX_ENTRY_LEN {
                return Err(CapabilityError::ValidationFailed(format!(
                    "allowed_paths[{}] length {} exceeds max {}",
                    i,
                    p.len(),
                    Self::MAX_ENTRY_LEN
                )));
            }
            // SECURITY (FIND-R113-007): Validate control/format chars on path entries.
            if crate::core::has_dangerous_chars(p) {
                return Err(CapabilityError::ValidationFailed(format!(
                    "allowed_paths[{i}] contains control or format characters"
                )));
            }
        }
        for (i, d) in self.allowed_domains.iter().enumerate() {
            if d.len() > Self::MAX_ENTRY_LEN {
                return Err(CapabilityError::ValidationFailed(format!(
                    "allowed_domains[{}] length {} exceeds max {}",
                    i,
                    d.len(),
                    Self::MAX_ENTRY_LEN
                )));
            }
            // SECURITY (FIND-R113-007): Validate control/format chars on domain entries.
            if crate::core::has_dangerous_chars(d) {
                return Err(CapabilityError::ValidationFailed(format!(
                    "allowed_domains[{i}] contains control or format characters"
                )));
            }
        }
        Ok(())
    }
}

/// Result of verifying a capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityVerification {
    /// Whether the token is valid.
    pub valid: bool,
    /// Reason for failure, if any.
    pub failure_reason: Option<String>,
}

impl CapabilityVerification {
    /// Maximum length for `failure_reason` field.
    const MAX_FAILURE_REASON_LEN: usize = 4096;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R216-011): Prevents oversized or injection-prone failure
    /// reason strings from untrusted deserialized payloads.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if let Some(ref reason) = self.failure_reason {
            if reason.len() > Self::MAX_FAILURE_REASON_LEN {
                return Err(CapabilityError::ValidationFailed(format!(
                    "CapabilityVerification failure_reason length {} exceeds max {}",
                    reason.len(),
                    Self::MAX_FAILURE_REASON_LEN,
                )));
            }
            if crate::core::has_dangerous_chars(reason) {
                return Err(CapabilityError::ValidationFailed(
                    "CapabilityVerification failure_reason contains control or format characters"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Errors from capability token operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// The signing key is invalid.
    InvalidKey(String),
    /// Token signing failed.
    SigningFailed(String),
    /// Token verification failed.
    VerificationFailed(String),
    /// The token has expired.
    Expired,
    /// Attenuation violation (grants not a subset of parent).
    AttenuationViolation(String),
    /// Structural validation failed.
    ValidationFailed(String),
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityError::InvalidKey(msg) => write!(f, "Invalid key: {msg}"),
            CapabilityError::SigningFailed(msg) => write!(f, "Signing failed: {msg}"),
            CapabilityError::VerificationFailed(msg) => {
                write!(f, "Verification failed: {msg}")
            }
            CapabilityError::Expired => write!(f, "Token has expired"),
            CapabilityError::AttenuationViolation(msg) => {
                write!(f, "Attenuation violation: {msg}")
            }
            CapabilityError::ValidationFailed(msg) => {
                write!(f, "Validation failed: {msg}")
            }
        }
    }
}

impl std::error::Error for CapabilityError {}

impl CapabilityToken {
    /// Validate the structural integrity of the token.
    ///
    /// Checks bounds on grants, depth, field lengths, and serialized size.
    pub fn validate_structure(&self) -> Result<(), CapabilityError> {
        if self.token_id.is_empty() {
            return Err(CapabilityError::ValidationFailed(
                "token_id must not be empty".to_string(),
            ));
        }
        // SECURITY (FIND-R115-001): Reject control/format chars in identity fields
        // to prevent zero-width space or bidi override bypasses of string equality checks.
        if crate::core::has_dangerous_chars(&self.token_id) {
            return Err(CapabilityError::ValidationFailed(
                "token_id contains control or format characters".to_string(),
            ));
        }
        if self.issuer.is_empty() {
            return Err(CapabilityError::ValidationFailed(
                "issuer must not be empty".to_string(),
            ));
        }
        if crate::core::has_dangerous_chars(&self.issuer) {
            return Err(CapabilityError::ValidationFailed(
                "issuer contains control or format characters".to_string(),
            ));
        }
        if self.holder.is_empty() {
            return Err(CapabilityError::ValidationFailed(
                "holder must not be empty".to_string(),
            ));
        }
        if crate::core::has_dangerous_chars(&self.holder) {
            return Err(CapabilityError::ValidationFailed(
                "holder contains control or format characters".to_string(),
            ));
        }
        // SECURITY (FIND-R224-002): Validate parent_token_id when present — reject
        // empty strings and dangerous characters to prevent delegation chain confusion.
        if let Some(ref parent_id) = self.parent_token_id {
            if parent_id.is_empty() {
                return Err(CapabilityError::ValidationFailed(
                    "parent_token_id must not be empty when present".to_string(),
                ));
            }
            if crate::core::has_dangerous_chars(parent_id) {
                return Err(CapabilityError::ValidationFailed(
                    "parent_token_id contains control or format characters".to_string(),
                ));
            }
        }
        // SECURITY (FIND-R224-006): Validate signature and issuer_public_key for
        // dangerous characters. These hex-encoded cryptographic fields should never
        // contain control or Unicode format characters.
        if crate::core::has_dangerous_chars(&self.signature) {
            return Err(CapabilityError::ValidationFailed(
                "signature contains control or format characters".to_string(),
            ));
        }
        if crate::core::has_dangerous_chars(&self.issuer_public_key) {
            return Err(CapabilityError::ValidationFailed(
                "issuer_public_key contains control or format characters".to_string(),
            ));
        }
        if self.grants.is_empty() {
            return Err(CapabilityError::ValidationFailed(
                "grants must not be empty".to_string(),
            ));
        }
        if self.grants.len() > MAX_GRANTS {
            return Err(CapabilityError::ValidationFailed(format!(
                "too many grants: {} (max {})",
                self.grants.len(),
                MAX_GRANTS
            )));
        }
        if self.remaining_depth > MAX_DELEGATION_DEPTH {
            return Err(CapabilityError::ValidationFailed(format!(
                "remaining_depth {} exceeds max {}",
                self.remaining_depth, MAX_DELEGATION_DEPTH
            )));
        }
        if self.issued_at.is_empty() {
            return Err(CapabilityError::ValidationFailed(
                "issued_at must not be empty".to_string(),
            ));
        }
        if self.expires_at.is_empty() {
            return Err(CapabilityError::ValidationFailed(
                "expires_at must not be empty".to_string(),
            ));
        }
        // SECURITY (FIND-R51-008): Validate temporal ordering.
        // For ISO 8601 timestamps, lexicographic comparison preserves chronological order.
        if self.expires_at <= self.issued_at {
            return Err(CapabilityError::ValidationFailed(
                "expires_at must be after issued_at".to_string(),
            ));
        }
        // Validate grants
        for (i, grant) in self.grants.iter().enumerate() {
            if grant.tool_pattern.is_empty() {
                return Err(CapabilityError::ValidationFailed(format!(
                    "grant {i} tool_pattern must not be empty"
                )));
            }
            if grant.function_pattern.is_empty() {
                return Err(CapabilityError::ValidationFailed(format!(
                    "grant {i} function_pattern must not be empty"
                )));
            }
            grant.validate()?;
        }
        // Check serialized size
        let serialized = serde_json::to_string(self)
            .map_err(|e| CapabilityError::ValidationFailed(format!("serialization failed: {e}")))?;
        if serialized.len() > MAX_TOKEN_SIZE {
            return Err(CapabilityError::ValidationFailed(format!(
                "serialized token size {} exceeds max {}",
                serialized.len(),
                MAX_TOKEN_SIZE
            )));
        }
        Ok(())
    }
}
