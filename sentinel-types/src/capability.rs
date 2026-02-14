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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// A single permission grant within a capability token.
///
/// Each grant specifies which tools/functions the holder can invoke,
/// optionally restricted to specific paths and domains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// Result of verifying a capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityVerification {
    /// Whether the token is valid.
    pub valid: bool,
    /// Reason for failure, if any.
    pub failure_reason: Option<String>,
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
            CapabilityError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            CapabilityError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            CapabilityError::VerificationFailed(msg) => {
                write!(f, "Verification failed: {}", msg)
            }
            CapabilityError::Expired => write!(f, "Token has expired"),
            CapabilityError::AttenuationViolation(msg) => {
                write!(f, "Attenuation violation: {}", msg)
            }
            CapabilityError::ValidationFailed(msg) => {
                write!(f, "Validation failed: {}", msg)
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
        if self.issuer.is_empty() {
            return Err(CapabilityError::ValidationFailed(
                "issuer must not be empty".to_string(),
            ));
        }
        if self.holder.is_empty() {
            return Err(CapabilityError::ValidationFailed(
                "holder must not be empty".to_string(),
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
        // Validate grants
        for (i, grant) in self.grants.iter().enumerate() {
            if grant.tool_pattern.is_empty() {
                return Err(CapabilityError::ValidationFailed(format!(
                    "grant {} tool_pattern must not be empty",
                    i
                )));
            }
            if grant.function_pattern.is_empty() {
                return Err(CapabilityError::ValidationFailed(format!(
                    "grant {} function_pattern must not be empty",
                    i
                )));
            }
        }
        // Check serialized size
        let serialized = serde_json::to_string(self).map_err(|e| {
            CapabilityError::ValidationFailed(format!("serialization failed: {}", e))
        })?;
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
