//! FIPS 140-3 Compliance Mode (Phase 23.3).
//!
//! When the `fips` feature is enabled, this module provides:
//! - ECDSA P-256 signing/verification as an alternative to Ed25519
//! - Algorithm validation that rejects non-FIPS algorithms
//! - FIPS mode flag for runtime enforcement
//!
//! # Feature Flag
//!
//! Requires the `fips` feature:
//! ```toml
//! vellaveto-mcp = { version = "2.2", features = ["fips"] }
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// FIPS 140-3 approved algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FipsAlgorithm {
    /// ECDSA with NIST P-256 curve.
    EcdsaP256,
    /// SHA-256 hash.
    Sha256,
    /// SHA-384 hash.
    Sha384,
    /// AES-256-GCM authenticated encryption.
    Aes256Gcm,
    /// HMAC-SHA-256 message authentication.
    HmacSha256,
}

impl FipsAlgorithm {
    /// Returns the algorithm name string.
    pub fn name(&self) -> &'static str {
        match self {
            FipsAlgorithm::EcdsaP256 => "ecdsa-p256",
            FipsAlgorithm::Sha256 => "sha256",
            FipsAlgorithm::Sha384 => "sha384",
            FipsAlgorithm::Aes256Gcm => "aes-256-gcm",
            FipsAlgorithm::HmacSha256 => "hmac-sha256",
        }
    }
}

/// Non-FIPS algorithms that must be rejected in FIPS mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonFipsAlgorithm {
    /// Ed25519 signatures (not NIST-approved).
    Ed25519,
    /// ChaCha20-Poly1305 (not NIST-approved).
    ChaCha20Poly1305,
    /// BLAKE2 hash (not NIST-approved).
    Blake2,
}

/// Errors from FIPS mode operations.
#[derive(Error, Debug)]
pub enum FipsError {
    #[error("Algorithm '{0}' is not FIPS 140-3 approved")]
    NonFipsAlgorithm(String),
    #[error("FIPS mode is not enabled")]
    NotEnabled,
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

/// FIPS 140-3 compliance mode controller.
pub struct FipsMode {
    enabled: bool,
}

/// Known algorithm names for validation.
const FIPS_APPROVED_ALGORITHMS: &[&str] = &[
    "ecdsa-p256",
    "ecdsa_p256",
    "sha256",
    "sha-256",
    "sha384",
    "sha-384",
    "sha512",
    "sha-512",
    "aes-256-gcm",
    "aes256gcm",
    "hmac-sha256",
    "hmac-sha-256",
    "rsa-pss",
];

const NON_FIPS_ALGORITHMS: &[&str] = &[
    "ed25519",
    "chacha20poly1305",
    "chacha20-poly1305",
    "blake2",
    "blake2b",
    "blake2s",
    "curve25519",
    "x25519",
];

impl FipsMode {
    /// Create a new FIPS mode controller.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Check if FIPS mode is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Validate that an algorithm is FIPS 140-3 approved.
    ///
    /// When FIPS mode is enabled, rejects non-FIPS algorithms.
    /// When disabled, all algorithms are accepted.
    pub fn validate_algorithm(&self, algorithm: &str) -> Result<(), FipsError> {
        if !self.enabled {
            return Ok(());
        }

        let alg_lower = algorithm.to_lowercase();

        // Check explicit non-FIPS list first
        if NON_FIPS_ALGORITHMS.contains(&alg_lower.as_str()) {
            return Err(FipsError::NonFipsAlgorithm(algorithm.to_string()));
        }

        // Check if it's in the approved list
        if FIPS_APPROVED_ALGORITHMS.contains(&alg_lower.as_str()) {
            return Ok(());
        }

        // Unknown algorithm — fail-closed in FIPS mode
        Err(FipsError::NonFipsAlgorithm(algorithm.to_string()))
    }

    /// Returns the list of allowed signature algorithms.
    pub fn allowed_signature_algorithms(&self) -> Vec<&'static str> {
        if self.enabled {
            vec!["ecdsa-p256", "rsa-pss"]
        } else {
            vec!["ed25519", "ecdsa-p256", "rsa-pss"]
        }
    }

    /// Returns the list of allowed hash algorithms.
    pub fn allowed_hash_algorithms(&self) -> Vec<&'static str> {
        if self.enabled {
            vec!["sha256", "sha384", "sha512"]
        } else {
            vec!["sha256", "sha384", "sha512", "blake2"]
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// ECDSA P-256 Operations (feature-gated)
// ═══════════════════════════════════════════════════════════════════

/// Sign data using ECDSA P-256.
///
/// Requires the `fips` feature.
#[cfg(feature = "fips")]
pub fn sign_ecdsa_p256(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, FipsError> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| FipsError::InvalidKey(format!("Invalid P-256 private key: {}", e)))?;

    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Verify an ECDSA P-256 signature.
///
/// Requires the `fips` feature.
#[cfg(feature = "fips")]
pub fn verify_ecdsa_p256(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, FipsError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    let point = EncodedPoint::from_bytes(public_key)
        .map_err(|e| FipsError::InvalidKey(format!("Invalid P-256 public key: {}", e)))?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| FipsError::InvalidKey(format!("Invalid P-256 public key: {}", e)))?;

    let sig = Signature::from_der(signature)
        .map_err(|e| FipsError::VerificationFailed(format!("Invalid DER signature: {}", e)))?;

    match verifying_key.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Stub for when `fips` feature is not enabled.
#[cfg(not(feature = "fips"))]
pub fn sign_ecdsa_p256(_data: &[u8], _private_key: &[u8]) -> Result<Vec<u8>, FipsError> {
    Err(FipsError::NotEnabled)
}

/// Stub for when `fips` feature is not enabled.
#[cfg(not(feature = "fips"))]
pub fn verify_ecdsa_p256(
    _data: &[u8],
    _signature: &[u8],
    _public_key: &[u8],
) -> Result<bool, FipsError> {
    Err(FipsError::NotEnabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_mode_rejects_ed25519() {
        let fips = FipsMode::new(true);
        let result = fips.validate_algorithm("ed25519");
        assert!(matches!(result, Err(FipsError::NonFipsAlgorithm(_))));
    }

    #[test]
    fn test_fips_mode_accepts_ecdsa_p256() {
        let fips = FipsMode::new(true);
        assert!(fips.validate_algorithm("ecdsa-p256").is_ok());
        assert!(fips.validate_algorithm("ecdsa_p256").is_ok());
    }

    #[test]
    fn test_fips_mode_accepts_sha256() {
        let fips = FipsMode::new(true);
        assert!(fips.validate_algorithm("sha256").is_ok());
        assert!(fips.validate_algorithm("sha-256").is_ok());
    }

    #[test]
    fn test_fips_mode_rejects_chacha20() {
        let fips = FipsMode::new(true);
        let result = fips.validate_algorithm("chacha20poly1305");
        assert!(matches!(result, Err(FipsError::NonFipsAlgorithm(_))));
    }

    #[test]
    fn test_fips_mode_rejects_blake2() {
        let fips = FipsMode::new(true);
        let result = fips.validate_algorithm("blake2");
        assert!(matches!(result, Err(FipsError::NonFipsAlgorithm(_))));
    }

    #[test]
    fn test_disabled_fips_allows_everything() {
        let fips = FipsMode::new(false);
        assert!(fips.validate_algorithm("ed25519").is_ok());
        assert!(fips.validate_algorithm("chacha20poly1305").is_ok());
        assert!(fips.validate_algorithm("blake2").is_ok());
        assert!(fips.validate_algorithm("anything").is_ok());
    }

    #[test]
    fn test_fips_mode_rejects_unknown_algorithm() {
        let fips = FipsMode::new(true);
        let result = fips.validate_algorithm("totally_made_up");
        assert!(matches!(result, Err(FipsError::NonFipsAlgorithm(_))));
    }

    #[test]
    fn test_allowed_signature_algorithms_fips() {
        let fips = FipsMode::new(true);
        let algs = fips.allowed_signature_algorithms();
        assert!(algs.contains(&"ecdsa-p256"));
        assert!(!algs.contains(&"ed25519"));
    }

    #[test]
    fn test_allowed_signature_algorithms_non_fips() {
        let fips = FipsMode::new(false);
        let algs = fips.allowed_signature_algorithms();
        assert!(algs.contains(&"ed25519"));
        assert!(algs.contains(&"ecdsa-p256"));
    }

    #[test]
    fn test_allowed_hash_algorithms() {
        let fips = FipsMode::new(true);
        let algs = fips.allowed_hash_algorithms();
        assert!(algs.contains(&"sha256"));
        assert!(!algs.contains(&"blake2"));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_ecdsa_p256_not_enabled() {
        let result = sign_ecdsa_p256(b"test", &[0; 32]);
        assert!(matches!(result, Err(FipsError::NotEnabled)));

        let result = verify_ecdsa_p256(b"test", &[0; 64], &[0; 33]);
        assert!(matches!(result, Err(FipsError::NotEnabled)));
    }

    #[test]
    fn test_fips_algorithm_names() {
        assert_eq!(FipsAlgorithm::EcdsaP256.name(), "ecdsa-p256");
        assert_eq!(FipsAlgorithm::Sha256.name(), "sha256");
        assert_eq!(FipsAlgorithm::Sha384.name(), "sha384");
        assert_eq!(FipsAlgorithm::Aes256Gcm.name(), "aes-256-gcm");
        assert_eq!(FipsAlgorithm::HmacSha256.name(), "hmac-sha256");
    }
}
