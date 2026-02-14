//! FIPS 140-3 compliance mode configuration (Phase 23.3).

use serde::{Deserialize, Serialize};

/// Default signature algorithm when FIPS mode is disabled.
fn default_signature_algorithm() -> String {
    "ed25519".to_string()
}

/// FIPS 140-3 compliance mode configuration.
///
/// When enabled, restricts cryptographic operations to NIST-approved algorithms:
/// - ECDSA P-256 for signatures (instead of Ed25519)
/// - SHA-256 / SHA-384 for hashing
/// - AES-256-GCM for encryption
/// - HMAC-SHA-256 for message authentication
///
/// Requires the `fips` feature flag on `sentinel-mcp`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FipsConfig {
    /// Whether FIPS 140-3 compliance mode is enabled.
    /// When true, non-FIPS algorithms (Ed25519, ChaCha20, Blake2) are rejected.
    #[serde(default)]
    pub enabled: bool,

    /// Signature algorithm to use.
    /// - `"ed25519"` (default, non-FIPS)
    /// - `"ecdsa-p256"` (FIPS-approved)
    #[serde(default = "default_signature_algorithm")]
    pub signature_algorithm: String,
}

impl Default for FipsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            signature_algorithm: default_signature_algorithm(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_config_default() {
        let config = FipsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.signature_algorithm, "ed25519");
    }

    #[test]
    fn test_fips_config_serde_roundtrip() {
        let config = FipsConfig {
            enabled: true,
            signature_algorithm: "ecdsa-p256".to_string(),
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: FipsConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(back.enabled);
        assert_eq!(back.signature_algorithm, "ecdsa-p256");
    }

    #[test]
    fn test_fips_config_deserialize_empty() {
        let config: FipsConfig = serde_json::from_str("{}").expect("deserialize");
        assert!(!config.enabled);
        assert_eq!(config.signature_algorithm, "ed25519");
    }
}
