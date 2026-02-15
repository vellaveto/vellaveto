use serde::{Deserialize, Serialize};
use vellaveto_types::SignatureAlgorithm;

// ═══════════════════════════════════════════════════
// ETDI: ENHANCED TOOL DEFINITION INTERFACE
// Cryptographic verification of MCP tool definitions
// Based on arxiv:2506.01333
// ═══════════════════════════════════════════════════

/// Configuration for the ETDI (Enhanced Tool Definition Interface) system.
///
/// ETDI provides cryptographic verification of MCP tool definitions to prevent:
/// - Tool rug-pulls (definition changes post-install)
/// - Tool squatting (malicious tools impersonating legitimate ones)
/// - Supply chain attacks on MCP tool servers
///
/// # TOML Example
///
/// ```toml
/// [etdi]
/// enabled = true
/// require_signatures = false
/// signature_algorithm = "ed25519"
/// data_path = "/var/lib/vellaveto/etdi"
///
/// [etdi.allowed_signers]
/// fingerprints = ["abc123..."]
/// spiffe_ids = ["spiffe://example.org/tool-provider"]
///
/// [etdi.attestation]
/// enabled = true
/// transparency_log = false
///
/// [etdi.version_pinning]
/// enabled = true
/// enforcement = "warn"
/// auto_pin = false
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EtdiConfig {
    /// Enable ETDI signature verification. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Require all tools to have valid signatures.
    /// When true, unsigned tools are rejected. Default: false.
    #[serde(default)]
    pub require_signatures: bool,

    /// Default signature algorithm for new signatures.
    #[serde(default)]
    pub signature_algorithm: SignatureAlgorithm,

    /// Path to ETDI data storage (signatures, attestations, pins).
    /// Default: "etdi_data" in current directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_path: Option<String>,

    /// Allowed signers configuration.
    #[serde(default)]
    pub allowed_signers: AllowedSignersConfig,

    /// Attestation chain configuration.
    #[serde(default)]
    pub attestation: AttestationConfig,

    /// Version pinning configuration.
    #[serde(default)]
    pub version_pinning: VersionPinningConfig,
}

/// Configuration for trusted tool signers.
///
/// Tools signed by keys matching these criteria are marked as trusted.
/// When both fingerprints and SPIFFE IDs are empty, no signers are trusted
/// (all signatures verify but are marked as "untrusted signer").
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AllowedSignersConfig {
    /// Hex-encoded SHA-256 fingerprints of trusted public keys.
    #[serde(default)]
    pub fingerprints: Vec<String>,

    /// SPIFFE IDs of trusted workload identities.
    /// Example: "spiffe://example.org/tool-provider"
    #[serde(default)]
    pub spiffe_ids: Vec<String>,
}

impl AllowedSignersConfig {
    /// Returns true if any trust criteria are configured.
    pub fn has_any(&self) -> bool {
        !self.fingerprints.is_empty() || !self.spiffe_ids.is_empty()
    }

    /// Check if a fingerprint is trusted.
    pub fn is_fingerprint_trusted(&self, fingerprint: &str) -> bool {
        self.fingerprints
            .iter()
            .any(|f| f.eq_ignore_ascii_case(fingerprint))
    }

    /// Check if a SPIFFE ID is trusted.
    pub fn is_spiffe_trusted(&self, spiffe_id: &str) -> bool {
        self.spiffe_ids.iter().any(|s| s == spiffe_id)
    }
}

/// Configuration for attestation chains (provenance tracking).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AttestationConfig {
    /// Enable attestation chain tracking. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Submit attestations to a transparency log (e.g., Rekor).
    /// Requires rekor_url to be set. Default: false.
    #[serde(default)]
    pub transparency_log: bool,

    /// URL of the Rekor transparency log server.
    /// Example: `https://rekor.sigstore.dev`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekor_url: Option<String>,
}

/// Configuration for version pinning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionPinningConfig {
    /// Enable version pinning. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Enforcement mode for version drift.
    /// - "warn": Log warnings but allow the tool to be used.
    /// - "block": Block tools that don't match their pinned version/hash.
    ///
    /// Default: "warn".
    #[serde(default = "default_version_enforcement")]
    pub enforcement: String,

    /// Path to version pins file. When not set, uses `{data_path}/pins.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pins_path: Option<String>,

    /// Automatically pin tools when first seen. Default: false.
    /// When true, new tools are automatically pinned to their initial version.
    #[serde(default)]
    pub auto_pin: bool,
}

fn default_version_enforcement() -> String {
    "warn".to_string()
}

impl Default for VersionPinningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enforcement: default_version_enforcement(),
            pins_path: None,
            auto_pin: false,
        }
    }
}

impl VersionPinningConfig {
    /// Returns true if enforcement is set to block.
    pub fn is_blocking(&self) -> bool {
        self.enforcement.eq_ignore_ascii_case("block")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ═══════════════════════════════════════════════════
    // ETDI Configuration Tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_etdi_config_default() {
        let config = EtdiConfig::default();
        assert!(!config.enabled);
        assert!(!config.require_signatures);
        assert_eq!(
            config.signature_algorithm,
            vellaveto_types::SignatureAlgorithm::Ed25519
        );
        assert!(config.data_path.is_none());
        assert!(!config.allowed_signers.has_any());
        assert!(!config.attestation.enabled);
        assert!(!config.version_pinning.enabled);
    }

    #[test]
    fn test_allowed_signers_has_any() {
        let empty = AllowedSignersConfig::default();
        assert!(!empty.has_any());

        let with_fingerprint = AllowedSignersConfig {
            fingerprints: vec!["abc".to_string()],
            spiffe_ids: vec![],
        };
        assert!(with_fingerprint.has_any());

        let with_spiffe = AllowedSignersConfig {
            fingerprints: vec![],
            spiffe_ids: vec!["spiffe://test".to_string()],
        };
        assert!(with_spiffe.has_any());
    }

    #[test]
    fn test_allowed_signers_is_fingerprint_trusted() {
        let signers = AllowedSignersConfig {
            fingerprints: vec!["ABC123".to_string()],
            spiffe_ids: vec![],
        };
        // Case-insensitive match
        assert!(signers.is_fingerprint_trusted("abc123"));
        assert!(signers.is_fingerprint_trusted("ABC123"));
        assert!(!signers.is_fingerprint_trusted("xyz789"));
    }

    #[test]
    fn test_allowed_signers_is_spiffe_trusted() {
        let signers = AllowedSignersConfig {
            fingerprints: vec![],
            spiffe_ids: vec!["spiffe://example.org/tool".to_string()],
        };
        assert!(signers.is_spiffe_trusted("spiffe://example.org/tool"));
        assert!(!signers.is_spiffe_trusted("spiffe://example.org/other"));
    }

    #[test]
    fn test_version_pinning_is_blocking() {
        let warn = VersionPinningConfig {
            enabled: true,
            enforcement: "warn".to_string(),
            pins_path: None,
            auto_pin: false,
        };
        assert!(!warn.is_blocking());

        let block = VersionPinningConfig {
            enabled: true,
            enforcement: "block".to_string(),
            pins_path: None,
            auto_pin: false,
        };
        assert!(block.is_blocking());

        // Case-insensitive
        let block_caps = VersionPinningConfig {
            enabled: true,
            enforcement: "BLOCK".to_string(),
            pins_path: None,
            auto_pin: false,
        };
        assert!(block_caps.is_blocking());
    }
}
