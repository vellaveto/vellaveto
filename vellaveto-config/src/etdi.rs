// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Maximum number of allowed signer fingerprints or SPIFFE IDs.
const MAX_ALLOWED_SIGNERS: usize = 1000;

/// Maximum length of a single fingerprint string.
const MAX_FINGERPRINT_LEN: usize = 256;

/// Maximum length of a single SPIFFE ID string.
const MAX_SPIFFE_ID_LEN: usize = 512;

impl EtdiConfig {
    /// Validate the ETDI configuration.
    pub fn validate(&self) -> Result<(), String> {
        self.allowed_signers.validate()?;
        self.attestation.validate()?;
        self.version_pinning.validate()?;
        if let Some(ref path) = self.data_path {
            if vellaveto_types::has_dangerous_chars(path) {
                return Err("etdi.data_path contains control or format characters".to_string());
            }
        }
        Ok(())
    }
}

impl AllowedSignersConfig {
    /// Validate bounds on allowed signers collections.
    pub fn validate(&self) -> Result<(), String> {
        if self.fingerprints.len() > MAX_ALLOWED_SIGNERS {
            return Err(format!(
                "allowed_signers.fingerprints count {} exceeds maximum {}",
                self.fingerprints.len(),
                MAX_ALLOWED_SIGNERS
            ));
        }
        if self.spiffe_ids.len() > MAX_ALLOWED_SIGNERS {
            return Err(format!(
                "allowed_signers.spiffe_ids count {} exceeds maximum {}",
                self.spiffe_ids.len(),
                MAX_ALLOWED_SIGNERS
            ));
        }
        for fp in &self.fingerprints {
            if fp.len() > MAX_FINGERPRINT_LEN {
                return Err(format!(
                    "fingerprint length {} exceeds maximum {}",
                    fp.len(),
                    MAX_FINGERPRINT_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(fp) {
                return Err("fingerprint contains control or format characters".to_string());
            }
        }
        for sid in &self.spiffe_ids {
            if sid.len() > MAX_SPIFFE_ID_LEN {
                return Err(format!(
                    "SPIFFE ID length {} exceeds maximum {}",
                    sid.len(),
                    MAX_SPIFFE_ID_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(sid) {
                return Err("SPIFFE ID contains control or format characters".to_string());
            }
        }
        Ok(())
    }
}

impl AttestationConfig {
    /// Validate attestation configuration.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref url) = self.rekor_url {
            // SECURITY (BUG-R110-005, FIND-R114-005): Use proper URL parsing for localhost check.
            // is_http_localhost_url rejects non-HTTP schemes like ftp://localhost.
            if !url.starts_with("https://") && !crate::validation::is_http_localhost_url(url) {
                return Err(format!(
                    "attestation.rekor_url must use https:// (got: {})",
                    url.chars().take(64).collect::<String>()
                ));
            }
            if vellaveto_types::has_dangerous_chars(url) {
                return Err(
                    "attestation.rekor_url contains control or format characters".to_string(),
                );
            }
        }
        if self.transparency_log && self.rekor_url.is_none() {
            return Err(
                "attestation.transparency_log requires attestation.rekor_url to be set".to_string(),
            );
        }
        Ok(())
    }
}

impl VersionPinningConfig {
    /// Returns true if enforcement is set to block.
    pub fn is_blocking(&self) -> bool {
        self.enforcement.eq_ignore_ascii_case("block")
    }

    /// Validate version pinning configuration.
    pub fn validate(&self) -> Result<(), String> {
        let lower = self.enforcement.to_lowercase();
        if lower != "warn" && lower != "block" {
            return Err(format!(
                "version_pinning.enforcement must be \"warn\" or \"block\" (got: \"{}\")",
                self.enforcement.chars().take(64).collect::<String>()
            ));
        }
        if let Some(ref path) = self.pins_path {
            if vellaveto_types::has_dangerous_chars(path) {
                return Err(
                    "version_pinning.pins_path contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
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

    // ═══════════════════════════════════════════════════
    // ETDI Validation Tests (IMP-R110-002)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_etdi_config_validate_default_passes() {
        assert!(EtdiConfig::default().validate().is_ok());
    }

    #[test]
    fn test_allowed_signers_validate_too_many_fingerprints() {
        let config = AllowedSignersConfig {
            fingerprints: (0..1001).map(|i| format!("fp{i}")).collect(),
            spiffe_ids: vec![],
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("fingerprints count"));
    }

    #[test]
    fn test_allowed_signers_validate_too_many_spiffe_ids() {
        let config = AllowedSignersConfig {
            fingerprints: vec![],
            spiffe_ids: (0..1001).map(|i| format!("spiffe://test/{i}")).collect(),
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("spiffe_ids count"));
    }

    #[test]
    fn test_allowed_signers_validate_control_chars_in_fingerprint() {
        let config = AllowedSignersConfig {
            fingerprints: vec!["abc\n123".to_string()],
            spiffe_ids: vec![],
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control"));
    }

    #[test]
    fn test_attestation_validate_rekor_url_not_https() {
        let config = AttestationConfig {
            enabled: true,
            transparency_log: true,
            rekor_url: Some("http://rekor.example.com".to_string()),
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("https://"));
    }

    #[test]
    fn test_attestation_validate_transparency_log_without_url() {
        let config = AttestationConfig {
            enabled: true,
            transparency_log: true,
            rekor_url: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("rekor_url"));
    }

    #[test]
    fn test_attestation_validate_localhost_allowed() {
        let config = AttestationConfig {
            enabled: true,
            transparency_log: true,
            rekor_url: Some("http://localhost:3000".to_string()),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_version_pinning_validate_invalid_enforcement() {
        let config = VersionPinningConfig {
            enabled: true,
            enforcement: "allow".to_string(),
            pins_path: None,
            auto_pin: false,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("enforcement"));
    }

    #[test]
    fn test_version_pinning_validate_warn_ok() {
        let config = VersionPinningConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_version_pinning_validate_block_ok() {
        let config = VersionPinningConfig {
            enabled: true,
            enforcement: "Block".to_string(),
            pins_path: None,
            auto_pin: false,
        };
        assert!(config.validate().is_ok());
    }
}
