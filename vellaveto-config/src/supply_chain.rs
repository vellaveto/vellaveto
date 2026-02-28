// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

use serde::{Deserialize, Serialize};

/// Constant-time comparison for hash strings to prevent timing side-channels.
///
/// SECURITY (R39-SUP-2): Standard `==` on strings uses early-exit comparison,
/// leaking information about the position of the first differing byte. This
/// function iterates all bytes unconditionally, XOR-folding differences into
/// a single accumulator.
///
/// Note: The length check at the start is not constant-time, but for hash
/// comparison this is acceptable because SHA-256 hex digests always have the
/// same length (64 characters). A length mismatch indicates a programming
/// error or corrupted data, not a valid comparison.
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Supply chain verification configuration.
///
/// When enabled, the proxy verifies SHA-256 hashes of MCP server binaries
/// before spawning them.
///
/// # TOML Example
///
/// ```toml
/// [supply_chain]
/// enabled = true
///
/// [supply_chain.allowed_servers]
/// "/usr/local/bin/my-mcp" = "sha256hex..."
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainConfig {
    /// Master toggle. When false (default), binary verification is skipped.
    #[serde(default)]
    pub enabled: bool,
    /// Map of binary path → expected SHA-256 hex digest.
    #[serde(default)]
    pub allowed_servers: std::collections::HashMap<String, String>,
    /// When true, validate that all paths in `allowed_servers` exist at load time.
    #[serde(default)]
    pub validate_paths_on_load: bool,
}

/// Maximum binary file size for supply chain hash computation (500 MB).
///
/// SECURITY (R39-SUP-3): Prevents OOM from unbounded file reads when
/// computing SHA-256 hashes of MCP server binaries.
pub const MAX_BINARY_SIZE: u64 = 500 * 1024 * 1024;

impl SupplyChainConfig {
    /// Compute the SHA-256 hash of a file at the given path.
    ///
    /// Returns the hex-encoded hash string, or an error if the file cannot be read
    /// or exceeds `MAX_BINARY_SIZE`.
    ///
    /// SECURITY (R39-SUP-3): Checks file metadata before reading to prevent
    /// unbounded memory allocation from very large files.
    pub fn compute_hash(path: &str) -> Result<String, String> {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("Cannot read metadata for '{}': {}", path, e))?;
        if meta.len() > MAX_BINARY_SIZE {
            return Err(format!(
                "Binary '{}' exceeds maximum size of {} bytes (actual: {})",
                path,
                MAX_BINARY_SIZE,
                meta.len()
            ));
        }
        let data = std::fs::read(path).map_err(|e| format!("Failed to read '{}': {}", path, e))?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Verify that a binary at `path` matches its expected SHA-256 hash.
    ///
    /// Returns `Ok(())` if verification passes or is disabled. Returns
    /// `Err(reason)` if the binary is unlisted, missing, or has a hash mismatch.
    ///
    /// SECURITY (R39-SUP-2): Uses constant-time comparison for hash strings
    /// to prevent timing side-channel attacks.
    pub fn verify_binary(&self, path: &str) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let expected_hash = self
            .allowed_servers
            .get(path)
            .ok_or_else(|| format!("Binary '{}' not in allowed_servers list", path))?;

        let actual_hash = Self::compute_hash(path)?;

        if !constant_time_eq(&actual_hash, expected_hash) {
            return Err(format!(
                "Hash mismatch for '{}': expected {}, got {}",
                path, expected_hash, actual_hash
            ));
        }

        Ok(())
    }

    /// Validate configuration bounds for supply chain settings.
    ///
    /// Checks:
    /// - `allowed_servers` count does not exceed 1000
    /// - Path keys and hash values are within length bounds
    /// - Hash values contain only hex characters and are 64 chars (SHA-256)
    /// - If `validate_paths_on_load` is set, all paths exist on the filesystem
    pub fn validate(&self) -> Result<(), String> {
        const MAX_ALLOWED_SERVERS: usize = 1000;
        const MAX_PATH_LEN: usize = 4096;
        const EXPECTED_SHA256_HEX_LEN: usize = 64;

        if self.allowed_servers.len() > MAX_ALLOWED_SERVERS {
            return Err(format!(
                "supply_chain.allowed_servers count {} exceeds maximum {MAX_ALLOWED_SERVERS}",
                self.allowed_servers.len()
            ));
        }

        for (path, hash) in &self.allowed_servers {
            if path.is_empty() {
                return Err("supply_chain.allowed_servers contains empty path key".to_string());
            }
            if path.len() > MAX_PATH_LEN {
                return Err(format!(
                    "supply_chain.allowed_servers path length {} exceeds maximum {MAX_PATH_LEN}",
                    path.len()
                ));
            }
            if path
                .bytes()
                .any(|b| b < 0x20 || b == 0x7F || (0x80..=0x9F).contains(&b))
            {
                return Err(format!(
                    "supply_chain.allowed_servers path '{}' contains control characters",
                    &path[..path.len().min(64)]
                ));
            }
            if hash.len() != EXPECTED_SHA256_HEX_LEN {
                return Err(format!(
                    "supply_chain.allowed_servers hash for '{}' has length {} (expected {EXPECTED_SHA256_HEX_LEN})",
                    &path[..path.len().min(64)],
                    hash.len()
                ));
            }
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "supply_chain.allowed_servers hash for '{}' contains non-hex characters",
                    &path[..path.len().min(64)]
                ));
            }
            // SECURITY (R114-004): Reject uppercase hex characters. compute_hash()
            // returns lowercase hex, and constant_time_eq() compares byte-literal.
            // Uppercase hashes will always fail verification at runtime with a
            // confusing "Hash mismatch" error. Reject early with a clear message.
            if hash.chars().any(|c| c.is_ascii_uppercase()) {
                return Err(format!(
                    "supply_chain.allowed_servers hash for '{}' must be lowercase hex",
                    &path[..path.len().min(64)]
                ));
            }
        }

        if self.validate_paths_on_load {
            if let Err(missing) = self.validate_paths() {
                return Err(format!(
                    "supply_chain.validate_paths_on_load: missing paths: {}",
                    missing.join(", ")
                ));
            }
        }

        Ok(())
    }

    /// Validate that all paths in `allowed_servers` exist on the filesystem.
    ///
    /// Returns `Ok(())` if all paths exist, or `Err(missing_paths)` with a list
    /// of paths that could not be found.
    pub fn validate_paths(&self) -> Result<(), Vec<String>> {
        let missing: Vec<String> = self
            .allowed_servers
            .keys()
            .filter(|path| !std::path::Path::new(path).exists())
            .cloned()
            .collect();

        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_chain_disabled_always_passes() {
        let config = SupplyChainConfig {
            enabled: false,
            allowed_servers: std::collections::HashMap::new(),
            ..Default::default()
        };
        assert!(config.verify_binary("/nonexistent/path").is_ok());
    }

    #[test]
    fn test_supply_chain_correct_hash_passes() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("fake-server");
        std::fs::write(&bin_path, b"hello server binary").unwrap();

        // Compute expected hash
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"hello server binary");
        let expected_hash = hex::encode(hasher.finalize());

        let mut allowed = std::collections::HashMap::new();
        allowed.insert(bin_path.to_string_lossy().to_string(), expected_hash);

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            ..Default::default()
        };
        assert!(config.verify_binary(&bin_path.to_string_lossy()).is_ok());
    }

    #[test]
    fn test_supply_chain_wrong_hash_fails() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("fake-server");
        std::fs::write(&bin_path, b"hello server binary").unwrap();

        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            bin_path.to_string_lossy().to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            ..Default::default()
        };
        let result = config.verify_binary(&bin_path.to_string_lossy());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hash mismatch"));
    }

    #[test]
    fn test_supply_chain_unlisted_binary_fails() {
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: std::collections::HashMap::new(),
            ..Default::default()
        };
        let result = config.verify_binary("/usr/bin/something");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowed_servers"));
    }

    #[test]
    fn test_supply_chain_missing_binary_fails() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/nonexistent/binary".to_string(),
            "abcdef1234567890".to_string(),
        );

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            ..Default::default()
        };
        let result = config.verify_binary("/nonexistent/binary");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot read metadata"));
    }

    #[test]
    fn test_supply_chain_compute_hash() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("test-binary");
        std::fs::write(&bin_path, b"hello").unwrap();

        let hash = SupplyChainConfig::compute_hash(bin_path.to_str().unwrap()).unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex
                                    // Hash of "hello"
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_supply_chain_validate_paths_all_exist() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("server");
        std::fs::write(&bin_path, b"binary").unwrap();

        let mut allowed = std::collections::HashMap::new();
        allowed.insert(bin_path.to_string_lossy().to_string(), "hash".to_string());

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            ..Default::default()
        };
        assert!(config.validate_paths().is_ok());
    }

    #[test]
    fn test_supply_chain_validate_paths_missing() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert("/nonexistent/server".to_string(), "hash".to_string());

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            ..Default::default()
        };
        let result = config.validate_paths();
        assert!(result.is_err());
        let missing = result.unwrap_err();
        assert!(missing.contains(&"/nonexistent/server".to_string()));
    }

    // --- validate() bounds tests ---

    #[test]
    fn test_supply_chain_validate_default_ok() {
        let config = SupplyChainConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_supply_chain_validate_valid_config() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/usr/bin/mcp-server".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: false,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_supply_chain_validate_empty_path() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            String::new(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: false,
        };
        assert!(config.validate().unwrap_err().contains("empty path key"));
    }

    #[test]
    fn test_supply_chain_validate_bad_hash_length() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert("/bin/server".to_string(), "tooshort".to_string());
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: false,
        };
        assert!(config.validate().unwrap_err().contains("has length"));
    }

    #[test]
    fn test_supply_chain_validate_non_hex_hash() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/bin/server".to_string(),
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(),
        );
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: false,
        };
        assert!(config.validate().unwrap_err().contains("non-hex"));
    }

    // R114-004: Uppercase hex must be rejected to prevent silent runtime mismatch
    #[test]
    fn test_supply_chain_validate_uppercase_hex_rejected() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/bin/server".to_string(),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".to_string(),
        );
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: false,
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("must be lowercase hex"),
            "Uppercase hex should be rejected, got: {}",
            err
        );
    }

    #[test]
    fn test_supply_chain_validate_mixed_case_hex_rejected() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/bin/server".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb924A7ae41e4649b934ca495991b7852b855".to_string(),
        );
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: false,
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("must be lowercase hex"),
            "Mixed-case hex should be rejected, got: {}",
            err
        );
    }

    #[test]
    fn test_supply_chain_validate_lowercase_hex_accepted() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/bin/server".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: false,
        };
        assert!(
            config.validate().is_ok(),
            "Lowercase hex should be accepted"
        );
    }

    #[test]
    fn test_supply_chain_validate_control_chars_in_path() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/bin/\x00server".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: false,
        };
        assert!(config
            .validate()
            .unwrap_err()
            .contains("control characters"));
    }

    #[test]
    fn test_supply_chain_validate_paths_on_load_missing() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/nonexistent/path".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        );
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            validate_paths_on_load: true,
        };
        assert!(config.validate().unwrap_err().contains("missing paths"));
    }

    // --- R39-SUP-2: Constant-time hash comparison tests ---

    #[test]
    fn test_r39_sup_2_constant_time_eq_equal_strings() {
        assert!(constant_time_eq("abc", "abc"));
    }

    #[test]
    fn test_r39_sup_2_constant_time_eq_different_strings() {
        assert!(!constant_time_eq("abc", "abd"));
    }

    #[test]
    fn test_r39_sup_2_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("abc", "ab"));
    }

    #[test]
    fn test_r39_sup_2_constant_time_eq_empty_strings() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_r39_sup_2_constant_time_eq_hex_hashes() {
        // Simulate real SHA-256 hex comparison
        let hash_a = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash_b = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(constant_time_eq(hash_a, hash_b));

        let hash_c = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856";
        assert!(!constant_time_eq(hash_a, hash_c));
    }

    #[test]
    fn test_r39_sup_2_verify_binary_uses_constant_time_comparison() {
        // Verify that verify_binary still works correctly with constant-time eq
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("test-binary");
        std::fs::write(&bin_path, b"test binary content").unwrap();

        let actual_hash = SupplyChainConfig::compute_hash(&bin_path.to_string_lossy()).unwrap();

        let mut allowed = std::collections::HashMap::new();
        allowed.insert(bin_path.to_string_lossy().to_string(), actual_hash);

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            ..Default::default()
        };
        assert!(config.verify_binary(&bin_path.to_string_lossy()).is_ok());
    }

    // --- R39-SUP-3: compute_hash file size bound tests ---

    #[test]
    fn test_r39_sup_3_compute_hash_works_for_normal_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small-binary");
        std::fs::write(&path, b"small file content").unwrap();

        let result = SupplyChainConfig::compute_hash(&path.to_string_lossy());
        assert!(result.is_ok());
        // SHA-256 hex hash should be 64 chars
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_r39_sup_3_compute_hash_nonexistent_file_returns_error() {
        let result = SupplyChainConfig::compute_hash("/nonexistent/path/binary");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot read metadata"));
    }
}
