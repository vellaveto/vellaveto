// ═══════════════════════════════════════════════════════════════════════════════
// LICENSING — Tier configuration, limits, and license key validation
// ═══════════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing;

const MAX_LICENSE_KEY_LEN: usize = 256;
const MAX_HMAC_SECRET_LEN: usize = 128;

/// License tier determining feature limits.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    #[default]
    Community,
    Pro,
    Business,
    Enterprise,
}

impl LicenseTier {
    fn from_key_segment(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "community" | "com" => Some(LicenseTier::Community),
            "pro" => Some(LicenseTier::Pro),
            "business" | "biz" => Some(LicenseTier::Business),
            "enterprise" | "ent" => Some(LicenseTier::Enterprise),
            _ => None,
        }
    }

    /// Returns the feature limits for this tier.
    pub fn limits(&self) -> TierLimits {
        match self {
            LicenseTier::Community => TierLimits {
                max_mcp_servers: Some(5),
                max_users: Some(3),
                siem_export: false,
                sso_oidc: false,
                sso_saml: false,
                rbac: false,
                multi_tenancy: false,
                ha_clustering: false,
                compliance_reports: false,
                nis2_evidence: false,
                incident_workflow: false,
            },
            LicenseTier::Pro => TierLimits {
                max_mcp_servers: Some(25),
                max_users: Some(20),
                siem_export: true,
                sso_oidc: true,
                sso_saml: false,
                rbac: false,
                multi_tenancy: false,
                ha_clustering: false,
                compliance_reports: false,
                nis2_evidence: false,
                incident_workflow: false,
            },
            LicenseTier::Business => TierLimits {
                max_mcp_servers: Some(100),
                max_users: None,
                siem_export: true,
                sso_oidc: true,
                sso_saml: true,
                rbac: true,
                multi_tenancy: true,
                ha_clustering: false,
                compliance_reports: true,
                nis2_evidence: false,
                incident_workflow: false,
            },
            LicenseTier::Enterprise => TierLimits {
                max_mcp_servers: None,
                max_users: None,
                siem_export: true,
                sso_oidc: true,
                sso_saml: true,
                rbac: true,
                multi_tenancy: true,
                ha_clustering: true,
                compliance_reports: true,
                nis2_evidence: true,
                incident_workflow: true,
            },
        }
    }

    /// Returns the tier name as used in license key segments.
    pub fn as_key_segment(&self) -> &'static str {
        match self {
            LicenseTier::Community => "COM",
            LicenseTier::Pro => "PRO",
            LicenseTier::Business => "BIZ",
            LicenseTier::Enterprise => "ENT",
        }
    }
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseTier::Community => write!(f, "Community"),
            LicenseTier::Pro => write!(f, "Pro"),
            LicenseTier::Business => write!(f, "Business"),
            LicenseTier::Enterprise => write!(f, "Enterprise"),
        }
    }
}

/// Feature limits for a given license tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierLimits {
    pub max_mcp_servers: Option<u32>,
    pub max_users: Option<u32>,
    pub siem_export: bool,
    pub sso_oidc: bool,
    pub sso_saml: bool,
    pub rbac: bool,
    pub multi_tenancy: bool,
    pub ha_clustering: bool,
    pub compliance_reports: bool,
    pub nis2_evidence: bool,
    pub incident_workflow: bool,
}

/// Licensing configuration section of PolicyConfig.
///
/// SECURITY: Custom Debug impl redacts license_key to prevent secret leakage.
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicensingConfig {
    #[serde(default)]
    pub license_key: Option<String>,
    #[serde(default)]
    pub tier_override: Option<LicenseTier>,
}

impl std::fmt::Debug for LicensingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicensingConfig")
            .field(
                "license_key",
                &self.license_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("tier_override", &self.tier_override)
            .finish()
    }
}

/// Result of license key validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseValidation {
    pub tier: LicenseTier,
    pub limits: TierLimits,
    pub reason: String,
}

impl LicensingConfig {
    /// Validate licensing configuration bounds.
    ///
    /// SECURITY: Rejects oversized or control-char-injected license keys
    /// at config load time (fail-closed).
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref key) = self.license_key {
            if key.len() > MAX_LICENSE_KEY_LEN {
                return Err(format!(
                    "licensing.license_key length {} exceeds max {}",
                    key.len(),
                    MAX_LICENSE_KEY_LEN,
                ));
            }
            if key
                .bytes()
                .any(|b| b < 0x20 || b == 0x7F || (0x80..=0x9F).contains(&b))
            {
                return Err("licensing.license_key contains control characters".to_string());
            }
        }
        Ok(())
    }

    /// Resolve the effective license tier. Fail-closed to Community.
    pub fn resolve(&self) -> LicenseValidation {
        if let Some(tier) = self.tier_override {
            tracing::warn!(tier = %tier, "License tier override active — bypasses key validation");
            return LicenseValidation {
                tier,
                limits: tier.limits(),
                reason: "tier_override in config".to_string(),
            };
        }

        let key = std::env::var("VELLAVETO_LICENSE_KEY")
            .ok()
            .or_else(|| self.license_key.clone());

        let key = match key {
            Some(k) if !k.is_empty() => k,
            _ => {
                tracing::info!("No license key provided, defaulting to Community tier");
                return LicenseValidation {
                    tier: LicenseTier::Community,
                    limits: LicenseTier::Community.limits(),
                    reason: "no license key".to_string(),
                };
            }
        };

        if key.len() > MAX_LICENSE_KEY_LEN {
            tracing::warn!("License key exceeds maximum length, defaulting to Community tier");
            return LicenseValidation {
                tier: LicenseTier::Community,
                limits: LicenseTier::Community.limits(),
                reason: "key too long".to_string(),
            };
        }

        let secret = match std::env::var("VELLAVETO_LICENSE_SECRET") {
            Ok(s) if !s.is_empty() && s.len() <= MAX_HMAC_SECRET_LEN => s,
            Ok(s) if s.is_empty() => {
                tracing::warn!("VELLAVETO_LICENSE_SECRET is empty");
                return LicenseValidation {
                    tier: LicenseTier::Community,
                    limits: LicenseTier::Community.limits(),
                    reason: "empty license secret".to_string(),
                };
            }
            _ => {
                tracing::warn!("VELLAVETO_LICENSE_SECRET not set or too long");
                return LicenseValidation {
                    tier: LicenseTier::Community,
                    limits: LicenseTier::Community.limits(),
                    reason: "no license secret".to_string(),
                };
            }
        };

        validate_license_key(&key, &secret)
    }
}

fn validate_license_key(key: &str, secret: &str) -> LicenseValidation {
    let community = || LicenseValidation {
        tier: LicenseTier::Community,
        limits: LicenseTier::Community.limits(),
        reason: "invalid license key".to_string(),
    };

    let parts: Vec<&str> = key.split('-').collect();
    if parts.len() != 4 || parts[0] != "VLV" {
        return community();
    }

    let tier = match LicenseTier::from_key_segment(parts[1]) {
        Some(t) => t,
        None => return community(),
    };

    let expiry: u64 = match parts[2].parse() {
        Ok(e) => e,
        Err(_) => return community(),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_else(|_| {
            tracing::warn!("SystemTime before UNIX_EPOCH; treating license as expired");
            u64::MAX
        });

    if now >= expiry {
        return LicenseValidation {
            tier: LicenseTier::Community,
            limits: LicenseTier::Community.limits(),
            reason: "license key expired".to_string(),
        };
    }

    let message = format!("VLV-{}-{}", parts[1], parts[2]);
    let expected_hmac = compute_hmac_sha256(secret.as_bytes(), message.as_bytes());
    let provided_hmac = parts[3].to_ascii_lowercase();

    if !constant_time_eq(expected_hmac.as_bytes(), provided_hmac.as_bytes()) {
        return community();
    }

    tracing::info!(tier = %tier, expiry, "License key validated successfully");
    LicenseValidation {
        tier,
        limits: tier.limits(),
        reason: "valid license key".to_string(),
    }
}

/// Compute HMAC-SHA256 using SHA-256 directly (no extra deps).
pub(crate) fn compute_hmac_sha256(key: &[u8], message: &[u8]) -> String {
    use sha2::Digest;
    const BLOCK_SIZE: usize = 64;

    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        k_prime[..32].copy_from_slice(&hash);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut inner_hasher = Sha256::new();
    let mut inner_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key_pad[i] = k_prime[i] ^ 0x36;
    }
    inner_hasher.update(inner_key_pad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    let mut outer_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key_pad[i] = k_prime[i] ^ 0x5c;
    }
    outer_hasher.update(outer_key_pad);
    outer_hasher.update(inner_hash);
    hex::encode(outer_hasher.finalize())
}

/// Constant-time byte comparison.
///
/// SECURITY: Uses `std::hint::black_box` to prevent the compiler from
/// optimizing the accumulator loop into an early-exit comparison.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Generate a license key for a given tier and expiry (test utility).
#[cfg(test)]
fn generate_license_key(tier: LicenseTier, expiry_epoch: u64, secret: &str) -> String {
    let tier_segment = tier.as_key_segment();
    let message = format!("VLV-{}-{}", tier_segment, expiry_epoch);
    let hmac = compute_hmac_sha256(secret.as_bytes(), message.as_bytes());
    format!("{}-{}", message, hmac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-for-unit-tests-only";

    #[test]
    fn test_generate_and_validate_pro_key() {
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 86400 * 365)
            .unwrap_or(0);
        let key = generate_license_key(LicenseTier::Pro, expiry, TEST_SECRET);
        let result = validate_license_key(&key, TEST_SECRET);
        assert_eq!(result.tier, LicenseTier::Pro);
    }

    #[test]
    fn test_generate_and_validate_all_tiers() {
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 86400 * 365)
            .unwrap_or(0);
        for tier in [
            LicenseTier::Community,
            LicenseTier::Pro,
            LicenseTier::Business,
            LicenseTier::Enterprise,
        ] {
            let key = generate_license_key(tier, expiry, TEST_SECRET);
            let result = validate_license_key(&key, TEST_SECRET);
            assert_eq!(result.tier, tier);
        }
    }

    #[test]
    fn test_expired_key_returns_community() {
        let key = generate_license_key(LicenseTier::Enterprise, 1_000_000, TEST_SECRET);
        let result = validate_license_key(&key, TEST_SECRET);
        assert_eq!(result.tier, LicenseTier::Community);
        assert_eq!(result.reason, "license key expired");
    }

    #[test]
    fn test_wrong_secret_returns_community() {
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 86400 * 365)
            .unwrap_or(0);
        let key = generate_license_key(LicenseTier::Enterprise, expiry, TEST_SECRET);
        let result = validate_license_key(&key, "wrong-secret");
        assert_eq!(result.tier, LicenseTier::Community);
    }

    #[test]
    fn test_tampered_tier_returns_community() {
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 86400 * 365)
            .unwrap_or(0);
        let key = generate_license_key(LicenseTier::Community, expiry, TEST_SECRET);
        let tampered = key.replace("VLV-COM-", "VLV-ENT-");
        let result = validate_license_key(&tampered, TEST_SECRET);
        assert_eq!(result.tier, LicenseTier::Community);
    }

    #[test]
    fn test_malformed_key_returns_community() {
        for key in [
            "",
            "not-a-key",
            "VLV",
            "VLV-PRO",
            "VLV-PRO-123",
            "VLV-UNKNOWN-123-abc",
            "XXX-PRO-123-abc",
        ] {
            let result = validate_license_key(key, TEST_SECRET);
            assert_eq!(result.tier, LicenseTier::Community);
        }
    }

    #[test]
    fn test_tier_limits() {
        assert_eq!(LicenseTier::Community.limits().max_mcp_servers, Some(5));
        assert_eq!(LicenseTier::Pro.limits().max_mcp_servers, Some(25));
        assert_eq!(LicenseTier::Business.limits().max_mcp_servers, Some(100));
        assert_eq!(LicenseTier::Enterprise.limits().max_mcp_servers, None);
    }

    #[test]
    fn test_tier_serde_roundtrip() {
        for tier in [
            LicenseTier::Community,
            LicenseTier::Pro,
            LicenseTier::Business,
            LicenseTier::Enterprise,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let parsed: LicenseTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, tier);
        }
    }

    #[test]
    fn test_hmac_sha256_known_vector() {
        let hmac = compute_hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hmac,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_tier_override_takes_precedence() {
        let config = LicensingConfig {
            license_key: Some("invalid".to_string()),
            tier_override: Some(LicenseTier::Enterprise),
        };
        let result = config.resolve();
        assert_eq!(result.tier, LicenseTier::Enterprise);
    }

    #[test]
    fn test_no_key_returns_community() {
        let config = LicensingConfig::default();
        let result = config.resolve();
        assert_eq!(result.tier, LicenseTier::Community);
    }

    // ═══════════════════════════════════════════════════
    // LicensingConfig::validate() tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_licensing_config_validate_ok() {
        let config = LicensingConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_licensing_config_validate_ok_with_key() {
        let config = LicensingConfig {
            license_key: Some("VLV-PRO-12345-abcdef".to_string()),
            tier_override: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_licensing_config_validate_oversized_key() {
        let config = LicensingConfig {
            license_key: Some("K".repeat(MAX_LICENSE_KEY_LEN + 1)),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("exceeds max"));
    }

    #[test]
    fn test_licensing_config_validate_null_byte_in_key() {
        let config = LicensingConfig {
            license_key: Some("VLV-PRO-123\x00-abc".to_string()),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_licensing_config_validate_newline_in_key() {
        let config = LicensingConfig {
            license_key: Some("VLV-PRO-123\n-abc".to_string()),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_licensing_config_validate_tab_in_key() {
        let config = LicensingConfig {
            license_key: Some("VLV\t-PRO-123-abc".to_string()),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_licensing_config_validate_c1_control_in_key() {
        let config = LicensingConfig {
            license_key: Some("VLV-PRO-\u{0085}-abc".to_string()),
            tier_override: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("control characters"));
    }

    #[test]
    fn test_licensing_config_deny_unknown_fields() {
        let json = r#"{"license_key": "test", "unknown_field": true}"#;
        let result: Result<LicensingConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_key_returns_community() {
        let key = "K".repeat(MAX_LICENSE_KEY_LEN + 1);
        let result = validate_license_key(&key, TEST_SECRET);
        assert_eq!(result.tier, LicenseTier::Community);
    }
}
