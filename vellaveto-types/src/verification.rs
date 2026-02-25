//! Verification tier and accountability attestation types.
//!
//! Provides an ordered verification tier system and accountability attestation
//! types for binding agents to policy compliance statements.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Ordered verification tier for agent identity.
///
/// Each tier represents a progressively stronger form of identity verification.
/// Tiers are ordered: `Unverified < EmailVerified < PhoneVerified < DidVerified < FullyVerified`.
///
/// # Policy Usage
///
/// Policies can require a minimum verification tier via the `min_verification_tier`
/// context condition. Agents below the required tier are denied (fail-closed).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum VerificationTier {
    /// No verification performed (default).
    #[default]
    Unverified = 0,
    /// Email address verified.
    EmailVerified = 1,
    /// Phone number verified.
    PhoneVerified = 2,
    /// DID:PLC verified (decentralized identity).
    DidVerified = 3,
    /// All verification methods completed.
    FullyVerified = 4,
}

impl VerificationTier {
    /// Returns the numeric level (0-4) of this tier.
    pub fn level(&self) -> u8 {
        *self as u8
    }

    /// Construct a tier from its numeric level.
    ///
    /// Returns `None` for levels > 4.
    pub fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(Self::Unverified),
            1 => Some(Self::EmailVerified),
            2 => Some(Self::PhoneVerified),
            3 => Some(Self::DidVerified),
            4 => Some(Self::FullyVerified),
            _ => None,
        }
    }

    /// Construct a tier from its string name.
    ///
    /// Accepts both snake_case and lowercase-no-separator forms.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "unverified" => Some(Self::Unverified),
            "email_verified" | "emailverified" => Some(Self::EmailVerified),
            "phone_verified" | "phoneverified" => Some(Self::PhoneVerified),
            "did_verified" | "didverified" => Some(Self::DidVerified),
            "fully_verified" | "fullyverified" => Some(Self::FullyVerified),
            _ => None,
        }
    }

    /// Returns `true` if this tier meets or exceeds the required minimum tier.
    pub fn meets_minimum(&self, required: VerificationTier) -> bool {
        *self >= required
    }
}

impl fmt::Display for VerificationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unverified => write!(f, "unverified"),
            Self::EmailVerified => write!(f, "email_verified"),
            Self::PhoneVerified => write!(f, "phone_verified"),
            Self::DidVerified => write!(f, "did_verified"),
            Self::FullyVerified => write!(f, "fully_verified"),
        }
    }
}

/// A signed accountability attestation binding an agent to a policy compliance statement.
///
/// Attestations provide cryptographic proof that an agent acknowledged and agreed
/// to specific policies at a specific point in time. They use Ed25519 signatures
/// over length-prefixed content to prevent boundary collision attacks.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityAttestation {
    /// Unique attestation identifier (UUID).
    pub attestation_id: String,
    /// Agent identity that created this attestation.
    pub agent_id: String,
    /// DID:PLC identifier of the agent (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Human-readable policy compliance statement being attested to.
    pub statement: String,
    /// SHA-256 hash of the policy document being attested (hex-encoded).
    pub policy_hash: String,
    /// Ed25519 signature over the attestation content (hex-encoded).
    pub signature: String,
    /// Signing algorithm used (e.g., "Ed25519").
    pub algorithm: String,
    /// Public key of the signer (hex-encoded).
    pub public_key: String,
    /// ISO 8601 timestamp when the attestation was created.
    pub created_at: String,
    /// ISO 8601 timestamp when the attestation expires.
    pub expires_at: String,
    /// Whether this attestation has been verified.
    #[serde(default)]
    pub verified: bool,
}

/// SECURITY (FIND-R53-002): Custom Debug redacts `signature` and `public_key`
/// to prevent secret leakage in logs/debug output.
impl fmt::Debug for AccountabilityAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountabilityAttestation")
            .field("attestation_id", &self.attestation_id)
            .field("agent_id", &self.agent_id)
            .field("did", &self.did)
            .field("statement", &self.statement)
            .field("policy_hash", &self.policy_hash)
            .field("signature", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("public_key", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("verified", &self.verified)
            .finish()
    }
}

impl AccountabilityAttestation {
    /// Maximum length for `signature` field (hex-encoded Ed25519).
    const MAX_SIGNATURE_LEN: usize = 512;
    /// Maximum length for `public_key` field (hex-encoded).
    const MAX_PUBLIC_KEY_LEN: usize = 512;
    /// Maximum length for `policy_hash` field (hex-encoded SHA-256).
    const MAX_POLICY_HASH_LEN: usize = 128;
    /// Maximum length for `statement` field.
    const MAX_STATEMENT_LEN: usize = 4096;
    /// Maximum length for `attestation_id` and `agent_id` fields.
    const MAX_ID_LEN: usize = 256;
    /// Maximum length for `algorithm` field.
    const MAX_ALGORITHM_LEN: usize = 64;
    /// Maximum length for timestamp fields (`created_at`, `expires_at`).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for optional `did` field (DID:PLC identifier).
    const MAX_DID_LEN: usize = 256;

    /// Check if a string is valid hex-encoded data (non-empty, even length, all hex chars).
    fn is_valid_hex(s: &str) -> bool {
        !s.is_empty() && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Validate structural bounds on string fields.
    ///
    /// SECURITY (FIND-R71-003): Prevents memory exhaustion via oversized attestation payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.attestation_id.len() > Self::MAX_ID_LEN {
            return Err(format!(
                "AccountabilityAttestation attestation_id length {} exceeds max {}",
                self.attestation_id.len(),
                Self::MAX_ID_LEN,
            ));
        }
        if self.agent_id.len() > Self::MAX_ID_LEN {
            return Err(format!(
                "AccountabilityAttestation agent_id length {} exceeds max {}",
                self.agent_id.len(),
                Self::MAX_ID_LEN,
            ));
        }
        // SECURITY (FIND-R215-008): Validate optional `did` field length and
        // control/format characters to prevent oversized or injection-prone DIDs.
        if let Some(ref did) = self.did {
            if did.len() > Self::MAX_DID_LEN {
                return Err(format!(
                    "AccountabilityAttestation did length {} exceeds max {}",
                    did.len(),
                    Self::MAX_DID_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(did) {
                return Err(
                    "AccountabilityAttestation did contains control or format characters"
                        .to_string(),
                );
            }
        }
        if self.statement.len() > Self::MAX_STATEMENT_LEN {
            return Err(format!(
                "AccountabilityAttestation statement length {} exceeds max {}",
                self.statement.len(),
                Self::MAX_STATEMENT_LEN,
            ));
        }
        if self.policy_hash.len() > Self::MAX_POLICY_HASH_LEN {
            return Err(format!(
                "AccountabilityAttestation policy_hash length {} exceeds max {}",
                self.policy_hash.len(),
                Self::MAX_POLICY_HASH_LEN,
            ));
        }
        // SECURITY (FIND-R215-009): Validate hex encoding on crypto fields.
        // policy_hash is documented as hex-encoded SHA-256.
        if !Self::is_valid_hex(&self.policy_hash) {
            return Err(
                "AccountabilityAttestation policy_hash must be valid hex-encoded data (non-empty, even length, hex chars only)"
                    .to_string(),
            );
        }
        if self.signature.len() > Self::MAX_SIGNATURE_LEN {
            return Err(format!(
                "AccountabilityAttestation signature length {} exceeds max {}",
                self.signature.len(),
                Self::MAX_SIGNATURE_LEN,
            ));
        }
        // SECURITY (FIND-R215-009): signature is documented as hex-encoded Ed25519.
        if !Self::is_valid_hex(&self.signature) {
            return Err(
                "AccountabilityAttestation signature must be valid hex-encoded data (non-empty, even length, hex chars only)"
                    .to_string(),
            );
        }
        if self.algorithm.len() > Self::MAX_ALGORITHM_LEN {
            return Err(format!(
                "AccountabilityAttestation algorithm length {} exceeds max {}",
                self.algorithm.len(),
                Self::MAX_ALGORITHM_LEN,
            ));
        }
        if self.public_key.len() > Self::MAX_PUBLIC_KEY_LEN {
            return Err(format!(
                "AccountabilityAttestation public_key length {} exceeds max {}",
                self.public_key.len(),
                Self::MAX_PUBLIC_KEY_LEN,
            ));
        }
        // SECURITY (FIND-R215-009): public_key is documented as hex-encoded.
        if !Self::is_valid_hex(&self.public_key) {
            return Err(
                "AccountabilityAttestation public_key must be valid hex-encoded data (non-empty, even length, hex chars only)"
                    .to_string(),
            );
        }
        if self.created_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "AccountabilityAttestation created_at length {} exceeds max {}",
                self.created_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if self.expires_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "AccountabilityAttestation expires_at length {} exceeds max {}",
                self.expires_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        // SECURITY (FIND-R157-004): Reject control/format chars in timestamp fields
        // to prevent log injection via crafted ISO 8601 strings.
        if crate::core::has_dangerous_chars(&self.created_at) {
            return Err(
                "AccountabilityAttestation created_at contains control or format characters"
                    .to_string(),
            );
        }
        if crate::core::has_dangerous_chars(&self.expires_at) {
            return Err(
                "AccountabilityAttestation expires_at contains control or format characters"
                    .to_string(),
            );
        }
        // SECURITY (FIND-R113-009): Validate control/format chars on non-hex string fields.
        if crate::core::has_dangerous_chars(&self.attestation_id)
        {
            return Err(
                "AccountabilityAttestation attestation_id contains control or format characters"
                    .to_string(),
            );
        }
        if crate::core::has_dangerous_chars(&self.agent_id)
        {
            return Err(
                "AccountabilityAttestation agent_id contains control or format characters"
                    .to_string(),
            );
        }
        if crate::core::has_dangerous_chars(&self.statement)
        {
            return Err(
                "AccountabilityAttestation statement contains control or format characters"
                    .to_string(),
            );
        }
        if crate::core::has_dangerous_chars(&self.algorithm)
        {
            return Err(
                "AccountabilityAttestation algorithm contains control or format characters"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Result of verifying an accountability attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AttestationVerificationResult {
    /// Whether the cryptographic signature is valid.
    pub signature_valid: bool,
    /// Whether the attestation has expired.
    pub expired: bool,
    /// Whether the signing key matches the agent's registered key.
    pub key_matches_agent: bool,
    /// Human-readable message describing the verification result.
    pub message: String,
}

impl AttestationVerificationResult {
    /// Maximum length for `message` field.
    const MAX_MESSAGE_LEN: usize = 4096;

    /// Returns `true` if the attestation is fully valid:
    /// signature is valid, not expired, and key matches the agent.
    pub fn is_valid(&self) -> bool {
        self.signature_valid && !self.expired && self.key_matches_agent
    }

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R216-015): Prevents oversized or injection-prone message
    /// strings from untrusted deserialized payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.message.len() > Self::MAX_MESSAGE_LEN {
            return Err(format!(
                "AttestationVerificationResult message length {} exceeds max {}",
                self.message.len(),
                Self::MAX_MESSAGE_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.message) {
            return Err(
                "AttestationVerificationResult message contains control or format characters"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_tier_ordering() {
        assert!(VerificationTier::Unverified < VerificationTier::EmailVerified);
        assert!(VerificationTier::EmailVerified < VerificationTier::PhoneVerified);
        assert!(VerificationTier::PhoneVerified < VerificationTier::DidVerified);
        assert!(VerificationTier::DidVerified < VerificationTier::FullyVerified);
    }

    #[test]
    fn test_verification_tier_level() {
        assert_eq!(VerificationTier::Unverified.level(), 0);
        assert_eq!(VerificationTier::EmailVerified.level(), 1);
        assert_eq!(VerificationTier::PhoneVerified.level(), 2);
        assert_eq!(VerificationTier::DidVerified.level(), 3);
        assert_eq!(VerificationTier::FullyVerified.level(), 4);
    }

    #[test]
    fn test_verification_tier_from_level() {
        assert_eq!(
            VerificationTier::from_level(0),
            Some(VerificationTier::Unverified)
        );
        assert_eq!(
            VerificationTier::from_level(3),
            Some(VerificationTier::DidVerified)
        );
        assert_eq!(
            VerificationTier::from_level(4),
            Some(VerificationTier::FullyVerified)
        );
        assert_eq!(VerificationTier::from_level(5), None);
        assert_eq!(VerificationTier::from_level(255), None);
    }

    #[test]
    fn test_verification_tier_from_name() {
        assert_eq!(
            VerificationTier::from_name("unverified"),
            Some(VerificationTier::Unverified)
        );
        assert_eq!(
            VerificationTier::from_name("email_verified"),
            Some(VerificationTier::EmailVerified)
        );
        assert_eq!(
            VerificationTier::from_name("EmailVerified"),
            Some(VerificationTier::EmailVerified)
        );
        assert_eq!(
            VerificationTier::from_name("did_verified"),
            Some(VerificationTier::DidVerified)
        );
        assert_eq!(
            VerificationTier::from_name("FULLY_VERIFIED"),
            Some(VerificationTier::FullyVerified)
        );
        assert_eq!(VerificationTier::from_name("invalid"), None);
    }

    #[test]
    fn test_verification_tier_meets_minimum() {
        assert!(VerificationTier::FullyVerified.meets_minimum(VerificationTier::Unverified));
        assert!(VerificationTier::DidVerified.meets_minimum(VerificationTier::DidVerified));
        assert!(!VerificationTier::Unverified.meets_minimum(VerificationTier::EmailVerified));
        assert!(!VerificationTier::PhoneVerified.meets_minimum(VerificationTier::DidVerified));
    }

    #[test]
    fn test_verification_tier_display() {
        assert_eq!(format!("{}", VerificationTier::Unverified), "unverified");
        assert_eq!(
            format!("{}", VerificationTier::EmailVerified),
            "email_verified"
        );
        assert_eq!(format!("{}", VerificationTier::DidVerified), "did_verified");
    }

    #[test]
    fn test_verification_tier_default() {
        let tier: VerificationTier = Default::default();
        assert_eq!(tier, VerificationTier::Unverified);
    }

    #[test]
    fn test_verification_tier_serde_roundtrip() {
        for tier in [
            VerificationTier::Unverified,
            VerificationTier::EmailVerified,
            VerificationTier::PhoneVerified,
            VerificationTier::DidVerified,
            VerificationTier::FullyVerified,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let deserialized: VerificationTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(tier, deserialized);
        }
    }

    #[test]
    fn test_accountability_attestation_serde() {
        let attestation = AccountabilityAttestation {
            attestation_id: "att-123".to_string(),
            agent_id: "agent-1".to_string(),
            did: Some("did:plc:ewvi7nxsareczkwkx5pz6q6e".to_string()),
            statement: "I agree to the data handling policy".to_string(),
            policy_hash: "abcdef1234567890".to_string(),
            signature: "deadbeef".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key: "cafebabe".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-12-31T23:59:59Z".to_string(),
            verified: false,
        };
        let json = serde_json::to_string(&attestation).expect("serialize");
        let deserialized: AccountabilityAttestation =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_attestation_without_did() {
        let attestation = AccountabilityAttestation {
            attestation_id: "att-456".to_string(),
            agent_id: "agent-2".to_string(),
            did: None,
            statement: "Policy compliance".to_string(),
            policy_hash: "1234".to_string(),
            signature: "sig".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key: "key".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-12-31T23:59:59Z".to_string(),
            verified: false,
        };
        let json = serde_json::to_string(&attestation).expect("serialize");
        // did should be omitted when None
        assert!(!json.contains("\"did\""));
    }

    #[test]
    fn test_attestation_verification_result_is_valid() {
        let valid = AttestationVerificationResult {
            signature_valid: true,
            expired: false,
            key_matches_agent: true,
            message: "Valid".to_string(),
        };
        assert!(valid.is_valid());

        let expired = AttestationVerificationResult {
            signature_valid: true,
            expired: true,
            key_matches_agent: true,
            message: "Expired".to_string(),
        };
        assert!(!expired.is_valid());

        let bad_sig = AttestationVerificationResult {
            signature_valid: false,
            expired: false,
            key_matches_agent: true,
            message: "Bad signature".to_string(),
        };
        assert!(!bad_sig.is_valid());

        let wrong_key = AttestationVerificationResult {
            signature_valid: true,
            expired: false,
            key_matches_agent: false,
            message: "Key mismatch".to_string(),
        };
        assert!(!wrong_key.is_valid());
    }

    // ════════════════════════════════════════════════════════
    // FIND-R215-008: AccountabilityAttestation did validation
    // ════════════════════════════════════════════════════════

    fn make_valid_attestation() -> AccountabilityAttestation {
        AccountabilityAttestation {
            attestation_id: "att-001".to_string(),
            agent_id: "agent-1".to_string(),
            did: None,
            statement: "I agree to the policy".to_string(),
            policy_hash: "abcdef1234567890".to_string(),
            signature: "deadbeef".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key: "cafebabe".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-12-31T23:59:59Z".to_string(),
            verified: false,
        }
    }

    #[test]
    fn test_r215_008_did_validation_too_long() {
        let mut att = make_valid_attestation();
        att.did = Some("x".repeat(257));
        let err = att.validate().unwrap_err();
        assert!(
            err.contains("did length"),
            "Expected did length error, got: {err}"
        );
    }

    #[test]
    fn test_r215_008_did_validation_dangerous_chars() {
        let mut att = make_valid_attestation();
        att.did = Some("did:plc:\x00evil".to_string());
        let err = att.validate().unwrap_err();
        assert!(
            err.contains("did contains control"),
            "Expected control char error, got: {err}"
        );
    }

    #[test]
    fn test_r215_008_did_validation_valid() {
        let mut att = make_valid_attestation();
        att.did = Some("did:plc:ewvi7nxsareczkwkx5pz6q6e".to_string());
        assert!(att.validate().is_ok());
    }

    // ════════════════════════════════════════════════════════
    // FIND-R215-009: Hex validation on crypto fields
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_r215_009_policy_hash_not_hex() {
        let mut att = make_valid_attestation();
        att.policy_hash = "not_hex_value!".to_string();
        let err = att.validate().unwrap_err();
        assert!(
            err.contains("policy_hash must be valid hex"),
            "Expected hex error, got: {err}"
        );
    }

    #[test]
    fn test_r215_009_policy_hash_odd_length() {
        let mut att = make_valid_attestation();
        att.policy_hash = "abc".to_string(); // odd length
        let err = att.validate().unwrap_err();
        assert!(
            err.contains("policy_hash must be valid hex"),
            "Expected hex error for odd length, got: {err}"
        );
    }

    #[test]
    fn test_r215_009_policy_hash_empty() {
        let mut att = make_valid_attestation();
        att.policy_hash = "".to_string();
        let err = att.validate().unwrap_err();
        assert!(
            err.contains("policy_hash must be valid hex"),
            "Expected hex error for empty, got: {err}"
        );
    }

    #[test]
    fn test_r215_009_signature_not_hex() {
        let mut att = make_valid_attestation();
        att.signature = "not-hex".to_string();
        let err = att.validate().unwrap_err();
        assert!(
            err.contains("signature must be valid hex"),
            "Expected hex error, got: {err}"
        );
    }

    #[test]
    fn test_r215_009_public_key_not_hex() {
        let mut att = make_valid_attestation();
        att.public_key = "key!@#".to_string();
        let err = att.validate().unwrap_err();
        assert!(
            err.contains("public_key must be valid hex"),
            "Expected hex error, got: {err}"
        );
    }

    #[test]
    fn test_r215_009_valid_hex_fields() {
        let att = make_valid_attestation();
        assert!(att.validate().is_ok(), "Valid hex fields should pass");
    }
}
