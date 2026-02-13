//! Accountability attestation signing and verification.
//!
//! Provides Ed25519 signing and verification of accountability attestations
//! that bind agents to policy compliance statements. Uses length-prefixed
//! content to prevent boundary collision attacks (same pattern as audit
//! checkpoints in `sentinel-audit/src/checkpoints.rs`).
//!
//! Uses `ed25519-dalek`, `sha2`, `hex`, `chrono`, `uuid`, and `subtle`
//! (transitive dep of ed25519-dalek, now direct for constant-time comparison).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sentinel_types::{AccountabilityAttestation, AttestationVerificationResult};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Errors from attestation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The signing key is invalid (not valid hex or wrong length).
    InvalidKey(String),
    /// Signing failed.
    SigningFailed(String),
    /// Verification failed.
    VerificationFailed(String),
    /// The attestation has expired.
    Expired,
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            AttestationError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            AttestationError::VerificationFailed(msg) => {
                write!(f, "Verification failed: {}", msg)
            }
            AttestationError::Expired => write!(f, "Attestation has expired"),
        }
    }
}

impl std::error::Error for AttestationError {}

/// Sign an accountability attestation.
///
/// Creates a new attestation with:
/// - Length-prefixed SHA-256 of canonical content
/// - Ed25519 signature using the provided signing key
/// - Unique attestation ID (UUID v4)
/// - Expiration based on `ttl_secs`
///
/// # Content Format
///
/// The signed content is a length-prefixed concatenation to prevent
/// boundary collision attacks:
///
/// ```text
/// <agent_id_len>:<agent_id><statement_len>:<statement><policy_hash_len>:<policy_hash><created_at>
/// ```
pub fn sign_attestation(
    agent_id: &str,
    did: Option<&str>,
    statement: &str,
    policy_hash: &str,
    signing_key_hex: &str,
    ttl_secs: u64,
) -> Result<AccountabilityAttestation, AttestationError> {
    // Parse signing key
    let key_bytes = hex::decode(signing_key_hex)
        .map_err(|e| AttestationError::InvalidKey(format!("hex decode failed: {}", e)))?;
    if key_bytes.len() != 32 {
        return Err(AttestationError::InvalidKey(format!(
            "expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let signing_key = SigningKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::InvalidKey("invalid key length".to_string()))?,
    );
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());

    let now = chrono::Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();

    // Build length-prefixed canonical content
    let canonical = build_canonical_content(agent_id, statement, policy_hash, &created_at);

    // SHA-256 hash the canonical content
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let content_hash = hasher.finalize();

    // Ed25519 sign
    let signature = signing_key.sign(&content_hash);
    let signature_hex = hex::encode(signature.to_bytes());

    Ok(AccountabilityAttestation {
        attestation_id: Uuid::new_v4().to_string(),
        agent_id: agent_id.to_string(),
        did: did.map(|s| s.to_string()),
        statement: statement.to_string(),
        policy_hash: policy_hash.to_string(),
        signature: signature_hex,
        algorithm: "Ed25519".to_string(),
        public_key: public_key_hex,
        created_at,
        expires_at,
        verified: false,
    })
}

/// Verify an accountability attestation.
///
/// Checks:
/// 1. Ed25519 signature over length-prefixed canonical content
/// 2. Expiration (using `now` parameter)
/// 3. Public key matches expected key (if provided)
pub fn verify_attestation(
    attestation: &AccountabilityAttestation,
    expected_public_key_hex: Option<&str>,
    now: &chrono::DateTime<chrono::Utc>,
) -> Result<AttestationVerificationResult, AttestationError> {
    // Parse public key from attestation
    let pub_key_bytes = hex::decode(&attestation.public_key).map_err(|e| {
        AttestationError::InvalidKey(format!("public key hex decode failed: {}", e))
    })?;
    let verifying_key =
        VerifyingKey::from_bytes(pub_key_bytes.as_slice().try_into().map_err(|_| {
            AttestationError::InvalidKey(format!(
                "public key must be 32 bytes, got {}",
                pub_key_bytes.len()
            ))
        })?)
        .map_err(|e| AttestationError::VerificationFailed(format!("invalid public key: {}", e)))?;

    // Parse signature
    let sig_bytes = hex::decode(&attestation.signature).map_err(|e| {
        AttestationError::VerificationFailed(format!("signature hex decode failed: {}", e))
    })?;
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| {
        AttestationError::VerificationFailed(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ))
    })?);

    // Rebuild canonical content and hash
    let canonical = build_canonical_content(
        &attestation.agent_id,
        &attestation.statement,
        &attestation.policy_hash,
        &attestation.created_at,
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let content_hash = hasher.finalize();

    // Verify signature
    let signature_valid = verifying_key.verify(&content_hash, &signature).is_ok();

    // Check expiry
    let expired = chrono::DateTime::parse_from_rfc3339(&attestation.expires_at)
        .map(|expires| now >= &expires.with_timezone(&chrono::Utc))
        .unwrap_or(true); // Fail-closed: unparseable expiry = expired

    // Check key match (constant-time to prevent timing side-channel)
    let key_matches_agent = match expected_public_key_hex {
        Some(expected) => {
            let a = attestation.public_key.to_ascii_lowercase();
            let b = expected.to_ascii_lowercase();
            a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
        }
        None => true, // No expected key to compare against
    };

    let message = if !signature_valid {
        "Invalid signature".to_string()
    } else if expired {
        "Attestation has expired".to_string()
    } else if !key_matches_agent {
        "Public key does not match agent's registered key".to_string()
    } else {
        "Attestation is valid".to_string()
    };

    Ok(AttestationVerificationResult {
        signature_valid,
        expired,
        key_matches_agent,
        message,
    })
}

/// Build length-prefixed canonical content for signing/verification.
///
/// Format: `<agent_id_len>:<agent_id><statement_len>:<statement><hash_len>:<policy_hash><created_at>`
///
/// Length prefixing prevents boundary collision: without it, `agent_id="ab" + statement="cd"`
/// would hash identically to `agent_id="abc" + statement="d"`.
fn build_canonical_content(
    agent_id: &str,
    statement: &str,
    policy_hash: &str,
    created_at: &str,
) -> String {
    format!(
        "{}:{}{}:{}{}:{}{}",
        agent_id.len(),
        agent_id,
        statement.len(),
        statement,
        policy_hash.len(),
        policy_hash,
        created_at
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn generate_test_keypair() -> (String, String) {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (
            hex::encode(signing_key.to_bytes()),
            hex::encode(verifying_key.as_bytes()),
        )
    }

    #[test]
    fn test_sign_and_verify_attestation() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let attestation = sign_attestation(
            "agent-1",
            Some("did:plc:ewvi7nxsareczkwkx5pz6q6e"),
            "I accept the data handling policy",
            "sha256:abcdef1234567890",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        assert_eq!(attestation.agent_id, "agent-1");
        assert_eq!(attestation.algorithm, "Ed25519");
        assert!(!attestation.verified);

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(result.is_valid());
        assert!(result.signature_valid);
        assert!(!result.expired);
        assert!(result.key_matches_agent);
    }

    #[test]
    fn test_verify_detects_tampered_statement() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "Original statement",
            "hash123",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Tamper with statement
        attestation.statement = "Tampered statement".to_string();

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(!result.signature_valid);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_detects_tampered_agent_id() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "Policy statement",
            "hash123",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        attestation.agent_id = "agent-evil".to_string();

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(!result.signature_valid);
    }

    #[test]
    fn test_verify_detects_expired() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            1, // 1 second TTL
        )
        .expect("sign");

        // Check with a time far in the future
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let result =
            verify_attestation(&attestation, Some(&public_key_hex), &future).expect("verify");
        assert!(result.expired);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_detects_wrong_key() {
        let (signing_key_hex, _) = generate_test_keypair();
        let wrong_key = hex::encode([99u8; 32]); // Wrong key

        let attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&wrong_key), &now).expect("verify");
        assert!(!result.key_matches_agent);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_sign_invalid_key_hex() {
        let result = sign_attestation("agent", None, "stmt", "hash", "not-hex!", 86400);
        assert!(matches!(result, Err(AttestationError::InvalidKey(_))));
    }

    #[test]
    fn test_sign_invalid_key_length() {
        let result = sign_attestation("agent", None, "stmt", "hash", "abcd", 86400);
        assert!(matches!(result, Err(AttestationError::InvalidKey(_))));
    }

    #[test]
    fn test_boundary_collision_prevention() {
        let (signing_key_hex, _) = generate_test_keypair();

        // These two should produce different attestations due to length prefixing
        let att1 =
            sign_attestation("ab", None, "cd", "hash", &signing_key_hex, 86400).expect("sign 1");
        let att2 =
            sign_attestation("abc", None, "d", "hash", &signing_key_hex, 86400).expect("sign 2");

        assert_ne!(att1.signature, att2.signature);
    }

    #[test]
    fn test_verify_no_expected_key() {
        let (signing_key_hex, _) = generate_test_keypair();

        let attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        let now = chrono::Utc::now();
        // No expected key -> key_matches_agent is true
        let result = verify_attestation(&attestation, None, &now).expect("verify");
        assert!(result.key_matches_agent);
        assert!(result.is_valid());
    }

    #[test]
    fn test_attestation_unique_ids() {
        let (signing_key_hex, _) = generate_test_keypair();

        let att1 =
            sign_attestation("agent", None, "stmt", "hash", &signing_key_hex, 86400).expect("1");
        let att2 =
            sign_attestation("agent", None, "stmt", "hash", &signing_key_hex, 86400).expect("2");

        assert_ne!(att1.attestation_id, att2.attestation_id);
    }
}
