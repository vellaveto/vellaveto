//! ETDI Signature Verification and Creation.
//!
//! Implements Ed25519 signature verification for tool definitions, with optional
//! ECDSA P-256 support. Tool providers sign the canonical JSON representation of
//! tool definitions, and Vellaveto verifies signatures before allowing registration.
//!
//! # Security
//!
//! - Signatures are verified against the canonical JSON (RFC 8785) of tool definitions
//! - Public key fingerprints use SHA-256 for trusted signer identification
//! - Expiration timestamps are enforced in UTC

use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use vellaveto_config::AllowedSignersConfig;
use vellaveto_types::{SignatureAlgorithm, SignatureVerification, ToolSignature};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors from ETDI operations.
#[derive(Error, Debug)]
pub enum EtdiError {
    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    #[error("Tool hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// SECURITY (FIND-027): HMAC initialization failure (fail-closed).
    #[error("HMAC initialization failed")]
    HmacInit,
}

/// Compute the canonical hash of a tool definition for signing.
///
/// Uses RFC 8785 (JSON Canonicalization Scheme) for deterministic serialization,
/// then SHA-256 for hashing. The hash is returned as a hex string.
pub fn compute_tool_hash(tool_name: &str, schema: &Value) -> String {
    let mut hasher = Sha256::new();

    // Hash tool name
    hasher.update(tool_name.as_bytes());
    hasher.update(b"|"); // Separator

    // Canonicalize and hash schema
    let canonical = serde_json_canonicalizer::to_string(schema)
        .unwrap_or_else(|_| serde_json::to_string(schema).unwrap_or_default());
    hasher.update(canonical.as_bytes());

    hex::encode(hasher.finalize())
}

/// Compute the SHA-256 fingerprint of a public key (hex-encoded).
pub fn compute_key_fingerprint(public_key_hex: &str) -> Result<String, EtdiError> {
    let key_bytes = hex::decode(public_key_hex)?;
    let mut hasher = Sha256::new();
    hasher.update(&key_bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Verifies signatures on tool definitions.
pub struct ToolSignatureVerifier {
    allowed_signers: AllowedSignersConfig,
}

impl ToolSignatureVerifier {
    /// Create a new verifier with the given allowed signers configuration.
    pub fn new(allowed_signers: AllowedSignersConfig) -> Self {
        Self { allowed_signers }
    }

    /// Verify a tool signature against its definition.
    ///
    /// # Returns
    ///
    /// A [`SignatureVerification`] indicating:
    /// - `valid`: Whether the cryptographic signature is correct
    /// - `signer_trusted`: Whether the signer is in the allowed list
    /// - `expired`: Whether the signature has expired
    pub fn verify_tool_signature(
        &self,
        tool_name: &str,
        schema: &Value,
        signature: &ToolSignature,
    ) -> SignatureVerification {
        // Compute expected hash
        let tool_hash = compute_tool_hash(tool_name, schema);

        // Verify based on algorithm
        let verification_result = match signature.algorithm {
            SignatureAlgorithm::Ed25519 => {
                self.verify_ed25519(&tool_hash, &signature.signature, &signature.public_key)
            }
            SignatureAlgorithm::EcdsaP256 => {
                // P-256 not implemented yet - fail closed
                Err(EtdiError::UnsupportedAlgorithm("ecdsa_p256".to_string()))
            }
        };

        match verification_result {
            Ok(()) => {
                // Signature valid, check trust and expiration
                let signer_trusted = self.is_signer_trusted(signature);
                let expired = self.is_signature_expired(signature);

                let message = if !signer_trusted {
                    "Signature valid but signer not trusted".to_string()
                } else if expired {
                    "Signature valid but expired".to_string()
                } else {
                    "Signature verified successfully".to_string()
                };

                SignatureVerification {
                    valid: true,
                    signer_trusted,
                    expired,
                    message,
                }
            }
            Err(e) => SignatureVerification {
                valid: false,
                signer_trusted: false,
                expired: false,
                message: format!("Verification failed: {}", e),
            },
        }
    }

    /// Verify an Ed25519 signature.
    fn verify_ed25519(
        &self,
        message: &str,
        signature_hex: &str,
        public_key_hex: &str,
    ) -> Result<(), EtdiError> {
        let sig_bytes = hex::decode(signature_hex)?;
        let key_bytes = hex::decode(public_key_hex)?;

        if key_bytes.len() != 32 {
            return Err(EtdiError::InvalidPublicKey(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        if sig_bytes.len() != 64 {
            return Err(EtdiError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                sig_bytes.len()
            )));
        }

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| EtdiError::InvalidPublicKey("Failed to convert to array".to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| EtdiError::InvalidPublicKey(e.to_string()))?;

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| EtdiError::InvalidSignature("Failed to convert to array".to_string()))?;
        let signature = Signature::from_bytes(&sig_array);

        verifying_key
            .verify(message.as_bytes(), &signature)
            .map_err(|e| EtdiError::VerificationFailed(e.to_string()))
    }

    /// Check if the signer is trusted.
    fn is_signer_trusted(&self, signature: &ToolSignature) -> bool {
        // Check fingerprint
        if let Some(ref fp) = signature.key_fingerprint {
            if self.allowed_signers.is_fingerprint_trusted(fp) {
                return true;
            }
        }

        // Compute fingerprint if not provided and check
        if let Ok(fp) = compute_key_fingerprint(&signature.public_key) {
            if self.allowed_signers.is_fingerprint_trusted(&fp) {
                return true;
            }
        }

        // Check SPIFFE ID
        if let Some(ref spiffe_id) = signature.signer_spiffe_id {
            if self.allowed_signers.is_spiffe_trusted(spiffe_id) {
                return true;
            }
        }

        // No trust configured = no signers trusted
        false
    }

    /// Check if the signature has expired.
    fn is_signature_expired(&self, signature: &ToolSignature) -> bool {
        let Some(ref expires_at) = signature.expires_at else {
            return false; // No expiration set
        };

        let now = Utc::now().to_rfc3339();
        now >= *expires_at
    }
}

/// Creates signatures for tool definitions.
///
/// Used by the CLI to sign tool definitions before publishing.
pub struct ToolSigner {
    signing_key: SigningKey,
    public_key_hex: String,
    fingerprint: String,
    signer_identity: Option<String>,
}

impl ToolSigner {
    /// Create a new signer from a signing key.
    pub fn new(signing_key: SigningKey, signer_identity: Option<String>) -> Self {
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.as_bytes());
        let fingerprint = compute_key_fingerprint(&public_key_hex).unwrap_or_default();

        Self {
            signing_key,
            public_key_hex,
            fingerprint,
            signer_identity,
        }
    }

    /// Generate a new random signing key.
    pub fn generate() -> Result<Self, EtdiError> {
        Self::generate_with_identity(None)
    }

    /// Generate a new random signing key with an optional signer identity (e.g., SPIFFE ID).
    pub fn generate_with_identity(signer_identity: Option<String>) -> Result<Self, EtdiError> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        Ok(Self::new(signing_key, signer_identity))
    }

    /// Create a signer from a hex-encoded private key.
    pub fn from_private_key_hex(
        key_hex: &str,
        signer_identity: Option<String>,
    ) -> Result<Self, EtdiError> {
        let key_bytes = hex::decode(key_hex)?;
        if key_bytes.len() != 32 {
            return Err(EtdiError::InvalidPublicKey(format!(
                "Ed25519 private key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| EtdiError::InvalidPublicKey("Failed to convert to array".to_string()))?;
        let signing_key = SigningKey::from_bytes(&key_array);
        Ok(Self::new(signing_key, signer_identity))
    }

    /// Get the hex-encoded public key.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Get the hex-encoded private key (for export).
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Get the public key fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Sign a tool definition.
    pub fn sign_tool(
        &self,
        tool_name: &str,
        schema: &Value,
        expires_in_days: Option<u32>,
    ) -> ToolSignature {
        let tool_hash = compute_tool_hash(tool_name, schema);
        let signature = self.signing_key.sign(tool_hash.as_bytes());

        let now = Utc::now();
        let expires_at = expires_in_days
            .map(|days| (now + chrono::Duration::days(i64::from(days))).to_rfc3339());

        ToolSignature {
            signature_id: format!("sig-{}", uuid::Uuid::new_v4()),
            signature: hex::encode(signature.to_bytes()),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: self.public_key_hex.clone(),
            key_fingerprint: Some(self.fingerprint.clone()),
            signed_at: now.to_rfc3339(),
            expires_at,
            signer_spiffe_id: self.signer_identity.clone(),
            rekor_entry: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compute_tool_hash() {
        let hash1 = compute_tool_hash("my_tool", &json!({"type": "object"}));
        let hash2 = compute_tool_hash("my_tool", &json!({"type": "object"}));
        assert_eq!(hash1, hash2);

        let hash3 = compute_tool_hash("other_tool", &json!({"type": "object"}));
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_compute_tool_hash_canonical() {
        // Order of keys shouldn't matter
        let hash1 = compute_tool_hash("tool", &json!({"a": 1, "b": 2}));
        let hash2 = compute_tool_hash("tool", &json!({"b": 2, "a": 1}));
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_tool_signer_generate_and_sign() {
        let signer = ToolSigner::generate().unwrap();
        let schema = json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let signature = signer.sign_tool("read_file", &schema, Some(365));

        assert!(!signature.signature.is_empty());
        assert!(!signature.public_key.is_empty());
        assert!(signature.key_fingerprint.is_some());
        assert!(signature.expires_at.is_some());
    }

    #[test]
    fn test_signature_verification_valid() {
        let signer = ToolSigner::generate().unwrap();
        let schema = json!({"type": "object"});
        let signature = signer.sign_tool("test_tool", &schema, None);

        // Trust the signer's fingerprint
        let allowed = AllowedSignersConfig {
            fingerprints: vec![signer.fingerprint().to_string()],
            spiffe_ids: vec![],
        };
        let verifier = ToolSignatureVerifier::new(allowed);

        let result = verifier.verify_tool_signature("test_tool", &schema, &signature);
        assert!(result.valid);
        assert!(result.signer_trusted);
        assert!(!result.expired);
    }

    #[test]
    fn test_signature_verification_untrusted_signer() {
        let signer = ToolSigner::generate().unwrap();
        let schema = json!({"type": "object"});
        let signature = signer.sign_tool("test_tool", &schema, None);

        // Empty allowed signers - no one is trusted
        let verifier = ToolSignatureVerifier::new(AllowedSignersConfig::default());

        let result = verifier.verify_tool_signature("test_tool", &schema, &signature);
        assert!(result.valid); // Signature is cryptographically valid
        assert!(!result.signer_trusted); // But signer is not trusted
    }

    #[test]
    fn test_signature_verification_wrong_schema() {
        let signer = ToolSigner::generate().unwrap();
        let schema = json!({"type": "object"});
        let signature = signer.sign_tool("test_tool", &schema, None);

        let allowed = AllowedSignersConfig {
            fingerprints: vec![signer.fingerprint().to_string()],
            spiffe_ids: vec![],
        };
        let verifier = ToolSignatureVerifier::new(allowed);

        // Try to verify with a different schema
        let different_schema = json!({"type": "string"});
        let result = verifier.verify_tool_signature("test_tool", &different_schema, &signature);
        assert!(!result.valid);
    }

    #[test]
    fn test_signature_verification_wrong_tool_name() {
        let signer = ToolSigner::generate().unwrap();
        let schema = json!({"type": "object"});
        let signature = signer.sign_tool("test_tool", &schema, None);

        let allowed = AllowedSignersConfig {
            fingerprints: vec![signer.fingerprint().to_string()],
            spiffe_ids: vec![],
        };
        let verifier = ToolSignatureVerifier::new(allowed);

        // Try to verify with a different tool name
        let result = verifier.verify_tool_signature("other_tool", &schema, &signature);
        assert!(!result.valid);
    }

    #[test]
    fn test_signature_verification_expired() {
        let signer = ToolSigner::generate().unwrap();
        let schema = json!({"type": "object"});
        let mut signature = signer.sign_tool("test_tool", &schema, None);

        // Set expiration to the past
        signature.expires_at = Some("2020-01-01T00:00:00Z".to_string());

        let allowed = AllowedSignersConfig {
            fingerprints: vec![signer.fingerprint().to_string()],
            spiffe_ids: vec![],
        };
        let verifier = ToolSignatureVerifier::new(allowed);

        let result = verifier.verify_tool_signature("test_tool", &schema, &signature);
        assert!(result.valid);
        assert!(result.signer_trusted);
        assert!(result.expired);
    }

    #[test]
    fn test_signer_from_private_key() {
        let signer1 = ToolSigner::generate().unwrap();
        let private_key = signer1.private_key_hex();

        let signer2 = ToolSigner::from_private_key_hex(&private_key, None).unwrap();
        assert_eq!(signer1.public_key_hex(), signer2.public_key_hex());
        assert_eq!(signer1.fingerprint(), signer2.fingerprint());
    }

    #[test]
    fn test_compute_key_fingerprint() {
        let signer = ToolSigner::generate().unwrap();
        let fp1 = compute_key_fingerprint(signer.public_key_hex()).unwrap();
        let fp2 = compute_key_fingerprint(signer.public_key_hex()).unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn test_spiffe_trust() {
        let signer = ToolSigner::new(
            SigningKey::generate(&mut rand::thread_rng()),
            Some("spiffe://example.org/tool-provider".to_string()),
        );
        let schema = json!({"type": "object"});
        let signature = signer.sign_tool("test_tool", &schema, None);

        let allowed = AllowedSignersConfig {
            fingerprints: vec![],
            spiffe_ids: vec!["spiffe://example.org/tool-provider".to_string()],
        };
        let verifier = ToolSignatureVerifier::new(allowed);

        let result = verifier.verify_tool_signature("test_tool", &schema, &signature);
        assert!(result.valid);
        assert!(result.signer_trusted); // Trusted via SPIFFE ID
    }
}
