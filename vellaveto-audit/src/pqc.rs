//! Post-Quantum Cryptography (PQC) hybrid signature support (Phase 54).
//!
//! Implements hybrid Ed25519 + ML-DSA-65 (FIPS 204) signatures for audit
//! checkpoints and rotation manifests.
//!
//! Design principles:
//! - **Hybrid security**: Both Ed25519 and ML-DSA-65 signatures must verify (fail-closed)
//! - **Backward compatible**: Legacy Ed25519-only checkpoints continue to verify
//! - **NIST SP 800-227 aligned**: Composite signature approach
//! - **Domain separation**: Different contexts for checkpoints vs manifests

use crate::types::AuditError;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

/// ML-DSA-65 public key size in bytes (FIPS 204).
pub const ML_DSA_65_PK_LEN: usize = 1952;

/// ML-DSA-65 secret key size in bytes (FIPS 204).
pub const ML_DSA_65_SK_LEN: usize = 4032;

/// ML-DSA-65 signature size in bytes (FIPS 204).
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// Domain separator context for checkpoint signatures.
/// Prevents cross-protocol signature reuse between checkpoints and manifests.
pub const CHECKPOINT_CONTEXT: &[u8] = b"vellaveto-checkpoint-v1";

/// Domain separator context for rotation manifest signatures.
pub const MANIFEST_CONTEXT: &[u8] = b"vellaveto-manifest-v1";

/// Generate a new ML-DSA-65 key pair.
///
/// Returns `(public_key_hex, secret_key_hex)` as hex-encoded strings.
/// Both keys must be stored together — ML-DSA key pairs are generated jointly.
/// The public key can also be derived from the private key via [`ml_dsa_public_key_from_secret`].
pub fn generate_ml_dsa_keypair() -> Result<(String, String), AuditError> {
    let (pk, sk) = ml_dsa_65::KG::try_keygen()
        .map_err(|e| AuditError::Validation(format!("ML-DSA-65 key generation failed: {}", e)))?;
    Ok((hex::encode(pk.into_bytes()), hex::encode(sk.into_bytes())))
}

/// Sign a message with ML-DSA-65.
///
/// The `context` parameter provides domain separation per FIPS 204 §4.2.
/// Use [`CHECKPOINT_CONTEXT`] for checkpoint signing and [`MANIFEST_CONTEXT`]
/// for rotation manifest signing.
///
/// Returns the hex-encoded signature (6618 hex chars / 3309 bytes).
pub fn ml_dsa_sign(sk_hex: &str, message: &[u8], context: &[u8]) -> Result<String, AuditError> {
    let sk_bytes = hex::decode(sk_hex)
        .map_err(|e| AuditError::Validation(format!("Invalid ML-DSA secret key hex: {}", e)))?;
    if sk_bytes.len() != ML_DSA_65_SK_LEN {
        return Err(AuditError::Validation(format!(
            "ML-DSA secret key wrong length: {} (expected {})",
            sk_bytes.len(),
            ML_DSA_65_SK_LEN
        )));
    }
    let sk_arr: [u8; ML_DSA_65_SK_LEN] = sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuditError::Validation("ML-DSA secret key conversion failed".to_string()))?;
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr)
        .map_err(|e| AuditError::Validation(format!("Invalid ML-DSA secret key bytes: {}", e)))?;
    let sig = sk
        .try_sign(message, context)
        .map_err(|e| AuditError::Validation(format!("ML-DSA-65 signing failed: {}", e)))?;
    // Signature from try_sign() is [u8; SIG_LEN] directly
    Ok(hex::encode(sig))
}

/// Verify an ML-DSA-65 signature.
///
/// The `context` must match the context used during signing.
/// Returns `Ok(())` on success, `Err(AuditError)` on verification failure (fail-closed).
pub fn ml_dsa_verify(
    pk_hex: &str,
    message: &[u8],
    sig_hex: &str,
    context: &[u8],
) -> Result<(), AuditError> {
    let pk_bytes = hex::decode(pk_hex)
        .map_err(|e| AuditError::Validation(format!("Invalid ML-DSA public key hex: {}", e)))?;
    if pk_bytes.len() != ML_DSA_65_PK_LEN {
        return Err(AuditError::Validation(format!(
            "ML-DSA public key wrong length: {} (expected {})",
            pk_bytes.len(),
            ML_DSA_65_PK_LEN
        )));
    }
    let pk_arr: [u8; ML_DSA_65_PK_LEN] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuditError::Validation("ML-DSA public key conversion failed".to_string()))?;
    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
        .map_err(|e| AuditError::Validation(format!("Invalid ML-DSA public key bytes: {}", e)))?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| AuditError::Validation(format!("Invalid ML-DSA signature hex: {}", e)))?;
    if sig_bytes.len() != ML_DSA_65_SIG_LEN {
        return Err(AuditError::Validation(format!(
            "ML-DSA signature wrong length: {} (expected {})",
            sig_bytes.len(),
            ML_DSA_65_SIG_LEN
        )));
    }
    let sig_arr: [u8; ML_DSA_65_SIG_LEN] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuditError::Validation("ML-DSA signature conversion failed".to_string()))?;

    // Signature from signing is [u8; SIG_LEN] — verify takes a reference to it
    // SECURITY: Fail-closed — verification failure is an error, not a silent false
    if pk.verify(message, &sig_arr, context) {
        Ok(())
    } else {
        Err(AuditError::Validation(
            "ML-DSA-65 signature verification failed".to_string(),
        ))
    }
}
