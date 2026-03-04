// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Item 1 / R226-PQC-1: Verify ML-DSA-65 sign/verify roundtrip.
    ///
    /// Exercises the `use_hint` code path in FIPS 204 Algorithm 40 by signing
    /// multiple messages (including an empty one, which tends to produce edge-case
    /// `r0 = 0` coefficients) and verifying them.  If the underlying `fips204`
    /// crate has an off-by-two bug in `use_hint`, at least some of these will
    /// fail verification.
    #[test]
    fn test_ml_dsa_sign_verify_roundtrip() {
        let (pk, sk) = generate_ml_dsa_keypair().expect("keygen must succeed");

        // A variety of messages that exercise different coefficient distributions
        let messages: &[&[u8]] = &[
            b"vellaveto checkpoint payload",
            b"",            // empty — maximises edge-case coefficient patterns
            &[0u8; 64],     // all-zero block
            &[0xFFu8; 128], // all-one block
            b"The quick brown fox jumps over the lazy dog",
        ];

        for (i, msg) in messages.iter().enumerate() {
            let sig = ml_dsa_sign(&sk, msg, CHECKPOINT_CONTEXT)
                .unwrap_or_else(|e| panic!("sign must succeed for message {}: {}", i, e));
            ml_dsa_verify(&pk, msg, &sig, CHECKPOINT_CONTEXT)
                .unwrap_or_else(|e| panic!("verify must succeed for message {}: {}", i, e));
        }
    }

    /// R226-PQC-2: Wrong context must fail verification (domain separation).
    #[test]
    fn test_ml_dsa_verify_wrong_context_fails() {
        let (pk, sk) = generate_ml_dsa_keypair().expect("keygen must succeed");
        let msg = b"checkpoint data";
        let sig = ml_dsa_sign(&sk, msg, CHECKPOINT_CONTEXT).expect("sign must succeed");

        // Verify with MANIFEST_CONTEXT instead — must fail
        let result = ml_dsa_verify(&pk, msg, &sig, MANIFEST_CONTEXT);
        assert!(
            result.is_err(),
            "Verification with wrong context must fail (domain separation)"
        );
    }

    /// R226-PQC-3: Tampered signature must fail verification (fail-closed).
    #[test]
    fn test_ml_dsa_verify_tampered_signature_fails() {
        let (pk, sk) = generate_ml_dsa_keypair().expect("keygen must succeed");
        let msg = b"audit checkpoint";
        let sig = ml_dsa_sign(&sk, msg, CHECKPOINT_CONTEXT).expect("sign must succeed");

        // Flip a byte in the middle of the hex-encoded signature
        let mut sig_bytes = hex::decode(&sig).expect("valid hex");
        let mid = sig_bytes.len() / 2;
        sig_bytes[mid] ^= 0xFF;
        let tampered = hex::encode(sig_bytes);

        let result = ml_dsa_verify(&pk, msg, &tampered, CHECKPOINT_CONTEXT);
        assert!(result.is_err(), "Tampered signature must fail verification");
    }

    /// R226-PQC-4: Invalid key lengths must be rejected.
    #[test]
    fn test_ml_dsa_verify_wrong_key_length() {
        let result = ml_dsa_verify("deadbeef", b"msg", "abcd", CHECKPOINT_CONTEXT);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("wrong length"),
            "Error should mention wrong length, got: {}",
            err_msg
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: PQC signing error paths and boundary tests
    // ═══════════════════════════════════════════════════════════════

    /// Sign with invalid hex string must fail.
    #[test]
    fn test_ml_dsa_sign_invalid_hex_secret_key() {
        let result = ml_dsa_sign("not-valid-hex!", b"message", CHECKPOINT_CONTEXT);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Invalid ML-DSA secret key hex"),
            "Expected hex decode error, got: {err}"
        );
    }

    /// Sign with wrong-length secret key (valid hex but wrong size).
    #[test]
    fn test_ml_dsa_sign_wrong_length_secret_key() {
        // 32 bytes = 64 hex chars, but ML-DSA-65 SK is 4032 bytes
        let short_key = "ab".repeat(32);
        let result = ml_dsa_sign(&short_key, b"message", CHECKPOINT_CONTEXT);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("wrong length"),
            "Expected wrong length error, got: {err}"
        );
    }

    /// Verify with invalid hex public key must fail.
    #[test]
    fn test_ml_dsa_verify_invalid_hex_public_key() {
        let result = ml_dsa_verify("ZZZZ", b"msg", "abcd", CHECKPOINT_CONTEXT);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Invalid ML-DSA public key hex"),
            "Expected hex decode error, got: {err}"
        );
    }

    /// Verify with invalid hex signature must fail.
    #[test]
    fn test_ml_dsa_verify_invalid_hex_signature() {
        // Valid-length PK (1952 bytes = 3904 hex chars) but invalid sig hex
        let pk_hex = "00".repeat(ML_DSA_65_PK_LEN);
        let result = ml_dsa_verify(&pk_hex, b"msg", "ZZZZ", CHECKPOINT_CONTEXT);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Invalid ML-DSA signature hex"),
            "Expected hex decode error, got: {err}"
        );
    }

    /// Verify with wrong-length signature must fail.
    #[test]
    fn test_ml_dsa_verify_wrong_length_signature() {
        let pk_hex = "00".repeat(ML_DSA_65_PK_LEN);
        let short_sig = "ab".repeat(64); // 64 bytes, not 3309
        let result = ml_dsa_verify(&pk_hex, b"msg", &short_sig, CHECKPOINT_CONTEXT);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("signature wrong length"),
            "Expected wrong length error, got: {err}"
        );
    }

    /// Key generation produces keys of correct length.
    #[test]
    fn test_ml_dsa_keygen_key_lengths() {
        let (pk_hex, sk_hex) = generate_ml_dsa_keypair().unwrap();
        let pk_bytes = hex::decode(&pk_hex).unwrap();
        let sk_bytes = hex::decode(&sk_hex).unwrap();
        assert_eq!(
            pk_bytes.len(),
            ML_DSA_65_PK_LEN,
            "PK should be {} bytes",
            ML_DSA_65_PK_LEN
        );
        assert_eq!(
            sk_bytes.len(),
            ML_DSA_65_SK_LEN,
            "SK should be {} bytes",
            ML_DSA_65_SK_LEN
        );
    }

    /// Signature is correct length.
    #[test]
    fn test_ml_dsa_signature_length() {
        let (_, sk) = generate_ml_dsa_keypair().unwrap();
        let sig = ml_dsa_sign(&sk, b"test message", CHECKPOINT_CONTEXT).unwrap();
        let sig_bytes = hex::decode(&sig).unwrap();
        assert_eq!(
            sig_bytes.len(),
            ML_DSA_65_SIG_LEN,
            "Signature should be {} bytes",
            ML_DSA_65_SIG_LEN
        );
    }

    /// Signing with MANIFEST_CONTEXT and verifying with MANIFEST_CONTEXT works.
    #[test]
    fn test_ml_dsa_sign_verify_manifest_context() {
        let (pk, sk) = generate_ml_dsa_keypair().unwrap();
        let msg = b"rotation manifest data";
        let sig = ml_dsa_sign(&sk, msg, MANIFEST_CONTEXT).unwrap();
        ml_dsa_verify(&pk, msg, &sig, MANIFEST_CONTEXT)
            .expect("Verify with matching manifest context should succeed");
    }

    /// Tampered message fails verification (fail-closed).
    #[test]
    fn test_ml_dsa_verify_tampered_message_fails() {
        let (pk, sk) = generate_ml_dsa_keypair().unwrap();
        let msg = b"original message";
        let sig = ml_dsa_sign(&sk, msg, CHECKPOINT_CONTEXT).unwrap();

        let result = ml_dsa_verify(&pk, b"tampered message", &sig, CHECKPOINT_CONTEXT);
        assert!(result.is_err(), "Tampered message must fail verification");
    }

    /// Different key pair fails verification.
    #[test]
    fn test_ml_dsa_verify_wrong_key_pair_fails() {
        let (_, sk1) = generate_ml_dsa_keypair().unwrap();
        let (pk2, _) = generate_ml_dsa_keypair().unwrap();
        let msg = b"test data";
        let sig = ml_dsa_sign(&sk1, msg, CHECKPOINT_CONTEXT).unwrap();

        let result = ml_dsa_verify(&pk2, msg, &sig, CHECKPOINT_CONTEXT);
        assert!(
            result.is_err(),
            "Verification with wrong public key must fail"
        );
    }

    /// Constants have expected values matching FIPS 204 spec.
    #[test]
    fn test_ml_dsa_65_constants() {
        assert_eq!(ML_DSA_65_PK_LEN, 1952);
        assert_eq!(ML_DSA_65_SK_LEN, 4032);
        assert_eq!(ML_DSA_65_SIG_LEN, 3309);
    }

    /// Domain separator constants are non-empty and distinct.
    #[test]
    fn test_domain_separator_constants_distinct() {
        assert!(!CHECKPOINT_CONTEXT.is_empty());
        assert!(!MANIFEST_CONTEXT.is_empty());
        assert_ne!(
            CHECKPOINT_CONTEXT, MANIFEST_CONTEXT,
            "Domain separators must be different"
        );
    }

    /// Empty context (allowed by FIPS 204) works for sign+verify.
    #[test]
    fn test_ml_dsa_sign_verify_empty_context() {
        let (pk, sk) = generate_ml_dsa_keypair().unwrap();
        let msg = b"data with empty context";
        let sig = ml_dsa_sign(&sk, msg, b"").unwrap();
        ml_dsa_verify(&pk, msg, &sig, b"").expect("Empty context should be valid per FIPS 204");
    }

    /// Large message sign/verify works (ensure no internal size limit).
    #[test]
    fn test_ml_dsa_sign_verify_large_message() {
        let (pk, sk) = generate_ml_dsa_keypair().unwrap();
        let large_msg = vec![0x42u8; 100_000]; // 100 KB message
        let sig = ml_dsa_sign(&sk, &large_msg, CHECKPOINT_CONTEXT).unwrap();
        ml_dsa_verify(&pk, &large_msg, &sig, CHECKPOINT_CONTEXT)
            .expect("Large message sign/verify should work");
    }
}
