// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Explicit trusted boundary for Merkle hashing and hash encoding.
//!
//! Verus proves the structural Merkle logic around these operations, but not
//! the SHA-256 primitive or the hex codec itself. This module keeps that
//! remaining trust surface narrow and named in one place.

use crate::types::AuditError;
use sha2::{Digest, Sha256};

/// RFC 6962 domain separation byte for leaf hashes.
const LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 domain separation byte for internal hashes.
const INTERNAL_PREFIX: u8 = 0x01;

/// Hash a Merkle leaf with the RFC 6962 leaf prefix.
#[must_use = "Merkle hash results must not be discarded"]
pub(crate) fn hash_leaf_rfc6962(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a Merkle internal node with the RFC 6962 internal prefix.
#[must_use = "Merkle hash results must not be discarded"]
pub(crate) fn hash_internal_rfc6962(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Encode a 32-byte hash as lowercase hex.
#[must_use = "Merkle root/proof encodings must not be discarded"]
pub(crate) fn encode_hash_hex(hash: [u8; 32]) -> String {
    hex::encode(hash)
}

/// Decode a hex-encoded hash string.
///
/// Length validation stays at the verified Merkle guard call site so the
/// fail-closed boundary remains explicit there.
pub(crate) fn decode_hash_hex(hash_hex: &str) -> Result<Vec<u8>, AuditError> {
    hex::decode(hash_hex)
        .map_err(|e| AuditError::Validation(format!("Invalid sibling hash hex: {e}")))
}

/// Compare a computed hash against a trusted hex-encoded root.
#[must_use = "Merkle root comparisons must not be discarded"]
pub(crate) fn hash_matches_trusted_root(hash: [u8; 32], trusted_root: &str) -> bool {
    encode_hash_hex(hash) == trusted_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_hash_hex_roundtrip() {
        let hash = [0x5au8; 32];
        let encoded = encode_hash_hex(hash);
        let decoded = decode_hash_hex(&encoded).expect("valid hex");
        assert_eq!(decoded, hash);
    }

    #[test]
    fn test_decode_hash_hex_rejects_invalid_hex() {
        let err = decode_hash_hex("not-hex").expect_err("invalid hex");
        match err {
            AuditError::Validation(msg) => assert!(msg.contains("Invalid sibling hash hex")),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_hash_matches_trusted_root_requires_exact_encoding() {
        let hash = [0x42u8; 32];
        assert!(hash_matches_trusted_root(hash, &encode_hash_hex(hash)));
        assert!(!hash_matches_trusted_root(hash, &"0".repeat(64)));
    }

    #[test]
    fn test_hash_leaf_and_internal_preserve_domain_separation() {
        let data = [0xa5u8; 32];
        assert_ne!(
            hash_leaf_rfc6962(&data),
            hash_internal_rfc6962(&data, &data)
        );
    }

    #[test]
    fn test_hash_internal_is_order_sensitive() {
        let left = [0x01u8; 32];
        let right = [0x02u8; 32];
        assert_ne!(
            hash_internal_rfc6962(&left, &right),
            hash_internal_rfc6962(&right, &left)
        );
    }
}
