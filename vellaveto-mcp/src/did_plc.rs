//! DID:PLC generation and validation.
//!
//! Implements the cryptographic operations for DID:PLC identifiers:
//! - SHA-256 hash of canonicalized genesis operation
//! - Base32 encoding (lowercase, no padding)
//! - Validation of DID:PLC format
//!
//! No new external dependencies — uses `sha2`, `serde_json_canonicalizer`,
//! and `hex` already present in this crate.

use sha2::{Digest, Sha256};
use vellaveto_types::{DidPlc, DidPlcError, DidPlcGenesisOperation};

/// Generate a DID:PLC from a genesis operation.
///
/// The DID is derived by:
/// 1. Setting `sig` to `null` in the genesis operation
/// 2. Canonicalizing the JSON (RFC 8785 / JCS)
/// 3. Computing SHA-256 of the canonical bytes
/// 4. Taking the first 15 bytes of the hash
/// 5. Base32-encoding (lowercase, no padding) -> 24 characters
/// 6. Prepending `did:plc:`
///
/// This is deterministic: the same genesis op always produces the same DID.
pub fn generate_did_plc(genesis: &DidPlcGenesisOperation) -> Result<DidPlc, DidPlcError> {
    // SECURITY (FIND-R178-001): Validate genesis bounds before clone+serialize.
    genesis
        .validate()
        .map_err(|e| DidPlcError::MissingField(format!("genesis validation failed: {}", e)))?;

    // Validate required fields
    if genesis.op_type.is_empty() {
        return Err(DidPlcError::MissingField("type".to_string()));
    }
    if genesis.rotation_keys.is_empty() && genesis.verification_methods.is_empty() {
        return Err(DidPlcError::MissingField(
            "rotation_keys or verification_methods (at least one required)".to_string(),
        ));
    }

    // Create a copy with sig = null for hashing
    let mut genesis_for_hash = genesis.clone();
    genesis_for_hash.sig = None;

    // Canonicalize JSON (RFC 8785)
    let json_bytes = serde_json::to_vec(&genesis_for_hash)
        .map_err(|e| DidPlcError::SigningError(format!("JSON serialization failed: {}", e)))?;
    let canonical = serde_json_canonicalizer::to_string(&json_bytes)
        .map_err(|e| DidPlcError::SigningError(format!("JSON canonicalization failed: {}", e)))?;

    // SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();

    // Take first 15 bytes, Base32 encode (lowercase, no padding) -> 24 chars
    let suffix = base32_encode_lower(&hash[..15]);
    debug_assert_eq!(suffix.len(), 24);

    DidPlc::from_parts(suffix)
        .ok_or_else(|| DidPlcError::InvalidFormat("generated suffix failed validation".to_string()))
}

/// Convenience: generate a DID:PLC from a single public key.
///
/// Creates a minimal genesis operation with one rotation key and one
/// verification method derived from the provided public key.
pub fn generate_did_plc_from_key(
    public_key_hex: &str,
    key_algorithm: &str,
) -> Result<DidPlc, DidPlcError> {
    if public_key_hex.is_empty() {
        return Err(DidPlcError::MissingField("public_key_hex".to_string()));
    }
    // SECURITY (FIND-R178-001): Bound input lengths to prevent oversized key_id.
    const MAX_PUBLIC_KEY_HEX_LEN: usize = 1024;
    const MAX_KEY_ALGORITHM_LEN: usize = 64;
    if public_key_hex.len() > MAX_PUBLIC_KEY_HEX_LEN {
        return Err(DidPlcError::MissingField(format!(
            "public_key_hex length {} exceeds maximum {}",
            public_key_hex.len(),
            MAX_PUBLIC_KEY_HEX_LEN
        )));
    }
    if key_algorithm.len() > MAX_KEY_ALGORITHM_LEN {
        return Err(DidPlcError::MissingField(format!(
            "key_algorithm length {} exceeds maximum {}",
            key_algorithm.len(),
            MAX_KEY_ALGORITHM_LEN
        )));
    }
    // SECURITY (FIND-R188-006): Reject control/format characters in key_algorithm
    // and public_key_hex to prevent log injection and canonicalization attacks.
    if vellaveto_types::has_dangerous_chars(key_algorithm) {
        return Err(DidPlcError::MissingField(
            "key_algorithm contains control or format characters".to_string(),
        ));
    }
    if vellaveto_types::has_dangerous_chars(public_key_hex) {
        return Err(DidPlcError::MissingField(
            "public_key_hex contains control or format characters".to_string(),
        ));
    }

    // Construct a did:key-style identifier (simplified)
    let key_id = format!("did:key:z{}:{}", key_algorithm, public_key_hex);

    let genesis = DidPlcGenesisOperation {
        op_type: "plc_operation".to_string(),
        rotation_keys: vec![key_id.clone()],
        verification_methods: vec![key_id],
        also_known_as: vec![],
        services: vec![],
        sig: None,
        prev: None,
    };

    generate_did_plc(&genesis)
}

/// Validate a DID:PLC string for correct format.
pub fn validate_did_plc(did: &str) -> Result<(), DidPlcError> {
    DidPlc::from_str_validated(did).map(|_| ()).ok_or_else(|| {
        // SECURITY (FIND-R178-005): Truncate to prevent oversized error messages.
        // SECURITY (IMP-R178-008): Use char boundary to avoid panic on multi-byte UTF-8.
        let display = if did.len() > 60 {
            let mut end = 60;
            while end > 0 && !did.is_char_boundary(end) {
                end -= 1;
            }
            &did[..end]
        } else {
            did
        };
        DidPlcError::InvalidFormat(format!(
            "expected 'did:plc:<24-char-base32-suffix>', got '{}'",
            display
        ))
    })
}

/// Base32 encode bytes using RFC 4648 lowercase alphabet (a-z, 2-7), no padding.
///
/// Internal helper — no new dependency needed. This is a straightforward
/// implementation of RFC 4648 §6 Base32 encoding.
fn base32_encode_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    // Handle remaining bits (if any)
    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::DidPlcService;

    #[test]
    fn test_base32_encode_known_vectors() {
        // RFC 4648 test vectors (lowercased)
        assert_eq!(base32_encode_lower(b""), "");
        assert_eq!(base32_encode_lower(b"f"), "my");
        assert_eq!(base32_encode_lower(b"fo"), "mzxq");
        assert_eq!(base32_encode_lower(b"foo"), "mzxw6");
        assert_eq!(base32_encode_lower(b"foob"), "mzxw6yq");
        assert_eq!(base32_encode_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_encode_lower(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn test_base32_encode_15_bytes_produces_24_chars() {
        let data = [0u8; 15];
        let encoded = base32_encode_lower(&data);
        assert_eq!(encoded.len(), 24);
    }

    #[test]
    fn test_generate_did_plc_deterministic() {
        let genesis = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:zTest123".to_string()],
            verification_methods: vec!["did:key:zTest123".to_string()],
            also_known_as: vec![],
            services: vec![],
            sig: None,
            prev: None,
        };

        let did1 = generate_did_plc(&genesis).expect("generate 1");
        let did2 = generate_did_plc(&genesis).expect("generate 2");
        assert_eq!(did1, did2, "Same genesis must produce same DID");
    }

    #[test]
    fn test_generate_did_plc_format() {
        let genesis = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:zTest456".to_string()],
            verification_methods: vec![],
            also_known_as: vec![],
            services: vec![],
            sig: None,
            prev: None,
        };

        let did = generate_did_plc(&genesis).expect("generate");
        assert!(did.as_str().starts_with("did:plc:"));
        assert_eq!(did.identifier().len(), 24);
        // Validate format
        assert!(DidPlc::from_str_validated(did.as_str()).is_some());
    }

    #[test]
    fn test_generate_did_plc_different_keys_different_dids() {
        let genesis1 = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:zKeyA".to_string()],
            verification_methods: vec![],
            also_known_as: vec![],
            services: vec![],
            sig: None,
            prev: None,
        };
        let genesis2 = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:zKeyB".to_string()],
            verification_methods: vec![],
            also_known_as: vec![],
            services: vec![],
            sig: None,
            prev: None,
        };

        let did1 = generate_did_plc(&genesis1).expect("generate 1");
        let did2 = generate_did_plc(&genesis2).expect("generate 2");
        assert_ne!(did1, did2, "Different keys must produce different DIDs");
    }

    #[test]
    fn test_generate_did_plc_sig_ignored() {
        let genesis_unsigned = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:zSigTest".to_string()],
            verification_methods: vec![],
            also_known_as: vec![],
            services: vec![],
            sig: None,
            prev: None,
        };
        let genesis_signed = DidPlcGenesisOperation {
            sig: Some("fake-signature-abc123".to_string()),
            ..genesis_unsigned.clone()
        };

        let did1 = generate_did_plc(&genesis_unsigned).expect("unsigned");
        let did2 = generate_did_plc(&genesis_signed).expect("signed");
        assert_eq!(did1, did2, "sig field must be ignored in DID derivation");
    }

    #[test]
    fn test_generate_did_plc_missing_fields() {
        let genesis = DidPlcGenesisOperation {
            op_type: "".to_string(),
            rotation_keys: vec![],
            verification_methods: vec![],
            also_known_as: vec![],
            services: vec![],
            sig: None,
            prev: None,
        };

        let result = generate_did_plc(&genesis);
        assert!(matches!(result, Err(DidPlcError::MissingField(_))));
    }

    #[test]
    fn test_generate_did_plc_no_keys() {
        let genesis = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec![],
            verification_methods: vec![],
            also_known_as: vec![],
            services: vec![],
            sig: None,
            prev: None,
        };

        let result = generate_did_plc(&genesis);
        assert!(matches!(result, Err(DidPlcError::MissingField(_))));
    }

    #[test]
    fn test_generate_did_plc_from_key() {
        let did = generate_did_plc_from_key("abcdef1234567890", "Ed25519").expect("from key");
        assert!(did.as_str().starts_with("did:plc:"));
        assert_eq!(did.identifier().len(), 24);
    }

    #[test]
    fn test_generate_did_plc_from_key_empty() {
        let result = generate_did_plc_from_key("", "Ed25519");
        assert!(matches!(result, Err(DidPlcError::MissingField(_))));
    }

    #[test]
    fn test_generate_did_plc_with_services() {
        let genesis = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:zServiceTest".to_string()],
            verification_methods: vec!["did:key:zServiceTest".to_string()],
            also_known_as: vec!["at://handle.example.com".to_string()],
            services: vec![DidPlcService {
                id: "atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            }],
            sig: None,
            prev: None,
        };

        let did = generate_did_plc(&genesis).expect("generate with services");
        assert!(validate_did_plc(did.as_str()).is_ok());
    }

    #[test]
    fn test_validate_did_plc_valid() {
        assert!(validate_did_plc("did:plc:ewvi7nxsareczkwkx5pz6q6e").is_ok());
    }

    #[test]
    fn test_validate_did_plc_invalid() {
        assert!(validate_did_plc("not-a-did").is_err());
        assert!(validate_did_plc("did:plc:short").is_err());
        assert!(validate_did_plc("did:web:example.com").is_err());
    }

    // ── R178 validation tests ──────────────────────────────────────────

    #[test]
    fn test_generate_did_plc_from_key_oversized_public_key() {
        let big_key = "a".repeat(1025);
        let result = generate_did_plc_from_key(&big_key, "Ed25519");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DidPlcError::MissingField(_)));
    }

    #[test]
    fn test_generate_did_plc_from_key_at_max_public_key() {
        let max_key = "a".repeat(1024);
        // Should not fail on the length check (may succeed or fail downstream)
        let result = generate_did_plc_from_key(&max_key, "Ed25519");
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_did_plc_from_key_oversized_algorithm() {
        let big_algo = "x".repeat(65);
        let result = generate_did_plc_from_key("abcdef1234", &big_algo);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DidPlcError::MissingField(_)));
    }

    #[test]
    fn test_generate_did_plc_from_key_at_max_algorithm() {
        let max_algo = "x".repeat(64);
        let result = generate_did_plc_from_key("abcdef1234", &max_algo);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_did_plc_genesis_exceeds_max_entries() {
        let many_keys: Vec<String> = (0..101).map(|i| format!("did:key:zKey{:04}", i)).collect();
        let genesis = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: many_keys,
            verification_methods: vec![],
            also_known_as: vec![],
            services: vec![],
            sig: None,
            prev: None,
        };
        let result = generate_did_plc(&genesis);
        assert!(
            result.is_err(),
            "Should reject genesis with 101 rotation keys"
        );
    }

    #[test]
    fn test_validate_did_plc_oversized_input() {
        let big_input = "did:plc:".to_string() + &"x".repeat(10_000);
        let result = validate_did_plc(&big_input);
        assert!(result.is_err());
        // Error message should be bounded (truncated to ~60 chars)
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.len() < 200,
            "Error message should be bounded: len={}",
            err_msg.len()
        );
    }

    #[test]
    fn test_validate_did_plc_multibyte_utf8_no_panic() {
        // Multi-byte chars that would cause &did[..60] to panic if byte-sliced
        let mut input = "did:plc:".to_string();
        // Each emoji is 4 bytes; 15 of them = 60 bytes + 8 for prefix = 68 bytes
        for _ in 0..15 {
            input.push('\u{1F600}'); // 😀
        }
        let result = validate_did_plc(&input);
        assert!(result.is_err()); // Should not panic
    }
}
