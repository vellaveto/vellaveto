//! DID:PLC (Decentralized Identifier: PLC) data types.
//!
//! Pure data types for DID:PLC identifiers — no cryptographic operations here.
//! Crypto (hashing, signing) lives in `vellaveto-mcp/src/did_plc.rs`.
//!
//! DID:PLC is a self-authenticating decentralized identifier scheme where the
//! DID is derived from the SHA-256 hash of a signed genesis operation.
//!
//! Format: `did:plc:<24-char-base32-suffix>`

use serde::{Deserialize, Serialize};
use std::fmt;

/// A validated DID:PLC identifier.
///
/// Format: `did:plc:<suffix>` where suffix is exactly 24 lowercase Base32
/// characters (no padding) derived from the first 15 bytes of a SHA-256 hash
/// of the canonicalized genesis operation.
///
/// # Example
///
/// ```
/// use vellaveto_types::DidPlc;
///
/// let did = DidPlc::from_str_validated("did:plc:ewvi7nxsareczkwkx5pz6q6e");
/// assert!(did.is_some());
///
/// let bad = DidPlc::from_str_validated("did:plc:TOOSHORT");
/// assert!(bad.is_none());
/// ```
// SECURITY (FIND-R46-001): Custom Deserialize implementation validates the
// DID:PLC format on deserialization. Previously `#[serde(transparent)]` allowed
// any arbitrary string to deserialize into a DidPlc, bypassing validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct DidPlc(String);

impl<'de> serde::Deserialize<'de> for DidPlc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DidPlc::from_str_validated(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "invalid DID:PLC format: expected 'did:plc:<24-char-base32-suffix>', got '{}'",
                if s.len() > 60 { &s[..60] } else { &s }
            ))
        })
    }
}

impl DidPlc {
    /// The required prefix for all DID:PLC identifiers.
    pub const PREFIX: &'static str = "did:plc:";

    /// The exact length of the Base32 suffix (15 bytes -> 24 chars in base32).
    pub const SUFFIX_LEN: usize = 24;

    /// Validate and construct a `DidPlc` from a string.
    ///
    /// Returns `None` if:
    /// - Missing `did:plc:` prefix
    /// - Suffix is not exactly 24 characters
    /// - Suffix contains non-base32 characters (a-z, 2-7)
    pub fn from_str_validated(s: &str) -> Option<Self> {
        let suffix = s.strip_prefix(Self::PREFIX)?;
        if suffix.len() != Self::SUFFIX_LEN {
            return None;
        }
        // Base32 lowercase alphabet: a-z, 2-7
        if !suffix
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        {
            return None;
        }
        Some(Self(s.to_string()))
    }

    /// Construct a `DidPlc` from a pre-computed Base32 suffix.
    ///
    /// Returns `None` if the suffix is not exactly 24 characters of valid
    /// Base32 (a-z, 2-7).
    ///
    /// SECURITY (FIND-R46-002): Previously accepted arbitrary strings without
    /// validation, bypassing the safety guarantees of the validated newtype.
    pub fn from_parts(suffix: String) -> Option<Self> {
        if suffix.len() != Self::SUFFIX_LEN {
            return None;
        }
        if !suffix
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        {
            return None;
        }
        Some(Self(format!("{}{}", Self::PREFIX, suffix)))
    }

    /// Returns the full DID string (e.g., `did:plc:ewvi7nxsareczkwkx5pz6q6e`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns only the identifier suffix (after `did:plc:`).
    pub fn identifier(&self) -> &str {
        &self.0[Self::PREFIX.len()..]
    }
}

impl fmt::Display for DidPlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A service endpoint in a DID:PLC document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidPlcService {
    /// Service identifier (e.g., `"atproto_pds"`).
    pub id: String,
    /// Service type (e.g., `"AtprotoPersonalDataServer"`).
    pub service_type: String,
    /// Service endpoint URL.
    pub endpoint: String,
}

/// The genesis (creation) operation for a DID:PLC identifier.
///
/// The DID is derived from the SHA-256 hash of the canonicalized JSON
/// representation of this operation (with `sig` set to `null`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidPlcGenesisOperation {
    /// Operation type — always `"plc_operation"` for genesis.
    #[serde(rename = "type")]
    pub op_type: String,
    /// Rotation keys (did:key format) that can update this DID document.
    #[serde(default)]
    pub rotation_keys: Vec<String>,
    /// Verification methods (did:key format) for signing.
    #[serde(default)]
    pub verification_methods: Vec<String>,
    /// Also-known-as identifiers (e.g., `at://` handles).
    #[serde(default)]
    pub also_known_as: Vec<String>,
    /// Service endpoints.
    #[serde(default)]
    pub services: Vec<DidPlcService>,
    /// Signature over the operation (set to `null` for DID derivation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// Previous operation CID (null for genesis).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
}

/// Errors related to DID:PLC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidPlcError {
    /// The DID string does not match the expected format.
    InvalidFormat(String),
    /// A required field is missing from the genesis operation.
    MissingField(String),
    /// Signing the genesis operation failed.
    SigningError(String),
    /// Verification of a DID operation failed.
    VerificationFailed(String),
    /// Resolution of a DID from a PLC directory failed.
    ResolutionError(String),
}

impl fmt::Display for DidPlcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidPlcError::InvalidFormat(msg) => write!(f, "Invalid DID:PLC format: {}", msg),
            DidPlcError::MissingField(field) => {
                write!(f, "Missing required field in genesis operation: {}", field)
            }
            DidPlcError::SigningError(msg) => write!(f, "DID:PLC signing error: {}", msg),
            DidPlcError::VerificationFailed(msg) => {
                write!(f, "DID:PLC verification failed: {}", msg)
            }
            DidPlcError::ResolutionError(msg) => write!(f, "DID:PLC resolution error: {}", msg),
        }
    }
}

impl std::error::Error for DidPlcError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_plc_valid() {
        let did = DidPlc::from_str_validated("did:plc:ewvi7nxsareczkwkx5pz6q6e");
        assert!(did.is_some());
        let did = did.expect("valid DID");
        assert_eq!(did.as_str(), "did:plc:ewvi7nxsareczkwkx5pz6q6e");
        assert_eq!(did.identifier(), "ewvi7nxsareczkwkx5pz6q6e");
    }

    #[test]
    fn test_did_plc_invalid_prefix() {
        assert!(DidPlc::from_str_validated("did:web:example.com").is_none());
        assert!(DidPlc::from_str_validated("ewvi7nxsareczkwkx5pz6q6e").is_none());
    }

    #[test]
    fn test_did_plc_invalid_suffix_length() {
        assert!(DidPlc::from_str_validated("did:plc:tooshort").is_none());
        assert!(DidPlc::from_str_validated("did:plc:waytoolongstringherexyz12345").is_none());
    }

    #[test]
    fn test_did_plc_invalid_characters() {
        // '8', '9', '0', '1' are not in base32 lowercase alphabet
        assert!(DidPlc::from_str_validated("did:plc:890100000000000000000000").is_none());
        // Uppercase not allowed
        assert!(DidPlc::from_str_validated("did:plc:EWVI7NXSARECZKWKX5PZ6Q6E").is_none());
    }

    #[test]
    fn test_did_plc_from_parts() {
        let did = DidPlc::from_parts("abcdefghijklmnopqrstuvwx".to_string());
        assert!(did.is_some());
        let did = did.unwrap();
        assert_eq!(did.as_str(), "did:plc:abcdefghijklmnopqrstuvwx");
        assert_eq!(did.identifier(), "abcdefghijklmnopqrstuvwx");
    }

    #[test]
    fn test_did_plc_from_parts_invalid_rejected() {
        // SECURITY (FIND-R46-002): from_parts now validates the suffix
        assert!(DidPlc::from_parts("INVALID".to_string()).is_none());
        assert!(DidPlc::from_parts("".to_string()).is_none());
        assert!(DidPlc::from_parts("890100000000000000000000".to_string()).is_none());
    }

    #[test]
    fn test_did_plc_display() {
        let did = DidPlc::from_parts("ewvi7nxsareczkwkx5pz6q6e".to_string()).unwrap();
        assert_eq!(format!("{}", did), "did:plc:ewvi7nxsareczkwkx5pz6q6e");
    }

    #[test]
    fn test_did_plc_serde_roundtrip() {
        let did = DidPlc::from_parts("ewvi7nxsareczkwkx5pz6q6e".to_string()).unwrap();
        let json = serde_json::to_string(&did).expect("serialize");
        let deserialized: DidPlc = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(did, deserialized);
    }

    // SECURITY (FIND-R46-001): Deserialization must validate the DID:PLC format
    #[test]
    fn test_did_plc_serde_rejects_invalid() {
        let result: Result<DidPlc, _> = serde_json::from_str("\"arbitrary-string\"");
        assert!(result.is_err(), "Invalid DID:PLC must be rejected on deserialization");
    }

    #[test]
    fn test_did_plc_genesis_operation_serde() {
        let genesis = DidPlcGenesisOperation {
            op_type: "plc_operation".to_string(),
            rotation_keys: vec!["did:key:z123".to_string()],
            verification_methods: vec!["did:key:z456".to_string()],
            also_known_as: vec![],
            services: vec![DidPlcService {
                id: "atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            }],
            sig: None,
            prev: None,
        };
        let json = serde_json::to_string(&genesis).expect("serialize");
        let deserialized: DidPlcGenesisOperation =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(genesis, deserialized);
        // sig and prev should be omitted when None
        assert!(!json.contains("\"sig\""));
        assert!(!json.contains("\"prev\""));
    }
}
