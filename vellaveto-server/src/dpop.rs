//! DPoP (Demonstrating Proof-of-Possession) Token Binding — Phase 65.
//!
//! Implements RFC 9449 DPoP proof verification for sender-constrained access
//! tokens. DPoP prevents token theft and replay by binding tokens to
//! the client's ephemeral key pair.
//!
//! # Overview
//!
//! DPoP adds a second layer of authentication: in addition to presenting
//! a Bearer token, the client must prove it holds the private key that
//! was used to create the DPoP proof. This prevents:
//!
//! - **Token theft**: A stolen access token cannot be used without the
//!   corresponding private key.
//! - **Token replay**: Each DPoP proof includes a unique `jti` and timestamp,
//!   preventing replay across different requests.
//!
//! # MCP DPoP SEP Progress
//!
//! This module prepares for the upcoming MCP DPoP Standards Enhancement
//! Proposal (SEP). The MCP specification is expected to mandate DPoP for
//! all authenticated MCP connections in a future revision. This
//! implementation tracks the draft and will be updated as the SEP evolves.
//!
//! # Security Design
//!
//! - Fail-closed: missing or invalid DPoP proof -> reject.
//! - Bounded: nonce cache, proof size limits, JTI replay window.
//! - No secrets in Debug output.
//! - All counters use `saturating_add`.
//! - `has_dangerous_chars()` on external strings.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use vellaveto_types::has_dangerous_chars;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum size of a DPoP proof JWT (bytes).
const MAX_DPOP_PROOF_SIZE: usize = 8192;

/// Maximum number of JTI entries in the replay cache.
const MAX_JTI_CACHE_ENTRIES: usize = 100_000;

/// JTI replay window in seconds (5 minutes, per RFC 9449 recommendation).
const JTI_REPLAY_WINDOW_SECS: u64 = 300;

/// Maximum clock skew tolerance in seconds.
const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Maximum length of an `htm` (HTTP method) value.
const MAX_HTM_LENGTH: usize = 16;

/// Maximum length of an `htu` (HTTP target URI) value.
const MAX_HTU_LENGTH: usize = 2048;

/// Maximum length of the `nonce` field.
const MAX_NONCE_LENGTH: usize = 256;

/// Maximum length of a JTI.
const MAX_JTI_LENGTH: usize = 256;

/// Maximum number of server nonces to track.
const MAX_SERVER_NONCES: usize = 10_000;

/// Server nonce validity in seconds (5 minutes).
const SERVER_NONCE_TTL_SECS: u64 = 300;

/// Supported JWK key types for DPoP proofs.
const SUPPORTED_KEY_TYPES: &[&str] = &["EC", "OKP", "RSA"];

/// Maximum length of key type string.
const MAX_KEY_TYPE_LEN: usize = 16;

/// Maximum JWK size (JSON bytes).
const MAX_JWK_SIZE: usize = 4096;

// ═══════════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════════

/// DPoP verification errors.
///
/// All error variants result in request denial (fail-closed).
#[derive(Debug, Error)]
pub enum DpopError {
    /// DPoP proof header is missing when required.
    #[error("DPoP proof required but not provided")]
    ProofMissing,

    /// DPoP proof exceeds maximum size.
    #[error("DPoP proof size {size} exceeds maximum {max}")]
    ProofTooLarge { size: usize, max: usize },

    /// DPoP proof JWT is malformed.
    #[error("malformed DPoP proof: {0}")]
    MalformedProof(String),

    /// DPoP proof header has an invalid `typ` (must be `dpop+jwt`).
    #[error("DPoP proof typ must be 'dpop+jwt', got '{0}'")]
    InvalidType(String),

    /// DPoP proof is missing the required JWK in the header.
    #[error("DPoP proof missing JWK in header")]
    MissingJwk,

    /// The JWK key type is not supported.
    #[error("unsupported JWK key type: {0}")]
    UnsupportedKeyType(String),

    /// DPoP proof signature verification failed.
    #[error("DPoP proof signature verification failed")]
    SignatureVerificationFailed,

    /// The `htm` (HTTP method) claim does not match the request.
    #[error("DPoP htm '{proof_htm}' does not match request method '{request_method}'")]
    HttpMethodMismatch {
        proof_htm: String,
        request_method: String,
    },

    /// The `htu` (HTTP target URI) claim does not match the request.
    #[error("DPoP htu mismatch")]
    HttpUriMismatch,

    /// The `jti` has been seen before (replay attempt).
    #[error("DPoP proof replay detected (duplicate jti)")]
    ReplayDetected,

    /// The proof's `iat` timestamp is outside the allowed window.
    #[error("DPoP proof timestamp out of acceptable range")]
    TimestampOutOfRange,

    /// The proof's `nonce` does not match the server-issued nonce.
    #[error("DPoP nonce mismatch or expired")]
    NonceMismatch,

    /// The proof's `ath` (access token hash) does not match.
    #[error("DPoP access token hash mismatch")]
    AccessTokenHashMismatch,

    /// The JWK thumbprint does not match the token's `cnf.jkt` claim.
    #[error("DPoP JWK thumbprint does not match token binding")]
    ThumbprintMismatch,

    /// Internal error (lock poisoned).
    #[error("DPoP internal error")]
    Internal,

    /// Field validation failed.
    #[error("DPoP field validation failed: {0}")]
    ValidationFailed(String),
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// DPoP proof header (JOSE header).
///
/// Per RFC 9449 Section 4.2: the header MUST contain `typ`, `alg`, and `jwk`.
#[derive(Debug, Clone, Deserialize)]
pub struct DpopHeader {
    /// Token type — MUST be "dpop+jwt".
    pub typ: String,
    /// Algorithm used to sign the proof.
    pub alg: String,
    /// The public key used to sign (JWK format).
    pub jwk: serde_json::Value,
}

/// DPoP proof claims (JWT payload).
///
/// Per RFC 9449 Section 4.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopClaims {
    /// Unique identifier for the proof (MUST be unique per proof).
    pub jti: String,
    /// HTTP method of the request.
    pub htm: String,
    /// HTTP target URI (without query and fragment).
    pub htu: String,
    /// Issued-at timestamp (Unix epoch seconds).
    pub iat: u64,
    /// Access token hash (SHA-256, base64url-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Server-provided nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl DpopClaims {
    /// Validate claim field lengths and content.
    pub fn validate(&self) -> Result<(), DpopError> {
        if self.jti.is_empty() || self.jti.len() > MAX_JTI_LENGTH {
            return Err(DpopError::ValidationFailed(
                "jti must be non-empty and within bounds".to_string(),
            ));
        }
        if has_dangerous_chars(&self.jti) {
            return Err(DpopError::ValidationFailed(
                "jti contains dangerous characters".to_string(),
            ));
        }
        if self.htm.is_empty() || self.htm.len() > MAX_HTM_LENGTH {
            return Err(DpopError::ValidationFailed(
                "htm must be non-empty and within bounds".to_string(),
            ));
        }
        if has_dangerous_chars(&self.htm) {
            return Err(DpopError::ValidationFailed(
                "htm contains dangerous characters".to_string(),
            ));
        }
        if self.htu.is_empty() || self.htu.len() > MAX_HTU_LENGTH {
            return Err(DpopError::ValidationFailed(
                "htu must be non-empty and within bounds".to_string(),
            ));
        }
        if has_dangerous_chars(&self.htu) {
            return Err(DpopError::ValidationFailed(
                "htu contains dangerous characters".to_string(),
            ));
        }
        if let Some(ref nonce) = self.nonce {
            if nonce.len() > MAX_NONCE_LENGTH {
                return Err(DpopError::ValidationFailed(
                    "nonce exceeds maximum length".to_string(),
                ));
            }
        }
        if let Some(ref ath) = self.ath {
            // Base64url-encoded SHA-256 = 43 chars
            if ath.len() > 128 {
                return Err(DpopError::ValidationFailed(
                    "ath exceeds maximum length".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Configuration for DPoP verification.
#[derive(Debug, Clone)]
pub struct DpopConfig {
    /// Whether DPoP is enabled.
    pub enabled: bool,
    /// Whether DPoP is required (vs. optional).
    /// When false, requests without DPoP proof are allowed but not sender-constrained.
    pub required: bool,
    /// Whether to require server nonces.
    pub require_nonce: bool,
    /// Clock skew tolerance in seconds.
    pub clock_skew_secs: u64,
    /// JTI replay window in seconds.
    pub jti_window_secs: u64,
    /// Temporary compatibility switch for environments that still use
    /// unsigned synthetic proofs. MUST remain false in production.
    pub allow_unverified_proofs: bool,
}

impl Default for DpopConfig {
    /// Default is fail-closed for proof verification.
    fn default() -> Self {
        Self {
            enabled: true,
            required: false, // Start as optional for gradual rollout
            require_nonce: false,
            clock_skew_secs: MAX_CLOCK_SKEW_SECS,
            jti_window_secs: JTI_REPLAY_WINDOW_SECS,
            allow_unverified_proofs: false,
        }
    }
}

/// Cached JTI entry for replay detection.
struct JtiEntry {
    seen_at: Instant,
}

/// Server-issued nonce entry.
struct NonceEntry {
    issued_at: Instant,
}

/// DPoP Verifier — validates DPoP proofs for sender-constrained tokens.
///
/// Thread-safe via internal `RwLock` on the JTI replay cache.
pub struct DpopVerifier {
    config: DpopConfig,
    /// JTI replay cache: jti -> seen_at.
    jti_cache: RwLock<HashMap<String, JtiEntry>>,
    /// Server-issued nonces: nonce -> issued_at.
    nonce_store: RwLock<HashMap<String, NonceEntry>>,
    /// Counter for total verifications.
    verification_count: std::sync::atomic::AtomicU64,
    /// Counter for verification failures.
    failure_count: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for DpopVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopVerifier")
            .field("config", &self.config)
            .field(
                "verification_count",
                &self
                    .verification_count
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .field(
                "failure_count",
                &self
                    .failure_count
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl DpopVerifier {
    /// Create a new DPoP verifier with the given configuration.
    pub fn new(config: DpopConfig) -> Self {
        Self {
            config,
            jti_cache: RwLock::new(HashMap::new()),
            nonce_store: RwLock::new(HashMap::new()),
            verification_count: std::sync::atomic::AtomicU64::new(0),
            failure_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Verify a DPoP proof.
    ///
    /// # Arguments
    ///
    /// * `proof_jwt` — The DPoP proof JWT from the `DPoP` HTTP header.
    /// * `http_method` — The HTTP method of the request (e.g., "POST").
    /// * `http_uri` — The HTTP target URI (without query and fragment).
    /// * `access_token` — The access token (for `ath` verification), if present.
    /// * `expected_thumbprint` — The JWK thumbprint from the token's `cnf.jkt`, if bound.
    ///
    /// # Errors
    ///
    /// Fails closed on any verification failure.
    pub fn verify_proof(
        &self,
        proof_jwt: &str,
        http_method: &str,
        http_uri: &str,
        access_token: Option<&str>,
        expected_thumbprint: Option<&str>,
    ) -> Result<DpopProofResult, DpopError> {
        self.verification_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        if !self.config.enabled {
            return Ok(DpopProofResult {
                valid: true,
                jwk_thumbprint: None,
                bound_key_type: None,
            });
        }

        // Size check
        if proof_jwt.len() > MAX_DPOP_PROOF_SIZE {
            self.increment_failures();
            return Err(DpopError::ProofTooLarge {
                size: proof_jwt.len(),
                max: MAX_DPOP_PROOF_SIZE,
            });
        }

        // Parse the JWT (header.payload.signature)
        let parts: Vec<&str> = proof_jwt.splitn(3, '.').collect();
        if parts.len() != 3 {
            self.increment_failures();
            return Err(DpopError::MalformedProof(
                "JWT must have 3 parts separated by '.'".to_string(),
            ));
        }

        // Decode header
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|e| {
            self.increment_failures();
            DpopError::MalformedProof(format!("invalid header base64: {}", e))
        })?;
        let header: DpopHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
            self.increment_failures();
            DpopError::MalformedProof(format!("invalid header JSON: {}", e))
        })?;

        // Verify typ
        if header.typ != "dpop+jwt" {
            self.increment_failures();
            return Err(DpopError::InvalidType(header.typ));
        }

        // Verify JWK is present and valid
        let jwk = &header.jwk;
        let jwk_size = serde_json::to_string(jwk).map(|s| s.len()).unwrap_or(0);
        if jwk_size > MAX_JWK_SIZE {
            self.increment_failures();
            return Err(DpopError::MalformedProof(format!(
                "JWK size {} exceeds maximum {}",
                jwk_size, MAX_JWK_SIZE
            )));
        }
        let key_type = jwk.get("kty").and_then(|v| v.as_str()).ok_or_else(|| {
            self.increment_failures();
            DpopError::MissingJwk
        })?;
        if key_type.len() > MAX_KEY_TYPE_LEN {
            self.increment_failures();
            return Err(DpopError::UnsupportedKeyType(
                key_type.chars().take(32).collect(),
            ));
        }
        if !SUPPORTED_KEY_TYPES.contains(&key_type) {
            self.increment_failures();
            return Err(DpopError::UnsupportedKeyType(key_type.to_string()));
        }

        // Decode claims
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| {
            self.increment_failures();
            DpopError::MalformedProof(format!("invalid claims base64: {}", e))
        })?;
        let claims: DpopClaims = serde_json::from_slice(&claims_bytes).map_err(|e| {
            self.increment_failures();
            DpopError::MalformedProof(format!("invalid claims JSON: {}", e))
        })?;

        // Validate claim fields
        claims.validate()?;

        // Verify HTTP method
        if !claims.htm.eq_ignore_ascii_case(http_method) {
            self.increment_failures();
            return Err(DpopError::HttpMethodMismatch {
                proof_htm: claims.htm.clone(),
                request_method: http_method.to_string(),
            });
        }

        // Verify HTTP URI (compare without query/fragment)
        let proof_uri = claims.htu.split('?').next().unwrap_or(&claims.htu);
        let request_uri = http_uri.split('?').next().unwrap_or(http_uri);
        if proof_uri != request_uri {
            self.increment_failures();
            return Err(DpopError::HttpUriMismatch);
        }

        // Verify timestamp
        self.check_timestamp(claims.iat)?;

        // Verify JTI (replay detection)
        self.check_jti(&claims.jti)?;

        // Verify nonce if required
        if self.config.require_nonce {
            match &claims.nonce {
                Some(nonce) => self.check_nonce(nonce)?,
                None => {
                    self.increment_failures();
                    return Err(DpopError::NonceMismatch);
                }
            }
        } else if let Some(ref nonce) = claims.nonce {
            // Nonce provided voluntarily — still verify it
            self.check_nonce(nonce)?;
        }

        // Verify access token hash if provided
        if let (Some(ref ath), Some(token)) = (&claims.ath, access_token) {
            let expected_ath = compute_token_hash(token);
            if !constant_time_eq(ath.as_bytes(), expected_ath.as_bytes()) {
                self.increment_failures();
                return Err(DpopError::AccessTokenHashMismatch);
            }
        }

        // Compute JWK thumbprint (RFC 7638)
        let thumbprint = compute_jwk_thumbprint(jwk)?;

        // Verify thumbprint binding if expected
        if let Some(expected) = expected_thumbprint {
            if !constant_time_eq(thumbprint.as_bytes(), expected.as_bytes()) {
                self.increment_failures();
                return Err(DpopError::ThumbprintMismatch);
            }
        }

        // SECURITY: Fail closed until JOSE signature verification is wired.
        // Accepting unsigned proofs would let attackers forge sender-constrained
        // tokens by controlling arbitrary `jwk` and `jti` values.
        if !self.config.allow_unverified_proofs {
            self.increment_failures();
            return Err(DpopError::SignatureVerificationFailed);
        }

        // Record JTI as seen
        self.record_jti(&claims.jti);

        Ok(DpopProofResult {
            valid: true,
            jwk_thumbprint: Some(thumbprint),
            bound_key_type: Some(key_type.to_string()),
        })
    }

    /// Issue a server nonce for the client to include in its next DPoP proof.
    ///
    /// Returns a fresh nonce string. The nonce is stored internally and
    /// validated when the client presents it back.
    pub fn issue_nonce(&self) -> Result<String, DpopError> {
        let nonce = generate_nonce();

        let mut store = self.nonce_store.write().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "DpopVerifier nonce_store write lock poisoned"
            );
            DpopError::Internal
        })?;

        // Evict expired nonces
        let ttl = Duration::from_secs(SERVER_NONCE_TTL_SECS);
        store.retain(|_, v| v.issued_at.elapsed() < ttl);

        // Cap at maximum
        while store.len() >= MAX_SERVER_NONCES {
            if let Some(oldest_key) = store
                .iter()
                .min_by_key(|(_, v)| v.issued_at)
                .map(|(k, _)| k.clone())
            {
                store.remove(&oldest_key);
            } else {
                break;
            }
        }

        store.insert(
            nonce.clone(),
            NonceEntry {
                issued_at: Instant::now(),
            },
        );

        Ok(nonce)
    }

    /// Check if a timestamp is within the acceptable window.
    fn check_timestamp(&self, iat: u64) -> Result<(), DpopError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let skew = self.config.clock_skew_secs;

        // Not in the future (beyond skew)
        if iat > now.saturating_add(skew) {
            self.increment_failures();
            return Err(DpopError::TimestampOutOfRange);
        }

        // Not too old (beyond replay window + skew)
        let window = self.config.jti_window_secs.saturating_add(skew);
        if now.saturating_sub(iat) > window {
            self.increment_failures();
            return Err(DpopError::TimestampOutOfRange);
        }

        Ok(())
    }

    /// Check if a JTI has been seen (replay detection).
    fn check_jti(&self, jti: &str) -> Result<(), DpopError> {
        let cache = self.jti_cache.read().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "DpopVerifier jti_cache read lock poisoned"
            );
            DpopError::Internal
        })?;

        if let Some(entry) = cache.get(jti) {
            let window = Duration::from_secs(self.config.jti_window_secs);
            if entry.seen_at.elapsed() < window {
                self.increment_failures();
                return Err(DpopError::ReplayDetected);
            }
        }

        Ok(())
    }

    /// Record a JTI as seen.
    fn record_jti(&self, jti: &str) {
        let mut cache = match self.jti_cache.write() {
            Ok(c) => c,
            Err(_) => {
                tracing::error!(
                    target: "vellaveto::security",
                    "DpopVerifier jti_cache write lock poisoned"
                );
                return;
            }
        };

        // Evict expired entries
        let window = Duration::from_secs(self.config.jti_window_secs);
        cache.retain(|_, v| v.seen_at.elapsed() < window);

        // Cap at maximum
        while cache.len() >= MAX_JTI_CACHE_ENTRIES {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.seen_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            } else {
                break;
            }
        }

        cache.insert(
            jti.to_string(),
            JtiEntry {
                seen_at: Instant::now(),
            },
        );
    }

    /// Check if a nonce is valid (issued by this server and not expired).
    fn check_nonce(&self, nonce: &str) -> Result<(), DpopError> {
        let store = self.nonce_store.read().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "DpopVerifier nonce_store read lock poisoned"
            );
            DpopError::Internal
        })?;

        match store.get(nonce) {
            Some(entry) => {
                let ttl = Duration::from_secs(SERVER_NONCE_TTL_SECS);
                if entry.issued_at.elapsed() > ttl {
                    self.increment_failures();
                    Err(DpopError::NonceMismatch)
                } else {
                    Ok(())
                }
            }
            None => {
                self.increment_failures();
                Err(DpopError::NonceMismatch)
            }
        }
    }

    /// Increment the failure counter.
    fn increment_failures(&self) {
        self.failure_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get the total number of verifications attempted.
    pub fn total_verifications(&self) -> u64 {
        self.verification_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the total number of verification failures.
    pub fn total_failures(&self) -> u64 {
        self.failure_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether DPoP is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Whether DPoP is required.
    pub fn is_required(&self) -> bool {
        self.config.required
    }

    /// Clear replay caches (for testing or operational reset).
    pub fn clear_caches(&self) {
        if let Ok(mut cache) = self.jti_cache.write() {
            cache.clear();
        }
        if let Ok(mut store) = self.nonce_store.write() {
            store.clear();
        }
    }
}

/// Result of a successful DPoP proof verification.
#[derive(Debug, Clone)]
pub struct DpopProofResult {
    /// Whether the proof was valid.
    pub valid: bool,
    /// JWK thumbprint of the proof key (for token binding).
    pub jwk_thumbprint: Option<String>,
    /// Key type of the bound key ("EC", "OKP", "RSA").
    pub bound_key_type: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute the SHA-256 hash of an access token, base64url-encoded (RFC 9449 Section 4.2).
pub fn compute_token_hash(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Compute the JWK Thumbprint per RFC 7638.
///
/// The thumbprint is a SHA-256 hash of the JWK's required members,
/// serialized in lexicographic order.
pub fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, DpopError> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DpopError::MalformedProof("JWK missing 'kty' field".to_string()))?;

    // Build the canonical representation per RFC 7638 Section 3.2
    let canonical = match kty {
        "EC" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            let x = jwk.get("x").and_then(|v| v.as_str()).unwrap_or("");
            let y = jwk.get("y").and_then(|v| v.as_str()).unwrap_or("");
            format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y)
        }
        "RSA" => {
            let e = jwk.get("e").and_then(|v| v.as_str()).unwrap_or("");
            let n = jwk.get("n").and_then(|v| v.as_str()).unwrap_or("");
            format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
        }
        "OKP" => {
            let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
            let x = jwk.get("x").and_then(|v| v.as_str()).unwrap_or("");
            format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x)
        }
        other => {
            return Err(DpopError::UnsupportedKeyType(other.to_string()));
        }
    };

    let hash = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Generate a cryptographically random nonce string.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Build a DPoP proof JWT for testing.
///
/// This is a helper for tests — not for production use.
#[cfg(test)]
fn build_test_proof(claims: &DpopClaims, jwk: &serde_json::Value) -> String {
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    // For testing, we use a dummy signature. In production, this would
    // be a real EC/Ed25519/RSA signature.
    let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
    format!("{}.{}.{}", header_b64, claims_b64, sig_b64)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_jwk() -> serde_json::Value {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "WbbaSStuffec977JuuBN7G-oARqTcPI_xnFE7RY7J9wI",
            "y": "f7YfGKxc5tMYJPGcILacr5cVjJBerFtMLNcqnWfU53s"
        })
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn test_claims() -> DpopClaims {
        DpopClaims {
            jti: "unique-jti-12345".to_string(),
            htm: "POST".to_string(),
            htu: "https://resource.example.com/api/evaluate".to_string(),
            iat: now_secs(),
            ath: None,
            nonce: None,
        }
    }

    // ── DpopConfig defaults ─────────────────────────────────────────────

    #[test]
    fn test_dpop_config_defaults() {
        let config = DpopConfig::default();
        assert!(config.enabled);
        assert!(!config.required); // Optional by default for gradual rollout
        assert!(!config.require_nonce);
        assert!(!config.allow_unverified_proofs);
    }

    // ── DpopClaims validation ───────────────────────────────────────────

    #[test]
    fn test_claims_validate_valid() {
        assert!(test_claims().validate().is_ok());
    }

    #[test]
    fn test_claims_validate_empty_jti_rejected() {
        let mut claims = test_claims();
        claims.jti = String::new();
        assert!(claims.validate().is_err());
    }

    #[test]
    fn test_claims_validate_jti_too_long_rejected() {
        let mut claims = test_claims();
        claims.jti = "x".repeat(MAX_JTI_LENGTH + 1);
        assert!(claims.validate().is_err());
    }

    #[test]
    fn test_claims_validate_dangerous_htm_rejected() {
        let mut claims = test_claims();
        claims.htm = "POST\x00".to_string();
        assert!(claims.validate().is_err());
    }

    #[test]
    fn test_claims_validate_htu_too_long_rejected() {
        let mut claims = test_claims();
        claims.htu = "https://".to_string() + &"x".repeat(MAX_HTU_LENGTH);
        assert!(claims.validate().is_err());
    }

    // ── DpopVerifier creation ───────────────────────────────────────────

    #[test]
    fn test_verifier_new() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        assert!(verifier.is_enabled());
        assert!(!verifier.is_required());
        assert_eq!(verifier.total_verifications(), 0);
        assert_eq!(verifier.total_failures(), 0);
    }

    // ── Proof verification: disabled ────────────────────────────────────

    #[test]
    fn test_verify_proof_disabled_passes() {
        let verifier = DpopVerifier::new(DpopConfig {
            enabled: false,
            ..DpopConfig::default()
        });
        let result = verifier
            .verify_proof("not-a-jwt", "POST", "/api", None, None)
            .unwrap();
        assert!(result.valid);
    }

    // ── Proof verification: oversized ───────────────────────────────────

    #[test]
    fn test_verify_proof_oversized_rejected() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let big = "x".repeat(MAX_DPOP_PROOF_SIZE + 1);
        let result = verifier.verify_proof(&big, "POST", "/api", None, None);
        assert!(matches!(result, Err(DpopError::ProofTooLarge { .. })));
    }

    // ── Proof verification: malformed ───────────────────────────────────

    #[test]
    fn test_verify_proof_malformed_jwt_rejected() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let result = verifier.verify_proof("not.a", "POST", "/api", None, None);
        assert!(matches!(result, Err(DpopError::MalformedProof(_))));
    }

    // ── Proof verification: wrong typ ───────────────────────────────────

    #[test]
    fn test_verify_proof_wrong_typ_rejected() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let header = json!({"typ": "JWT", "alg": "ES256", "jwk": test_jwk()});
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&test_claims()).unwrap());
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let proof = format!("{}.{}.{}", header_b64, claims_b64, sig_b64);
        let result = verifier.verify_proof(&proof, "POST", "/api", None, None);
        assert!(matches!(result, Err(DpopError::InvalidType(_))));
    }

    // ── Proof verification: valid structure ─────────────────────────────

    #[test]
    fn test_verify_proof_valid_structure() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let claims = test_claims();
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(matches!(
            result,
            Err(DpopError::SignatureVerificationFailed)
        ));
    }

    // ── Proof verification: HTTP method mismatch ────────────────────────

    #[test]
    fn test_verify_proof_method_mismatch_rejected() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let claims = test_claims();
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "GET", // claims.htm is "POST"
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(matches!(result, Err(DpopError::HttpMethodMismatch { .. })));
    }

    // ── Proof verification: URI mismatch ────────────────────────────────

    #[test]
    fn test_verify_proof_uri_mismatch_rejected() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let claims = test_claims();
        let proof = build_test_proof(&claims, &test_jwk());
        let result =
            verifier.verify_proof(&proof, "POST", "https://different.example.com", None, None);
        assert!(matches!(result, Err(DpopError::HttpUriMismatch)));
    }

    // ── Proof verification: replay detection ────────────────────────────

    #[test]
    fn test_verify_proof_replay_detected() {
        let verifier = DpopVerifier::new(DpopConfig {
            allow_unverified_proofs: true,
            ..DpopConfig::default()
        });
        let claims = test_claims();
        let proof = build_test_proof(&claims, &test_jwk());
        let uri = "https://resource.example.com/api/evaluate";

        // First call succeeds
        verifier
            .verify_proof(&proof, "POST", uri, None, None)
            .unwrap();

        // Second call with same JTI is replay
        let result = verifier.verify_proof(&proof, "POST", uri, None, None);
        assert!(matches!(result, Err(DpopError::ReplayDetected)));
    }

    // ── Proof verification: expired timestamp ───────────────────────────

    #[test]
    fn test_verify_proof_expired_timestamp_rejected() {
        let verifier = DpopVerifier::new(DpopConfig {
            clock_skew_secs: 0,
            jti_window_secs: 60,
            ..DpopConfig::default()
        });
        let mut claims = test_claims();
        claims.iat = now_secs().saturating_sub(3600); // 1 hour ago
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(matches!(result, Err(DpopError::TimestampOutOfRange)));
    }

    // ── Proof verification: future timestamp ────────────────────────────

    #[test]
    fn test_verify_proof_future_timestamp_rejected() {
        let verifier = DpopVerifier::new(DpopConfig {
            clock_skew_secs: 10,
            ..DpopConfig::default()
        });
        let mut claims = test_claims();
        claims.iat = now_secs() + 600; // 10 minutes in the future
        claims.jti = "future-jti".to_string();
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(matches!(result, Err(DpopError::TimestampOutOfRange)));
    }

    // ── Proof verification: access token hash ───────────────────────────

    #[test]
    fn test_verify_proof_access_token_hash_match() {
        let verifier = DpopVerifier::new(DpopConfig {
            allow_unverified_proofs: true,
            ..DpopConfig::default()
        });
        let token = "my-access-token-12345";
        let ath = compute_token_hash(token);
        let mut claims = test_claims();
        claims.ath = Some(ath);
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            Some(token),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_proof_access_token_hash_mismatch_rejected() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let mut claims = test_claims();
        claims.ath = Some(compute_token_hash("correct-token"));
        claims.jti = "ath-mismatch-jti".to_string();
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            Some("wrong-token"),
            None,
        );
        assert!(matches!(result, Err(DpopError::AccessTokenHashMismatch)));
    }

    // ── Proof verification: nonce ───────────────────────────────────────

    #[test]
    fn test_verify_proof_nonce_required_but_missing_rejected() {
        let verifier = DpopVerifier::new(DpopConfig {
            require_nonce: true,
            ..DpopConfig::default()
        });
        let claims = test_claims(); // no nonce
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(matches!(result, Err(DpopError::NonceMismatch)));
    }

    #[test]
    fn test_verify_proof_nonce_issued_and_verified() {
        let verifier = DpopVerifier::new(DpopConfig {
            require_nonce: true,
            allow_unverified_proofs: true,
            ..DpopConfig::default()
        });
        let nonce = verifier.issue_nonce().unwrap();
        let mut claims = test_claims();
        claims.nonce = Some(nonce);
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_proof_wrong_nonce_rejected() {
        let verifier = DpopVerifier::new(DpopConfig {
            require_nonce: true,
            ..DpopConfig::default()
        });
        let _nonce = verifier.issue_nonce().unwrap();
        let mut claims = test_claims();
        claims.nonce = Some("wrong-nonce".to_string());
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(matches!(result, Err(DpopError::NonceMismatch)));
    }

    // ── Proof verification: thumbprint binding ──────────────────────────

    #[test]
    fn test_verify_proof_thumbprint_match() {
        let verifier = DpopVerifier::new(DpopConfig {
            allow_unverified_proofs: true,
            ..DpopConfig::default()
        });
        let jwk = test_jwk();
        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
        let claims = test_claims();
        let proof = build_test_proof(&claims, &jwk);
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            Some(&thumbprint),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_proof_thumbprint_mismatch_rejected() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let mut claims = test_claims();
        claims.jti = "thumbprint-mismatch-jti".to_string();
        let proof = build_test_proof(&claims, &test_jwk());
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            Some("wrong-thumbprint-value"),
        );
        assert!(matches!(result, Err(DpopError::ThumbprintMismatch)));
    }

    // ── JWK thumbprint computation ──────────────────────────────────────

    #[test]
    fn test_compute_jwk_thumbprint_ec() {
        let jwk = test_jwk();
        let tp = compute_jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
        // Deterministic
        assert_eq!(tp, compute_jwk_thumbprint(&jwk).unwrap());
    }

    #[test]
    fn test_compute_jwk_thumbprint_rsa() {
        let jwk = json!({"kty": "RSA", "n": "abc", "e": "AQAB"});
        let tp = compute_jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
    }

    #[test]
    fn test_compute_jwk_thumbprint_okp() {
        let jwk = json!({"kty": "OKP", "crv": "Ed25519", "x": "abc"});
        let tp = compute_jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
    }

    #[test]
    fn test_compute_jwk_thumbprint_unknown_type_rejected() {
        let jwk = json!({"kty": "UNKNOWN"});
        assert!(compute_jwk_thumbprint(&jwk).is_err());
    }

    #[test]
    fn test_compute_jwk_thumbprint_missing_kty_rejected() {
        let jwk = json!({"crv": "P-256"});
        assert!(compute_jwk_thumbprint(&jwk).is_err());
    }

    // ── Token hash computation ──────────────────────────────────────────

    #[test]
    fn test_compute_token_hash_deterministic() {
        let h1 = compute_token_hash("my-token");
        let h2 = compute_token_hash("my-token");
        assert_eq!(h1, h2);
        assert!(!h1.is_empty());
    }

    #[test]
    fn test_compute_token_hash_different_tokens_differ() {
        assert_ne!(compute_token_hash("a"), compute_token_hash("b"));
    }

    // ── Nonce issuance ──────────────────────────────────────────────────

    #[test]
    fn test_issue_nonce_unique() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let n1 = verifier.issue_nonce().unwrap();
        let n2 = verifier.issue_nonce().unwrap();
        assert_ne!(n1, n2);
    }

    // ── Cache clearing ──────────────────────────────────────────────────

    #[test]
    fn test_clear_caches() {
        let verifier = DpopVerifier::new(DpopConfig {
            allow_unverified_proofs: true,
            ..DpopConfig::default()
        });
        let claims = test_claims();
        let proof = build_test_proof(&claims, &test_jwk());
        verifier
            .verify_proof(
                &proof,
                "POST",
                "https://resource.example.com/api/evaluate",
                None,
                None,
            )
            .unwrap();
        verifier.clear_caches();
        // After clear, same JTI should be accepted again
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(result.is_ok());
    }

    // ── Debug output ────────────────────────────────────────────────────

    #[test]
    fn test_verifier_debug() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let debug_str = format!("{:?}", verifier);
        assert!(debug_str.contains("DpopVerifier"));
        assert!(debug_str.contains("verification_count"));
    }

    // ── Counters ────────────────────────────────────────────────────────

    #[test]
    fn test_counters_increment_on_verification() {
        let verifier = DpopVerifier::new(DpopConfig {
            allow_unverified_proofs: true,
            ..DpopConfig::default()
        });
        let claims = test_claims();
        let proof = build_test_proof(&claims, &test_jwk());
        verifier
            .verify_proof(
                &proof,
                "POST",
                "https://resource.example.com/api/evaluate",
                None,
                None,
            )
            .unwrap();
        assert_eq!(verifier.total_verifications(), 1);
        assert_eq!(verifier.total_failures(), 0);
    }

    #[test]
    fn test_counters_increment_on_failure() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let _ = verifier.verify_proof("bad.jwt", "POST", "/api", None, None);
        assert_eq!(verifier.total_verifications(), 1);
        assert!(verifier.total_failures() > 0);
    }

    // ── Unsupported key type ────────────────────────────────────────────

    #[test]
    fn test_verify_proof_unsupported_key_type_rejected() {
        let verifier = DpopVerifier::new(DpopConfig::default());
        let bad_jwk = json!({"kty": "UNKNOWN", "x": "abc"});
        let claims = test_claims();
        let proof = build_test_proof(&claims, &bad_jwk);
        let result = verifier.verify_proof(
            &proof,
            "POST",
            "https://resource.example.com/api/evaluate",
            None,
            None,
        );
        assert!(matches!(result, Err(DpopError::UnsupportedKeyType(_))));
    }
}
