//! OAuth 2.1 JWT validation for the MCP HTTP proxy.
//!
//! When configured, the proxy validates Bearer tokens on incoming requests
//! against a JWKS endpoint published by the OAuth authorization server.
//!
//! Token validation checks:
//! - Signature verification against cached JWKS keys
//! - Expiry (`exp` claim)
//! - Issuer (`iss` claim) matches configured issuer
//! - Audience (`aud` claim) matches configured audience
//! - Required scopes (from `scope` claim, space-delimited)
//!
//! **Pass-through mode:** When `pass_through` is true, the original
//! `Authorization` header is forwarded to the upstream MCP server.

use jsonwebtoken::{
    decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
    Algorithm, DecodingKey, TokenData, Validation,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

/// DPoP enforcement mode for OAuth requests.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DpopMode {
    /// Ignore DPoP proofs entirely.
    #[default]
    Off,
    /// Validate DPoP proofs when present, but allow bearer-only requests.
    Optional,
    /// Require a valid DPoP proof on every OAuth-authenticated request.
    Required,
}

/// OAuth 2.1 configuration for the HTTP proxy.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// OAuth issuer URL (e.g., `https://auth.example.com`).
    /// Validated against the `iss` claim in the JWT.
    pub issuer: String,

    /// Expected audience claim (e.g., `mcp-server`).
    /// Validated against the `aud` claim in the JWT.
    pub audience: String,

    /// JWKS endpoint URL for public key discovery.
    /// If not provided, defaults to `{issuer}/.well-known/jwks.json`.
    pub jwks_uri: Option<String>,

    /// Required OAuth scopes. All listed scopes must be present in the token.
    /// If empty, no scope checking is performed.
    pub required_scopes: Vec<String>,

    /// Whether to forward the Bearer token to the upstream MCP server.
    /// When false, the proxy strips the Authorization header before forwarding.
    pub pass_through: bool,

    /// Allowed JWT signing algorithms. Tokens using an algorithm not in this
    /// list are rejected. Prevents algorithm confusion attacks where an attacker
    /// selects a weak algorithm (e.g., HS256 with an RSA public key as secret).
    ///
    /// Defaults to asymmetric algorithms only: RS256, RS384, RS512, ES256, ES384,
    /// PS256, PS384, PS512, EdDSA. HMAC (HS*) algorithms are excluded because
    /// OAuth 2.1 flows use asymmetric key pairs.
    pub allowed_algorithms: Vec<Algorithm>,

    /// Expected resource indicator (RFC 8707). When set, the JWT must contain a
    /// `resource` claim matching this value. This prevents a token scoped for one
    /// MCP server from being replayed against a different server.
    pub expected_resource: Option<String>,

    /// Allowable clock skew when validating `exp`, `nbf`, and `iat` claims.
    /// Accounts for clock drift between the authorization server and this proxy.
    pub clock_skew_leeway: Duration,

    /// When true, tokens without an `aud` claim are rejected even if the
    /// `jsonwebtoken` library would otherwise accept them.
    pub require_audience: bool,

    /// DPoP enforcement mode (`off`, `optional`, `required`).
    pub dpop_mode: DpopMode,

    /// Allowed algorithms for DPoP proof JWTs.
    pub dpop_allowed_algorithms: Vec<Algorithm>,

    /// When true, require `ath` (access token hash) claim in DPoP proofs.
    pub dpop_require_ath: bool,

    /// Maximum absolute clock skew for DPoP `iat` validation.
    pub dpop_max_clock_skew: Duration,
}

/// Default allowed algorithms for OAuth 2.1 — asymmetric only.
///
/// HMAC algorithms (HS256/HS384/HS512) are excluded to prevent algorithm
/// confusion attacks where the attacker uses the server's public key as
/// an HMAC secret.
pub fn default_allowed_algorithms() -> Vec<Algorithm> {
    vec![
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::ES256,
        Algorithm::ES384,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
        Algorithm::EdDSA,
    ]
}

/// Default allowed algorithms for DPoP proofs.
///
/// We default to modern asymmetric signature algorithms.
pub fn default_dpop_allowed_algorithms() -> Vec<Algorithm> {
    vec![Algorithm::ES256, Algorithm::EdDSA]
}

impl OAuthConfig {
    /// Resolve the JWKS URI, falling back to well-known discovery.
    pub fn effective_jwks_uri(&self) -> String {
        self.jwks_uri.clone().unwrap_or_else(|| {
            let base = self.issuer.trim_end_matches('/');
            format!("{}/.well-known/jwks.json", base)
        })
    }
}

/// Extract a bearer token from an Authorization header value.
pub fn extract_bearer_token(auth_header: &str) -> Result<&str, OAuthError> {
    // SECURITY (R28-PROXY-1): Per RFC 7235 §2.1, the authentication scheme
    // is case-insensitive. Accept "bearer", "Bearer", "BEARER", etc.
    let token = if auth_header.len() > 7 && auth_header[..7].eq_ignore_ascii_case("bearer ") {
        &auth_header[7..]
    } else {
        return Err(OAuthError::InvalidFormat);
    };

    if token.is_empty() {
        return Err(OAuthError::InvalidFormat);
    }

    Ok(token)
}

/// Extracted and validated claims from a JWT token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    /// Subject identifier (the authenticated user/client).
    #[serde(default)]
    pub sub: String,

    /// Issuer.
    #[serde(default)]
    pub iss: String,

    /// Audience (can be a single string or array; we normalize to Vec).
    #[serde(default, deserialize_with = "deserialize_aud")]
    pub aud: Vec<String>,

    /// Expiry (Unix timestamp).
    #[serde(default)]
    pub exp: u64,

    /// Issued-at (Unix timestamp).
    #[serde(default)]
    pub iat: u64,

    /// Space-delimited scope string (OAuth 2.1 convention).
    #[serde(default)]
    pub scope: String,

    /// Resource indicator (RFC 8707). Identifies which resource server this
    /// token is scoped to. May be a single string or absent.
    #[serde(default)]
    pub resource: Option<String>,

    /// Token confirmation claim (RFC 7800 / RFC 9449).
    /// When present with `cnf.jkt`, binds the access token to a DPoP key.
    #[serde(default)]
    pub cnf: Option<OAuthConfirmationClaim>,
}

/// OAuth token confirmation (`cnf`) claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfirmationClaim {
    /// JWK thumbprint (RFC 7638) for sender-constrained token binding.
    #[serde(default)]
    pub jkt: Option<String>,
}

/// Claims expected in a DPoP proof JWT (RFC 9449).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DpopClaims {
    #[serde(default)]
    htm: String,
    #[serde(default)]
    htu: String,
    #[serde(default)]
    iat: u64,
    #[serde(default)]
    jti: String,
    #[serde(default)]
    ath: Option<String>,
}

impl OAuthClaims {
    /// Return the individual scopes as a Vec.
    pub fn scopes(&self) -> Vec<&str> {
        if self.scope.is_empty() {
            Vec::new()
        } else {
            self.scope.split(' ').filter(|s| !s.is_empty()).collect()
        }
    }
}

/// Custom deserializer for the `aud` claim which can be a string or array.
fn deserialize_aud<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct AudVisitor;

    impl<'de> de::Visitor<'de> for AudVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while let Some(v) = seq.next_element::<String>()? {
                values.push(v);
            }
            Ok(values)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(AudVisitor)
}

fn jwk_required_str_field<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, OAuthError> {
    obj.get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| OAuthError::InvalidDpopProof(format!("DPoP JWK missing '{field}' field")))
}

/// Compute RFC 7638 SHA-256 thumbprint for the DPoP header JWK.
///
/// We avoid `Jwk::thumbprint()` because that implementation may panic on
/// malformed/inconsistent key material; this helper must remain fully fallible.
fn dpop_jwk_thumbprint_sha256(jwk: &jsonwebtoken::jwk::Jwk) -> Result<String, OAuthError> {
    let value = serde_json::to_value(jwk)
        .map_err(|e| OAuthError::InvalidDpopProof(format!("invalid DPoP JWK: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| OAuthError::InvalidDpopProof("invalid DPoP JWK object".to_string()))?;

    let kty = jwk_required_str_field(obj, "kty")?;

    let canonical = match kty {
        "EC" => {
            let crv = jwk_required_str_field(obj, "crv")?;
            let x = jwk_required_str_field(obj, "x")?;
            let y = jwk_required_str_field(obj, "y")?;
            format!(
                r#"{{"crv":{},"kty":{},"x":{},"y":{}}}"#,
                serde_json::to_string(crv).map_err(|e| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK curve: {e}"))
                })?,
                serde_json::to_string(kty).map_err(|e| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK type: {e}"))
                })?,
                serde_json::to_string(x).map_err(|e| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK x: {e}"))
                })?,
                serde_json::to_string(y).map_err(|e| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK y: {e}"))
                })?
            )
        }
        "OKP" => {
            let crv = jwk_required_str_field(obj, "crv")?;
            let x = jwk_required_str_field(obj, "x")?;
            format!(
                r#"{{"crv":{},"kty":{},"x":{}}}"#,
                serde_json::to_string(crv).map_err(|e| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK curve: {e}"))
                })?,
                serde_json::to_string(kty).map_err(|e| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK type: {e}"))
                })?,
                serde_json::to_string(x).map_err(|e| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK x: {e}"))
                })?
            )
        }
        "RSA" => {
            let e = jwk_required_str_field(obj, "e")?;
            let n = jwk_required_str_field(obj, "n")?;
            format!(
                r#"{{"e":{},"kty":{},"n":{}}}"#,
                serde_json::to_string(e).map_err(|err| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK e: {err}"))
                })?,
                serde_json::to_string(kty).map_err(|err| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK type: {err}"))
                })?,
                serde_json::to_string(n).map_err(|err| {
                    OAuthError::InvalidDpopProof(format!("failed to encode JWK n: {err}"))
                })?
            )
        }
        _ => {
            return Err(OAuthError::InvalidDpopProof(format!(
                "unsupported DPoP JWK key type '{kty}'"
            )));
        }
    };

    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

/// OAuth validation errors.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("missing Authorization header")]
    MissingToken,

    #[error("invalid Authorization header format (expected: Bearer <token>)")]
    InvalidFormat,

    #[error("JWT validation failed: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("insufficient scope: required {required}, found {found}")]
    InsufficientScope { required: String, found: String },

    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),

    #[error("no matching key found in JWKS for kid '{0}'")]
    NoMatchingKey(String),

    #[error("disallowed algorithm: {0:?} is not in the allowed list")]
    DisallowedAlgorithm(Algorithm),

    #[error("token missing 'kid' header but JWKS contains {0} keys — ambiguous key selection")]
    MissingKid(usize),

    #[error("resource mismatch: token resource '{token}' does not match expected '{expected}' (RFC 8707)")]
    ResourceMismatch { expected: String, token: String },

    #[error("token missing required 'aud' claim")]
    MissingAudience,

    #[error("token audience mismatch: expected '{expected}', found '{found}'")]
    AudienceMismatch { expected: String, found: String },

    #[error("authorization server does not support PKCE (S256)")]
    PkceNotSupported,

    #[error("missing DPoP proof header")]
    MissingDpopProof,

    #[error("invalid DPoP proof: {0}")]
    InvalidDpopProof(String),

    #[error("DPoP replay detected")]
    DpopReplayDetected,
}

/// Cached JWKS key set with TTL-based refresh.
struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

/// JWT token validator with JWKS key caching.
///
/// Thread-safe — can be shared across handlers via `Arc`.
pub struct OAuthValidator {
    config: OAuthConfig,
    http_client: reqwest::Client,
    jwks_cache: RwLock<Option<CachedJwks>>,
    /// How long to cache JWKS keys before re-fetching.
    cache_ttl: Duration,
    /// Recently seen DPoP JTIs for replay detection.
    dpop_jti_cache: RwLock<VecDeque<(String, u64)>>,
}

impl OAuthValidator {
    /// Create a new validator with the given configuration.
    ///
    /// The `http_client` is reused from the proxy's existing reqwest client.
    pub fn new(config: OAuthConfig, http_client: reqwest::Client) -> Self {
        Self {
            config,
            http_client,
            jwks_cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(300), // 5 minute JWKS cache TTL
            dpop_jti_cache: RwLock::new(VecDeque::new()),
        }
    }

    /// Validate a Bearer token from the Authorization header value.
    ///
    /// Returns the validated claims on success.
    pub async fn validate_token(&self, auth_header: &str) -> Result<OAuthClaims, OAuthError> {
        let token = extract_bearer_token(auth_header)?;

        // Decode header to find the key ID (kid)
        let header = decode_header(token)?;

        // Challenge 11 fix: Reject algorithms not in the allowed list.
        // Prevents algorithm confusion attacks (e.g., HS256 with RSA public key).
        // NOTE (FIND-039 false positive): jsonwebtoken v10 does not have an
        // Algorithm::None variant — the "none" algorithm cannot be represented
        // in this library's type system. A token with alg="none" will fail at
        // decode_header() above since it cannot be deserialized into Algorithm.
        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(OAuthError::DisallowedAlgorithm(header.alg));
        }

        let kid = header.kid.clone().unwrap_or_default();

        // Get the decoding key from JWKS
        let decoding_key = self.get_decoding_key(&kid, &header.alg).await?;

        // Build validation parameters — use the verified algorithm
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;
        validation.validate_nbf = true; // Challenge 14 fix: reject tokens before nbf
        validation.leeway = self.config.clock_skew_leeway.as_secs();

        // Decode and validate
        let token_data: TokenData<OAuthClaims> = decode(token, &decoding_key, &validation)?;
        let claims = token_data.claims;

        if claims.aud.is_empty() {
            if self.config.require_audience {
                return Err(OAuthError::MissingAudience);
            }
        } else if !claims.aud.iter().any(|aud| aud == &self.config.audience) {
            return Err(OAuthError::AudienceMismatch {
                expected: self.config.audience.clone(),
                found: claims.aud.join(" "),
            });
        }

        // Check required scopes
        if !self.config.required_scopes.is_empty() {
            let token_scopes = claims.scopes();
            for required in &self.config.required_scopes {
                if !token_scopes.contains(&required.as_str()) {
                    return Err(OAuthError::InsufficientScope {
                        required: self.config.required_scopes.join(" "),
                        found: claims.scope.clone(),
                    });
                }
            }
        }

        // RFC 8707: Check resource indicator if configured.
        // Prevents token replay attacks where a token scoped to one MCP server
        // is used against a different server.
        if let Some(ref expected_resource) = self.config.expected_resource {
            match &claims.resource {
                Some(token_resource) if token_resource == expected_resource => {
                    // Match — continue
                }
                Some(token_resource) => {
                    return Err(OAuthError::ResourceMismatch {
                        expected: expected_resource.clone(),
                        token: token_resource.clone(),
                    });
                }
                None => {
                    return Err(OAuthError::ResourceMismatch {
                        expected: expected_resource.clone(),
                        token: String::new(),
                    });
                }
            }
        }

        if self.config.dpop_mode == DpopMode::Required {
            let token_jkt = claims
                .cnf
                .as_ref()
                .and_then(|cnf| cnf.jkt.as_deref())
                .map(str::trim)
                .filter(|jkt| !jkt.is_empty());

            if token_jkt.is_none() {
                return Err(OAuthError::InvalidDpopProof(
                    "missing cnf.jkt in access token for required DPoP mode".to_string(),
                ));
            }
        }

        Ok(claims)
    }

    /// Validate a DPoP proof for an already-authenticated access token.
    pub async fn validate_dpop_proof(
        &self,
        dpop_header: Option<&str>,
        access_token: &str,
        expected_method: &str,
        expected_uri: &str,
        token_claims: Option<&OAuthClaims>,
    ) -> Result<(), OAuthError> {
        match self.config.dpop_mode {
            DpopMode::Off => return Ok(()),
            DpopMode::Optional if dpop_header.is_none() => return Ok(()),
            DpopMode::Required if dpop_header.is_none() => {
                return Err(OAuthError::MissingDpopProof)
            }
            _ => {}
        }

        let proof_jwt = dpop_header
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or(OAuthError::MissingDpopProof)?;

        let header = decode_header(proof_jwt)?;

        if !self.config.dpop_allowed_algorithms.contains(&header.alg) {
            return Err(OAuthError::DisallowedAlgorithm(header.alg));
        }

        let has_dpop_typ = header
            .typ
            .as_deref()
            .map(|typ| typ.eq_ignore_ascii_case("dpop+jwt"))
            .unwrap_or(false);
        if !has_dpop_typ {
            return Err(OAuthError::InvalidDpopProof(
                "missing typ=dpop+jwt header".to_string(),
            ));
        }

        let jwk = header.jwk.ok_or_else(|| {
            OAuthError::InvalidDpopProof("missing embedded JWK in DPoP header".to_string())
        })?;
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| OAuthError::InvalidDpopProof(format!("invalid DPoP JWK: {}", e)))?;

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims.clear();
        let token_data: TokenData<DpopClaims> = decode(proof_jwt, &decoding_key, &validation)?;
        let claims = token_data.claims;

        if claims.htm.is_empty() || !claims.htm.eq_ignore_ascii_case(expected_method) {
            return Err(OAuthError::InvalidDpopProof(format!(
                "htm mismatch: expected '{}', got '{}'",
                expected_method, claims.htm
            )));
        }

        if claims.htu.trim_end_matches('/') != expected_uri.trim_end_matches('/') {
            return Err(OAuthError::InvalidDpopProof(format!(
                "htu mismatch: expected '{}', got '{}'",
                expected_uri, claims.htu
            )));
        }

        if claims.jti.trim().is_empty() {
            return Err(OAuthError::InvalidDpopProof("missing jti".to_string()));
        }
        // Bound untrusted claim size to avoid cache key memory abuse.
        if claims.jti.len() > 256 {
            return Err(OAuthError::InvalidDpopProof(
                "jti exceeds maximum length".to_string(),
            ));
        }

        let now = chrono::Utc::now().timestamp();
        let iat = claims.iat as i64;
        let skew = self.config.dpop_max_clock_skew.as_secs() as i64;
        if (now - iat).abs() > skew {
            return Err(OAuthError::InvalidDpopProof(format!(
                "iat outside allowed skew window (iat={}, now={})",
                claims.iat, now
            )));
        }

        if self.config.dpop_require_ath {
            let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
            match claims.ath.as_deref() {
                Some(ath) if ath == expected_ath => {}
                _ => {
                    return Err(OAuthError::InvalidDpopProof(
                        "ath mismatch for access token binding".to_string(),
                    ));
                }
            }
        }

        if let Some(token_jkt) = token_claims
            .and_then(|c| c.cnf.as_ref())
            .and_then(|cnf| cnf.jkt.as_deref())
            .map(str::trim)
            .filter(|jkt| !jkt.is_empty())
        {
            let proof_jkt = dpop_jwk_thumbprint_sha256(&jwk)?;
            if proof_jkt != token_jkt {
                return Err(OAuthError::InvalidDpopProof(
                    "cnf.jkt does not match DPoP proof key thumbprint".to_string(),
                ));
            }
        }

        // Replay protection: reject reused JTIs within the replay window.
        let now_u64 = now.max(0) as u64;
        let replay_window = std::cmp::max((skew.max(0) as u64) * 2, 600);
        let oldest_allowed = now_u64.saturating_sub(replay_window);

        let mut cache = self.dpop_jti_cache.write().await;
        while let Some((_, ts)) = cache.front() {
            if *ts < oldest_allowed {
                cache.pop_front();
            } else {
                break;
            }
        }

        // Replay key is token-bound when `ath` is present to avoid false
        // positives across distinct tokens that reuse the same JTI value.
        let replay_key = match claims.ath.as_deref() {
            Some(ath) if !ath.is_empty() => format!("{}:{}", claims.jti, ath),
            _ => claims.jti.clone(),
        };
        if replay_key.len() > 512 {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP replay key exceeds maximum length".to_string(),
            ));
        }

        if cache.iter().any(|(cached, _)| cached == &replay_key) {
            return Err(OAuthError::DpopReplayDetected);
        }

        cache.push_back((replay_key, now_u64));
        if cache.len() > 8192 {
            cache.pop_front();
        }

        Ok(())
    }

    /// Get a decoding key from the cached JWKS, refreshing if stale.
    ///
    /// Uses a read lock for the fast path and upgrades to a write lock only on
    /// cache miss. After acquiring the write lock we double-check freshness to
    /// avoid redundant fetches when multiple tasks race on a stale cache.
    async fn get_decoding_key(
        &self,
        kid: &str,
        alg: &Algorithm,
    ) -> Result<DecodingKey, OAuthError> {
        // Fast path — read lock only
        {
            let cache = self.jwks_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    if let Some(key) = find_key_in_jwks(&cached.keys, kid, alg) {
                        return Ok(key);
                    }
                }
            }
        }
        // Read lock dropped here

        // Slow path — acquire write lock, then double-check before fetching
        let mut cache = self.jwks_cache.write().await;

        // Double-check: another task may have refreshed while we waited for the lock
        if let Some(cached) = cache.as_ref() {
            if cached.fetched_at.elapsed() < self.cache_ttl {
                if let Some(key) = find_key_in_jwks(&cached.keys, kid, alg) {
                    return Ok(key);
                }
            }
        }

        // Fetch JWKS while holding the write lock
        let jwks = self.fetch_jwks().await?;

        // Challenge 12 fix: Require kid when JWKS has multiple keys.
        // Without kid, a token could match any key — dangerous if JWKS
        // contains test keys, rotated keys, or keys from other services.
        if kid.is_empty() && jwks.keys.len() > 1 {
            return Err(OAuthError::MissingKid(jwks.keys.len()));
        }

        let key = find_key_in_jwks(&jwks, kid, alg)
            .ok_or_else(|| OAuthError::NoMatchingKey(kid.to_string()))?;

        // Update cache while still holding the write lock
        *cache = Some(CachedJwks {
            keys: jwks,
            fetched_at: Instant::now(),
        });

        Ok(key)
    }

    /// Fetch the JWKS key set from the configured endpoint.
    async fn fetch_jwks(&self) -> Result<JwkSet, OAuthError> {
        let uri = self.config.effective_jwks_uri();

        tracing::debug!("Fetching JWKS from {}", uri);

        let response = self
            .http_client
            .get(&uri)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| OAuthError::JwksFetchFailed(format!("request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(OAuthError::JwksFetchFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        // SECURITY (R24-PROXY-2): Bound JWKS response body to prevent OOM
        // from oversized responses. 1 MB is generous for any legitimate JWKS.
        const MAX_JWKS_BODY_SIZE: usize = 1024 * 1024;
        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| OAuthError::JwksFetchFailed(format!("body read failed: {}", e)))?;
        if body_bytes.len() > MAX_JWKS_BODY_SIZE {
            return Err(OAuthError::JwksFetchFailed(format!(
                "JWKS response too large ({} bytes, max {} bytes)",
                body_bytes.len(),
                MAX_JWKS_BODY_SIZE
            )));
        }
        let jwks: JwkSet = serde_json::from_slice(&body_bytes)
            .map_err(|e| OAuthError::JwksFetchFailed(format!("invalid JWKS JSON: {}", e)))?;

        tracing::info!("Fetched {} keys from JWKS endpoint", jwks.keys.len());

        Ok(jwks)
    }

    /// Get the OAuth config (for pass-through decisions).
    pub fn config(&self) -> &OAuthConfig {
        &self.config
    }
}

/// Convert a JWK `KeyAlgorithm` to a JWT `Algorithm` using explicit matching.
///
/// Returns `None` for encryption-only algorithms (RSA1_5, RSA_OAEP, RSA_OAEP_256)
/// that have no corresponding signing algorithm.
fn key_algorithm_to_algorithm(ka: &KeyAlgorithm) -> Option<Algorithm> {
    match ka {
        KeyAlgorithm::HS256 => Some(Algorithm::HS256),
        KeyAlgorithm::HS384 => Some(Algorithm::HS384),
        KeyAlgorithm::HS512 => Some(Algorithm::HS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        // Encryption-only algorithms have no signing equivalent
        _ => None,
    }
}

/// Find a matching decoding key in the JWKS by key ID and algorithm.
///
/// SECURITY (R22-PROXY-2): When the token specifies a `kid`, we REQUIRE
/// the JWK to also have a `kid` and it must match. Previously, a JWK
/// without a `kid` field would match *any* token kid, allowing an attacker
/// to use a kidless JWK as a wildcard to validate tokens with arbitrary
/// kid values. Per RFC 7517 §4.5, kid is OPTIONAL, but when the token
/// asserts one we must only accept exact matches.
fn find_key_in_jwks(jwks: &JwkSet, kid: &str, alg: &Algorithm) -> Option<DecodingKey> {
    for key in &jwks.keys {
        // Match by kid if provided
        if !kid.is_empty() {
            match &key.common.key_id {
                Some(key_kid) if key_kid == kid => {} // exact match — continue
                Some(_) => continue,                  // kid mismatch — skip
                None => continue,                     // no kid on JWK — skip (R22-PROXY-2)
            }
        }

        // Challenge 13 fix: Match algorithm via explicit mapping, not Debug format.
        if let Some(ref key_alg) = key.common.key_algorithm {
            match key_algorithm_to_algorithm(key_alg) {
                Some(mapped) if &mapped == alg => {} // match — continue to key construction
                _ => continue,                       // no match or encryption-only — skip
            }
        }

        // Try to construct a DecodingKey from the JWK
        if let Ok(dk) = DecodingKey::from_jwk(key) {
            return Some(dk);
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════
// PKCE Verification (MCP Spec Compliance)
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that the authorization server supports PKCE with S256 method.
///
/// PKCE (Proof Key for Code Exchange) prevents authorization code interception
/// attacks. The MCP specification requires OAuth 2.1 flows, which mandate PKCE.
/// This function checks the authorization server metadata to ensure S256 is
/// supported before initiating an OAuth flow.
///
/// # Arguments
/// * `metadata` - The authorization server metadata (from `.well-known/oauth-authorization-server`)
///
/// # Returns
/// * `Ok(())` if S256 is supported
/// * `Err(OAuthError::PkceNotSupported)` if S256 is not listed in `code_challenge_methods_supported`
///
/// # Example
/// ```ignore
/// use serde_json::json;
/// use sentinel_http_proxy::oauth::verify_pkce_support;
///
/// let metadata = json!({
///     "issuer": "https://auth.example.com",
///     "code_challenge_methods_supported": ["S256", "plain"]
/// });
/// assert!(verify_pkce_support(&metadata).is_ok());
///
/// let no_pkce = json!({"issuer": "https://auth.example.com"});
/// assert!(verify_pkce_support(&no_pkce).is_err());
/// ```
pub fn verify_pkce_support(metadata: &serde_json::Value) -> Result<(), OAuthError> {
    let supported = metadata
        .get("code_challenge_methods_supported")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(|m| m.as_str() == Some("S256")))
        .unwrap_or(false);

    if !supported {
        return Err(OAuthError::PkceNotSupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_config_effective_jwks_uri_explicit() {
        let config = OAuthConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "mcp-server".to_string(),
            jwks_uri: Some("https://auth.example.com/keys".to_string()),
            required_scopes: vec![],
            pass_through: false,
            allowed_algorithms: default_allowed_algorithms(),
            expected_resource: None,
            clock_skew_leeway: Duration::from_secs(30),
            require_audience: true,
            dpop_mode: DpopMode::Off,
            dpop_allowed_algorithms: default_dpop_allowed_algorithms(),
            dpop_require_ath: true,
            dpop_max_clock_skew: Duration::from_secs(300),
        };
        assert_eq!(config.effective_jwks_uri(), "https://auth.example.com/keys");
    }

    #[test]
    fn test_oauth_config_effective_jwks_uri_wellknown() {
        let config = OAuthConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "mcp-server".to_string(),
            jwks_uri: None,
            required_scopes: vec![],
            pass_through: false,
            allowed_algorithms: default_allowed_algorithms(),
            expected_resource: None,
            clock_skew_leeway: Duration::from_secs(30),
            require_audience: true,
            dpop_mode: DpopMode::Off,
            dpop_allowed_algorithms: default_dpop_allowed_algorithms(),
            dpop_require_ath: true,
            dpop_max_clock_skew: Duration::from_secs(300),
        };
        assert_eq!(
            config.effective_jwks_uri(),
            "https://auth.example.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn test_oauth_config_effective_jwks_uri_trailing_slash() {
        let config = OAuthConfig {
            issuer: "https://auth.example.com/".to_string(),
            audience: "mcp-server".to_string(),
            jwks_uri: None,
            required_scopes: vec![],
            pass_through: false,
            allowed_algorithms: default_allowed_algorithms(),
            expected_resource: None,
            clock_skew_leeway: Duration::from_secs(30),
            require_audience: true,
            dpop_mode: DpopMode::Off,
            dpop_allowed_algorithms: default_dpop_allowed_algorithms(),
            dpop_require_ath: true,
            dpop_max_clock_skew: Duration::from_secs(300),
        };
        assert_eq!(
            config.effective_jwks_uri(),
            "https://auth.example.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn test_oauth_claims_scopes_parsing() {
        let claims = OAuthClaims {
            sub: "user-123".to_string(),
            iss: "https://auth.example.com".to_string(),
            aud: vec!["mcp-server".to_string()],
            exp: 0,
            iat: 0,
            scope: "tools.call resources.read admin".to_string(),
            resource: None,
            cnf: None,
        };
        let scopes = claims.scopes();
        assert_eq!(scopes, vec!["tools.call", "resources.read", "admin"]);
    }

    #[test]
    fn test_oauth_claims_empty_scope() {
        let claims = OAuthClaims {
            sub: "user-123".to_string(),
            iss: "https://auth.example.com".to_string(),
            aud: vec![],
            exp: 0,
            iat: 0,
            scope: String::new(),
            resource: None,
            cnf: None,
        };
        let scopes = claims.scopes();
        assert!(scopes.is_empty());
    }

    #[test]
    fn test_deserialize_aud_string() {
        let json = r#"{"sub":"user","aud":"mcp-server","scope":""}"#;
        let claims: OAuthClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, vec!["mcp-server"]);
    }

    #[test]
    fn test_deserialize_aud_array() {
        let json = r#"{"sub":"user","aud":["mcp-server","other"],"scope":""}"#;
        let claims: OAuthClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, vec!["mcp-server", "other"]);
    }

    #[test]
    fn test_oauth_error_display() {
        let err = OAuthError::MissingToken;
        assert_eq!(err.to_string(), "missing Authorization header");

        let err = OAuthError::InsufficientScope {
            required: "tools.call admin".to_string(),
            found: "tools.call".to_string(),
        };
        assert!(err.to_string().contains("insufficient scope"));
    }

    // Challenge 11: Algorithm confusion prevention
    #[test]
    fn test_default_allowed_algorithms_excludes_hmac() {
        let allowed = default_allowed_algorithms();
        assert!(!allowed.contains(&Algorithm::HS256));
        assert!(!allowed.contains(&Algorithm::HS384));
        assert!(!allowed.contains(&Algorithm::HS512));
    }

    #[test]
    fn test_default_allowed_algorithms_includes_asymmetric() {
        let allowed = default_allowed_algorithms();
        assert!(allowed.contains(&Algorithm::RS256));
        assert!(allowed.contains(&Algorithm::ES256));
        assert!(allowed.contains(&Algorithm::PS256));
        assert!(allowed.contains(&Algorithm::EdDSA));
    }

    #[test]
    fn test_disallowed_algorithm_error_display() {
        let err = OAuthError::DisallowedAlgorithm(Algorithm::HS256);
        assert!(err.to_string().contains("disallowed algorithm"));
        assert!(err.to_string().contains("HS256"));
    }

    #[test]
    fn test_missing_kid_error_display() {
        let err = OAuthError::MissingKid(3);
        assert!(err.to_string().contains("missing 'kid'"));
        assert!(err.to_string().contains("3 keys"));
    }

    // Challenge 13: Explicit algorithm mapping
    #[test]
    fn test_key_algorithm_to_algorithm_all_signing() {
        assert_eq!(
            key_algorithm_to_algorithm(&KeyAlgorithm::HS256),
            Some(Algorithm::HS256)
        );
        assert_eq!(
            key_algorithm_to_algorithm(&KeyAlgorithm::RS256),
            Some(Algorithm::RS256)
        );
        assert_eq!(
            key_algorithm_to_algorithm(&KeyAlgorithm::ES256),
            Some(Algorithm::ES256)
        );
        assert_eq!(
            key_algorithm_to_algorithm(&KeyAlgorithm::PS256),
            Some(Algorithm::PS256)
        );
        assert_eq!(
            key_algorithm_to_algorithm(&KeyAlgorithm::EdDSA),
            Some(Algorithm::EdDSA)
        );
    }

    #[test]
    fn test_key_algorithm_to_algorithm_encryption_returns_none() {
        assert_eq!(key_algorithm_to_algorithm(&KeyAlgorithm::RSA1_5), None);
        assert_eq!(key_algorithm_to_algorithm(&KeyAlgorithm::RSA_OAEP), None);
        assert_eq!(
            key_algorithm_to_algorithm(&KeyAlgorithm::RSA_OAEP_256),
            None
        );
    }

    // RFC 8707: Resource indicator validation
    #[test]
    fn test_resource_mismatch_error_display() {
        let err = OAuthError::ResourceMismatch {
            expected: "https://mcp.example.com".to_string(),
            token: "https://other.example.com".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("resource mismatch"));
        assert!(msg.contains("https://mcp.example.com"));
        assert!(msg.contains("https://other.example.com"));
        assert!(msg.contains("RFC 8707"));
    }

    #[test]
    fn test_resource_mismatch_missing_claim_error_display() {
        let err = OAuthError::ResourceMismatch {
            expected: "https://mcp.example.com".to_string(),
            token: String::new(),
        };
        let msg = err.to_string();
        assert!(msg.contains("resource mismatch"));
        assert!(msg.contains("https://mcp.example.com"));
    }

    #[test]
    fn test_deserialize_claims_with_resource() {
        let json =
            r#"{"sub":"user","aud":"mcp-server","scope":"","resource":"https://mcp.example.com"}"#;
        let claims: OAuthClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.resource, Some("https://mcp.example.com".to_string()));
    }

    #[test]
    fn test_deserialize_claims_without_resource() {
        let json = r#"{"sub":"user","aud":"mcp-server","scope":""}"#;
        let claims: OAuthClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.resource, None);
    }

    #[test]
    fn test_deserialize_claims_with_cnf_jkt() {
        let json = r#"{"sub":"user","aud":"mcp-server","scope":"","cnf":{"jkt":"thumbprint-123"}}"#;
        let claims: OAuthClaims = serde_json::from_str(json).unwrap();
        let jkt = claims
            .cnf
            .as_ref()
            .and_then(|cnf| cnf.jkt.as_deref())
            .expect("cnf.jkt must deserialize");
        assert_eq!(jkt, "thumbprint-123");
    }

    #[test]
    fn test_dpop_jwk_thumbprint_sha256_rsa() {
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }))
        .expect("valid RSA JWK");

        let thumbprint = dpop_jwk_thumbprint_sha256(&jwk).expect("thumbprint should compute");
        assert_eq!(thumbprint, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn test_dpop_jwk_thumbprint_rejects_unsupported_key_type() {
        let jwk: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(serde_json::json!({"kty": "oct", "k": "AQAB"}))
                .expect("valid octet JWK");

        let err = dpop_jwk_thumbprint_sha256(&jwk).expect_err("octet keys are not valid for DPoP");
        assert!(err.to_string().contains("unsupported DPoP JWK key type"));
    }

    #[test]
    fn test_clock_skew_leeway_configurable() {
        let config = OAuthConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "mcp-server".to_string(),
            jwks_uri: None,
            required_scopes: vec![],
            pass_through: false,
            allowed_algorithms: default_allowed_algorithms(),
            expected_resource: None,
            clock_skew_leeway: Duration::from_secs(60),
            require_audience: true,
            dpop_mode: DpopMode::Off,
            dpop_allowed_algorithms: default_dpop_allowed_algorithms(),
            dpop_require_ath: true,
            dpop_max_clock_skew: Duration::from_secs(300),
        };
        assert_eq!(config.clock_skew_leeway, Duration::from_secs(60));
    }

    #[test]
    fn test_deserialize_missing_aud_yields_empty_vec() {
        let json = r#"{"sub":"user","scope":"read"}"#;
        let claims: OAuthClaims = serde_json::from_str(json).unwrap();
        assert!(claims.aud.is_empty());
    }

    #[test]
    fn test_missing_audience_error_display() {
        let err = OAuthError::MissingAudience;
        assert_eq!(err.to_string(), "token missing required 'aud' claim");
    }

    #[test]
    fn test_audience_mismatch_error_display() {
        let err = OAuthError::AudienceMismatch {
            expected: "mcp-server".to_string(),
            found: "other-aud".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("audience mismatch"));
        assert!(msg.contains("mcp-server"));
        assert!(msg.contains("other-aud"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PKCE Verification Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verify_pkce_support_s256_supported() {
        let metadata = serde_json::json!({
            "issuer": "https://auth.example.com",
            "code_challenge_methods_supported": ["S256", "plain"]
        });
        assert!(verify_pkce_support(&metadata).is_ok());
    }

    #[test]
    fn test_verify_pkce_support_s256_only() {
        let metadata = serde_json::json!({
            "issuer": "https://auth.example.com",
            "code_challenge_methods_supported": ["S256"]
        });
        assert!(verify_pkce_support(&metadata).is_ok());
    }

    #[test]
    fn test_verify_pkce_support_missing_field() {
        let metadata = serde_json::json!({
            "issuer": "https://auth.example.com"
        });
        let result = verify_pkce_support(&metadata);
        assert!(matches!(result, Err(OAuthError::PkceNotSupported)));
    }

    #[test]
    fn test_verify_pkce_support_plain_only() {
        // Plain is not secure - we require S256
        let metadata = serde_json::json!({
            "issuer": "https://auth.example.com",
            "code_challenge_methods_supported": ["plain"]
        });
        let result = verify_pkce_support(&metadata);
        assert!(matches!(result, Err(OAuthError::PkceNotSupported)));
    }

    #[test]
    fn test_verify_pkce_support_empty_array() {
        let metadata = serde_json::json!({
            "issuer": "https://auth.example.com",
            "code_challenge_methods_supported": []
        });
        let result = verify_pkce_support(&metadata);
        assert!(matches!(result, Err(OAuthError::PkceNotSupported)));
    }

    #[test]
    fn test_pkce_not_supported_error_display() {
        let err = OAuthError::PkceNotSupported;
        assert!(err.to_string().contains("PKCE"));
        assert!(err.to_string().contains("S256"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FIND-045: End-to-End JWT Validation Tests
    //
    // These tests exercise the full validate_token() flow:
    //   sign JWT → start mock JWKS server → create OAuthValidator → validate
    //
    // This catches integration bugs that unit tests miss:
    //   - JWKS fetch + key matching + signature verification
    //   - Algorithm allowlist enforcement on real tokens
    //   - Claim validation (exp, iss, aud, scope, resource) on real tokens
    //   - kid matching with multi-key JWKS
    // ═══════════════════════════════════════════════════════════════════════════

    // Hardcoded RSA 2048-bit test key pair (generated offline, not a real secret).
    const TEST_RSA_PRIVATE_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDXsFTcrmrrw3RK
Ll2pK5mhqySdvuoQY/U1CwFXmu1S2BAEnh+/Yzsilc/LWJjBmcDdmY88NC+F8PhO
q6+hQjWZR08QewinBg69w2+TRqr4x09XXZm/w3Y+jOlspHR85PISy8sqkHzGk3o4
cLNCxDkw2mwQaVDQQz1YJ0x22+IoOZniRTntUK1yAyI0jqhpZJjn9dY+CbDt/H8B
nGollAlhKQFizDAIMYOL/duJLJv1jtgv5hwvH94tSYgLGzJcufmxvioBBD4ZcxDq
Lk2vNdC5ETVkS9GeyYfuQbHW55lYSACe2NfYwgwYc3PO6X6PlJxuksL7JfR6kivU
WkYHOTVLAgMBAAECggEATuXElRkEKYvMrRn6ztgREa9N7JoaerZlyupkqkwUxfod
GeNRj6vXxNXyNdsJvb/laeozF/2q6J715aktzJowiwonpMqsppQzrjygQspV3jzi
C/5EMH5qcYUQGdqqdck1t6Rug/poeicWTTEEkca/eNxdLT+o/RWrieSONuhF+Ro0
7S60Dc4tFRA6XBDayikUzuFd2XoroRfoukC+HcC7mHMQdPHNt7QjORJNitdjwP+P
BcwNm61043sz9VSdW9FMtrdpg+pndbzRiYwYCDRt7r0hhUSZ4cojY6Tyoqexa5BD
7W5jDTmySO5/Jzl3QGvtevyKVx3x6DQE9858W8kucQKBgQDynqb19kVK6IFPccFX
01D9qVg0vZ1WoAR30s79DkoKA/NyM3sjP431p38Kkj1QomERBSCb0O1OOfsfjAEO
2SoEqTSa+2cgDYikQ16IEqKfbucilDNMTsYQz9Jwx16BEJRGoz+lbt52exhZN+nf
qfVtuwIvlb46bksxh5pXJ9L7wwKBgQDjlXatVjiZgigpGwmj4/Uj9tI0c+AmtooX
zA/2B3GJdXbRVtMvFsQB73/d7U2lCwUHJmG56FYS1Dg8C88Xn7nE6kBSYoeguxCA
bLPBbCGtPD/VeGP2ymxLxsULLiiRx4S+6K7hUulCkg9m3CWkc3m5AH5lrHVEXgi1
YadcFKMv2QKBgAuaJqXQdxPT9osUB4jppA/dT0iGYMXJtSz9ucREMKo18ihd6d+P
pHxA3ERnJeN7QGUN97c70H1TLH0fttU88VNzu/5FU3Mm8ofYaObc7UXuicMPjzxw
7+vR5GBcSFqnrk+Kcvq4SI8l584sbFSzzfbHYJ1h7czhhVsC/xB36RD9AoGBANQ8
JXGer6fQrp0u3r2dL5Y7bmqGCWpw3rU0k0nwRRxYk9bDbqxCQcZAUHFpBPi+HxE8
5PQXTHXAvTSaGqXASeDuR8/MnQjyioAJX1Uo/vrr7eeonyieO4IrOsSjZigU9aGH
otb0mB2B0qUs9lm3arNxV25/9tgsDVkBWa7QfCJ5AoGBAJF/XTU+YnGjQYGgxvfg
Ma5j2E3NRga/10ncKjDKbRNzLXk887xp4kl68vDTayAKGLu+ndYQ9dMpHCUTPky5
2KGQijoG2H/1Ri4JE8dGa+RbjG3gMIRIdbYApn/Q4nrAadrWrDLaTpbnAhhL95FJ
TfzccotDw2uXy3Xbwy/kdpfK
-----END PRIVATE KEY-----"#;

    // n and e in base64url for the JWKS JSON (matches the private key above).
    const TEST_RSA_N: &str = "17BU3K5q68N0Si5dqSuZoasknb7qEGP1NQsBV5rtUtgQBJ4fv2M7IpXPy1iYwZnA3ZmPPDQvhfD4TquvoUI1mUdPEHsIpwYOvcNvk0aq-MdPV12Zv8N2PozpbKR0fOTyEsvLKpB8xpN6OHCzQsQ5MNpsEGlQ0EM9WCdMdtviKDmZ4kU57VCtcgMiNI6oaWSY5_XWPgmw7fx_AZxqJZQJYSkBYswwCDGDi_3biSyb9Y7YL-YcLx_eLUmICxsyXLn5sb4qAQQ-GXMQ6i5NrzXQuRE1ZEvRnsmH7kGx1ueZWEgAntjX2MIMGHNzzul-j5ScbpLC-yX0epIr1FpGBzk1Sw";
    const TEST_RSA_E: &str = "AQAB";

    /// Build a JWKS JSON string with a single RSA key.
    fn test_jwks_json(kid: &str) -> String {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": TEST_RSA_N,
                "e": TEST_RSA_E
            }]
        })
        .to_string()
    }

    /// Start a mock JWKS server and return (base_url, join_handle).
    async fn start_mock_jwks_server(jwks_json: String) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{routing::get, Router};
        use std::net::SocketAddr;

        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let json = jwks_json.clone();
                async move {
                    (
                        [(
                            http::header::CONTENT_TYPE,
                            http::HeaderValue::from_static("application/json"),
                        )],
                        json,
                    )
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind to random port");
        let addr: SocketAddr = listener.local_addr().expect("local addr");
        let base_url = format!("http://127.0.0.1:{}", addr.port());

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock JWKS server failed");
        });

        // Give the server a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        (base_url, handle)
    }

    /// Build an OAuthConfig pointing at the mock JWKS server.
    fn test_oauth_config(jwks_url: String) -> OAuthConfig {
        OAuthConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "mcp-server".to_string(),
            jwks_uri: Some(jwks_url),
            required_scopes: vec!["tools.call".to_string()],
            pass_through: false,
            allowed_algorithms: default_allowed_algorithms(),
            expected_resource: None,
            clock_skew_leeway: Duration::from_secs(30),
            require_audience: true,
            dpop_mode: DpopMode::Off,
            dpop_allowed_algorithms: default_dpop_allowed_algorithms(),
            dpop_require_ath: true,
            dpop_max_clock_skew: Duration::from_secs(300),
        }
    }

    /// Sign a JWT with the test RSA key.
    fn sign_test_jwt(claims: &serde_json::Value, kid: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes())
            .expect("valid RSA PEM");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());

        encode(&header, claims, &key).expect("JWT signing must succeed")
    }

    /// Return valid JWT claims with sensible defaults.
    fn valid_claims() -> serde_json::Value {
        let now = chrono::Utc::now().timestamp() as u64;
        serde_json::json!({
            "sub": "user-123",
            "iss": "https://auth.example.com",
            "aud": "mcp-server",
            "exp": now + 3600,
            "iat": now,
            "nbf": now - 10,
            "scope": "tools.call resources.read"
        })
    }

    #[tokio::test]
    async fn test_e2e_valid_jwt_accepted() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let token = sign_test_jwt(&valid_claims(), kid);
        let auth_header = format!("Bearer {}", token);

        let claims = validator.validate_token(&auth_header).await
            .expect("valid JWT must be accepted");
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.iss, "https://auth.example.com");
        assert!(claims.scopes().contains(&"tools.call"));
    }

    #[tokio::test]
    async fn test_e2e_expired_jwt_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let now = chrono::Utc::now().timestamp() as u64;
        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(now - 600); // 10 minutes ago

        let token = sign_test_jwt(&claims, kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("expired JWT must be rejected");
        assert!(
            matches!(err, OAuthError::JwtError(_)),
            "expected JwtError for expired token, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_wrong_algorithm_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        // Only allow ES256 — not RS256
        let mut config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        config.allowed_algorithms = vec![Algorithm::ES256];

        let validator = OAuthValidator::new(config, reqwest::Client::new());

        // Token is signed with RS256, but we only allow ES256
        let token = sign_test_jwt(&valid_claims(), kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("RS256 JWT must be rejected when only ES256 is allowed");
        assert!(
            matches!(err, OAuthError::DisallowedAlgorithm(Algorithm::RS256)),
            "expected DisallowedAlgorithm(RS256), got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_wrong_issuer_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let mut claims = valid_claims();
        claims["iss"] = serde_json::json!("https://evil.example.com");

        let token = sign_test_jwt(&claims, kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("wrong issuer must be rejected");
        assert!(
            matches!(err, OAuthError::JwtError(_)),
            "expected JwtError for issuer mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_wrong_audience_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("wrong-audience");

        let token = sign_test_jwt(&claims, kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("wrong audience must be rejected");
        // jsonwebtoken rejects audience mismatch before our custom check
        assert!(
            matches!(err, OAuthError::JwtError(_) | OAuthError::AudienceMismatch { .. }),
            "expected audience rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_missing_required_scope_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let mut claims = valid_claims();
        claims["scope"] = serde_json::json!("resources.read"); // missing tools.call

        let token = sign_test_jwt(&claims, kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("missing required scope must be rejected");
        assert!(
            matches!(err, OAuthError::InsufficientScope { .. }),
            "expected InsufficientScope, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_resource_mismatch_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let mut config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        config.expected_resource = Some("https://mcp.example.com".to_string());

        let validator = OAuthValidator::new(config, reqwest::Client::new());

        // Token has wrong resource
        let mut claims = valid_claims();
        claims["resource"] = serde_json::json!("https://evil.example.com");

        let token = sign_test_jwt(&claims, kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("resource mismatch must be rejected");
        assert!(
            matches!(err, OAuthError::ResourceMismatch { .. }),
            "expected ResourceMismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_resource_missing_when_required_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let mut config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        config.expected_resource = Some("https://mcp.example.com".to_string());

        let validator = OAuthValidator::new(config, reqwest::Client::new());

        // Token has no resource claim
        let token = sign_test_jwt(&valid_claims(), kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("missing resource when required must be rejected");
        assert!(
            matches!(err, OAuthError::ResourceMismatch { .. }),
            "expected ResourceMismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_resource_match_accepted() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let mut config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        config.expected_resource = Some("https://mcp.example.com".to_string());

        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let mut claims = valid_claims();
        claims["resource"] = serde_json::json!("https://mcp.example.com");

        let token = sign_test_jwt(&claims, kid);
        let auth_header = format!("Bearer {}", token);

        let result = validator.validate_token(&auth_header).await;
        assert!(result.is_ok(), "matching resource must be accepted: {result:?}");
    }

    #[tokio::test]
    async fn test_e2e_kid_mismatch_rejected() {
        let jwks = test_jwks_json("server-key-1");
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        // Sign with kid "wrong-key" but JWKS only has "server-key-1"
        let token = sign_test_jwt(&valid_claims(), "wrong-key");
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("kid mismatch must be rejected");
        assert!(
            matches!(err, OAuthError::NoMatchingKey(_)),
            "expected NoMatchingKey, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_multi_key_jwks_no_kid_rejected() {
        // JWKS with two keys
        let jwks = serde_json::json!({
            "keys": [
                {
                    "kty": "RSA", "use": "sig", "alg": "RS256",
                    "kid": "key-1",
                    "n": TEST_RSA_N, "e": TEST_RSA_E
                },
                {
                    "kty": "RSA", "use": "sig", "alg": "RS256",
                    "kid": "key-2",
                    "n": TEST_RSA_N, "e": TEST_RSA_E
                }
            ]
        })
        .to_string();
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        // Sign a token with no kid header
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes())
            .expect("valid RSA PEM");
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = None; // No kid
        let token = jsonwebtoken::encode(&header, &valid_claims(), &key)
            .expect("JWT signing");
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("missing kid with multi-key JWKS must be rejected");
        assert!(
            matches!(err, OAuthError::MissingKid(2)),
            "expected MissingKid(2), got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_tampered_signature_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let token = sign_test_jwt(&valid_claims(), kid);
        // Tamper with the signature: flip the last character
        let mut tampered = token.clone();
        let last_char = tampered.pop().unwrap_or('A');
        tampered.push(if last_char == 'A' { 'B' } else { 'A' });

        let auth_header = format!("Bearer {}", tampered);

        let err = validator.validate_token(&auth_header).await
            .expect_err("tampered signature must be rejected");
        assert!(
            matches!(err, OAuthError::JwtError(_)),
            "expected JwtError for signature tampering, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_missing_audience_with_require_audience_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let mut config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        config.require_audience = true;

        let validator = OAuthValidator::new(config, reqwest::Client::new());

        // Claims with no aud — jsonwebtoken will reject before our check
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = serde_json::json!({
            "sub": "user-123",
            "iss": "https://auth.example.com",
            "exp": now + 3600,
            "iat": now,
            "nbf": now - 10,
            "scope": "tools.call"
        });

        let token = sign_test_jwt(&claims, kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("missing aud with require_audience must be rejected");
        assert!(
            matches!(err, OAuthError::JwtError(_) | OAuthError::MissingAudience),
            "expected audience rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_bearer_case_insensitive() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let token = sign_test_jwt(&valid_claims(), kid);

        // Test case-insensitive "bearer" prefix (RFC 7235 §2.1)
        let auth_header = format!("BEARER {}", token);
        let result = validator.validate_token(&auth_header).await;
        assert!(result.is_ok(), "BEARER (uppercase) must be accepted: {result:?}");
    }

    #[tokio::test]
    async fn test_e2e_not_before_future_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        let validator = OAuthValidator::new(config, reqwest::Client::new());

        let now = chrono::Utc::now().timestamp() as u64;
        let mut claims = valid_claims();
        claims["nbf"] = serde_json::json!(now + 600); // 10 minutes in the future

        let token = sign_test_jwt(&claims, kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("token with future nbf must be rejected");
        assert!(
            matches!(err, OAuthError::JwtError(_)),
            "expected JwtError for nbf in the future, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_e2e_dpop_required_but_no_cnf_jkt_rejected() {
        let kid = "test-key-1";
        let jwks = test_jwks_json(kid);
        let (base_url, _handle) = start_mock_jwks_server(jwks).await;

        let mut config = test_oauth_config(format!("{}/.well-known/jwks.json", base_url));
        config.dpop_mode = DpopMode::Required;

        let validator = OAuthValidator::new(config, reqwest::Client::new());

        // Token without cnf.jkt claim
        let token = sign_test_jwt(&valid_claims(), kid);
        let auth_header = format!("Bearer {}", token);

        let err = validator.validate_token(&auth_header).await
            .expect_err("DPoP required but no cnf.jkt must be rejected");
        assert!(
            matches!(err, OAuthError::InvalidDpopProof(_)),
            "expected InvalidDpopProof, got: {err}"
        );
    }
}
