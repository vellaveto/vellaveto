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
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

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

impl OAuthConfig {
    /// Resolve the JWKS URI, falling back to well-known discovery.
    pub fn effective_jwks_uri(&self) -> String {
        self.jwks_uri.clone().unwrap_or_else(|| {
            let base = self.issuer.trim_end_matches('/');
            format!("{}/.well-known/jwks.json", base)
        })
    }
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
        }
    }

    /// Validate a Bearer token from the Authorization header value.
    ///
    /// Returns the validated claims on success.
    pub async fn validate_token(&self, auth_header: &str) -> Result<OAuthClaims, OAuthError> {
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(OAuthError::InvalidFormat)?;

        if token.is_empty() {
            return Err(OAuthError::InvalidFormat);
        }

        // Decode header to find the key ID (kid)
        let header = decode_header(token)?;

        // Challenge 11 fix: Reject algorithms not in the allowed list.
        // Prevents algorithm confusion attacks (e.g., HS256 with RSA public key).
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

        // Decode and validate
        let token_data: TokenData<OAuthClaims> = decode(token, &decoding_key, &validation)?;
        let claims = token_data.claims;

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

        Ok(claims)
    }

    /// Get a decoding key from the cached JWKS, refreshing if stale.
    async fn get_decoding_key(
        &self,
        kid: &str,
        alg: &Algorithm,
    ) -> Result<DecodingKey, OAuthError> {
        // Try cache first
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

        // Cache miss or stale — fetch fresh JWKS
        let jwks = self.fetch_jwks().await?;

        // Challenge 12 fix: Require kid when JWKS has multiple keys.
        // Without kid, a token could match any key — dangerous if JWKS
        // contains test keys, rotated keys, or keys from other services.
        if kid.is_empty() && jwks.keys.len() > 1 {
            return Err(OAuthError::MissingKid(jwks.keys.len()));
        }

        let key = find_key_in_jwks(&jwks, kid, alg)
            .ok_or_else(|| OAuthError::NoMatchingKey(kid.to_string()))?;

        // Update cache
        {
            let mut cache = self.jwks_cache.write().await;
            *cache = Some(CachedJwks {
                keys: jwks,
                fetched_at: Instant::now(),
            });
        }

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

        let jwks: JwkSet = response
            .json()
            .await
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
fn find_key_in_jwks(jwks: &JwkSet, kid: &str, alg: &Algorithm) -> Option<DecodingKey> {
    for key in &jwks.keys {
        // Match by kid if provided
        if !kid.is_empty() {
            if let Some(ref key_kid) = key.common.key_id {
                if key_kid != kid {
                    continue;
                }
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
}
