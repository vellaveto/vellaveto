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
    decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, TokenData, Validation,
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
        let kid = header.kid.unwrap_or_default();

        // Get the decoding key from JWKS
        let decoding_key = self.get_decoding_key(&kid, &header.alg).await?;

        // Build validation parameters
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;

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

        // Match algorithm family
        if let Some(ref key_alg) = key.common.key_algorithm {
            let key_alg_str = format!("{:?}", key_alg);
            let req_alg_str = format!("{:?}", alg);
            if key_alg_str != req_alg_str {
                continue;
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
}
