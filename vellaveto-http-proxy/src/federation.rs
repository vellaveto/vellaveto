// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Federation identity resolver for cross-organization agent identity (Phase 39).
//!
//! Validates JWTs against configured `FederationTrustAnchor` entries, caches
//! JWKS per-anchor with configurable TTL, and maps external JWT claims to
//! internal `AgentIdentity` principals.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::KeyAlgorithm;
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use vellaveto_config::abac::FederationConfig;
use vellaveto_types::abac::{
    FederationAnchorInfo, FederationAnchorStatus, FederationStatus, FederationTrustAnchor,
};
use vellaveto_types::identity::AgentIdentity;

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

/// Result of successful federation validation.
#[derive(Debug, Clone)]
pub struct FederatedIdentity {
    /// Mapped internal identity with populated claims.
    pub identity: AgentIdentity,
    /// Organization that issued the token.
    pub org_id: String,
    /// Trust level from the matching anchor.
    pub trust_level: String,
}

/// Federation validation errors. All variants are fail-closed.
#[derive(Debug)]
pub enum FederationError {
    /// JWKS fetch failed for a matched anchor.
    JwksFetchFailed { org_id: String, source: String },
    /// JWT validation failed (signature, expiry, claims).
    JwtValidationFailed { org_id: String, source: String },
    /// No matching key found in JWKS for the given kid.
    NoMatchingKey { org_id: String, kid: String },
    /// JWT uses a disallowed algorithm (e.g., symmetric).
    DisallowedAlgorithm(String),
    /// JWT header decode failed.
    InvalidHeader(String),
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JwksFetchFailed { org_id, source } => {
                write!(f, "JWKS fetch failed for {org_id}: {source}")
            }
            Self::JwtValidationFailed { org_id, source } => {
                write!(f, "JWT validation failed for {org_id}: {source}")
            }
            Self::NoMatchingKey { org_id, kid } => {
                // SECURITY (FIND-R50-040): Sanitize kid value in error messages
                // to prevent control character injection in logs.
                // SECURITY (IMP-R154-003): Also filter Unicode format chars
                // (zero-width, bidi, TAG) — not just control chars.
                let safe_kid = vellaveto_types::sanitize_for_log(kid, 128);
                write!(
                    f,
                    "no matching key in JWKS for org {org_id}, kid '{safe_kid}'"
                )
            }
            Self::DisallowedAlgorithm(alg) => {
                write!(f, "disallowed JWT algorithm: {alg}")
            }
            Self::InvalidHeader(msg) => {
                write!(f, "invalid JWT header: {msg}")
            }
        }
    }
}

impl std::error::Error for FederationError {}

/// Cached JWKS key set with expiry.
struct CachedJwks {
    keys: jsonwebtoken::jwk::JwkSet,
    fetched_at: Instant,
}

/// Compiled trust anchor with runtime state.
struct CompiledAnchor {
    config: FederationTrustAnchor,
    jwks_cache: RwLock<Option<CachedJwks>>,
    success_count: AtomicU64,
    failure_count: AtomicU64,
}

/// Maximum number of extra claims allowed in a federated JWT (FIND-R50-013).
const MAX_EXTRA_CLAIMS: usize = 50;

/// Maximum serialized size per extra claim value in bytes (FIND-R50-013).
const MAX_EXTRA_CLAIM_VALUE_BYTES: usize = 8192;

/// Maximum length of a single array element string when extracting claim values (FIND-R50-018).
const MAX_CLAIM_ELEMENT_LEN: usize = 1024;

/// Maximum total joined length when extracting array claim values (FIND-R50-018).
const MAX_CLAIM_JOINED_LEN: usize = 8192;

/// Maximum length for a claim value used in template substitution (FIND-R50-005).
const MAX_TEMPLATE_CLAIM_VALUE_LEN: usize = 1024;

/// JWT claims we extract from federated tokens.
#[derive(Debug, Deserialize)]
struct FederatedClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    email: Option<String>,
    /// Catch-all for custom claims.
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

impl FederatedClaims {
    /// Validate that extra claims are within bounds (FIND-R50-013).
    ///
    /// Returns `Err` if there are too many extra claims or any single claim value
    /// exceeds the serialized size limit.
    fn validate_extra_claims(&self) -> Result<(), String> {
        if self.extra.len() > MAX_EXTRA_CLAIMS {
            return Err(format!(
                "federated JWT has {} extra claims, max is {}",
                self.extra.len(),
                MAX_EXTRA_CLAIMS
            ));
        }
        for (key, value) in &self.extra {
            let serialized_len = serde_json::to_string(value).map(|s| s.len()).unwrap_or(0);
            if serialized_len > MAX_EXTRA_CLAIM_VALUE_BYTES {
                return Err(format!(
                    "federated JWT extra claim '{key}' is {serialized_len} bytes, max is {MAX_EXTRA_CLAIM_VALUE_BYTES}"
                ));
            }
        }
        Ok(())
    }
}

/// Allowed asymmetric JWT algorithms.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::EdDSA,
];

// ═══════════════════════════════════════════════════════════════════════════════
// FederationResolver
// ═══════════════════════════════════════════════════════════════════════════════

/// Federation identity resolver.
///
/// Validates JWTs against configured trust anchors, caches JWKS per-anchor,
/// and maps external claims to internal `AgentIdentity`.
/// Maximum JWKS response body size (1 MB).
const MAX_JWKS_BODY_BYTES: usize = 1_048_576;

pub struct FederationResolver {
    anchors: Vec<Arc<CompiledAnchor>>,
    http_client: reqwest::Client,
    cache_ttl: Duration,
    fetch_timeout: Duration,
    /// SECURITY (FIND-R50-002): Expected audience for JWT validation.
    /// When set, federated tokens must include this value in `aud`.
    expected_audience: Option<String>,
}

impl FederationResolver {
    /// Create from config. Returns Err if config is invalid.
    pub fn new(config: &FederationConfig, http_client: reqwest::Client) -> Result<Self, String> {
        let mut anchors = Vec::with_capacity(config.trust_anchors.len());
        for anchor_config in &config.trust_anchors {
            anchor_config.validate()?;
            anchors.push(Arc::new(CompiledAnchor {
                config: anchor_config.clone(),
                jwks_cache: RwLock::new(None),
                success_count: AtomicU64::new(0),
                failure_count: AtomicU64::new(0),
            }));
        }
        Ok(Self {
            anchors,
            http_client,
            cache_ttl: Duration::from_secs(config.jwks_cache_ttl_secs),
            fetch_timeout: Duration::from_secs(config.jwks_fetch_timeout_secs),
            expected_audience: config.expected_audience.clone(),
        })
    }

    /// Try to validate a JWT against federation trust anchors.
    ///
    /// Returns `Ok(Some(identity))` if a matching anchor validates the token.
    /// Returns `Ok(None)` if no anchor matches the issuer.
    /// Returns `Err` if an anchor matches but validation fails (fail-closed).
    pub async fn validate_federated_token(
        &self,
        token: &str,
    ) -> Result<Option<FederatedIdentity>, FederationError> {
        // 1. Decode header to get issuer and kid
        let header =
            decode_header(token).map_err(|e| FederationError::InvalidHeader(e.to_string()))?;

        let alg = header.alg;
        let alg_str = format!("{alg:?}");
        if !ALLOWED_ALGORITHMS.contains(&alg) {
            return Err(FederationError::DisallowedAlgorithm(alg_str));
        }

        // SECURITY (FIND-R50-032): Require kid in JWT header for federation.
        // Without a kid, we cannot reliably select the correct key from the JWKS,
        // and an empty kid would match any JWK with a matching algorithm.
        let kid = match header.kid {
            Some(ref k) if !k.is_empty() => k.clone(),
            _ => {
                return Err(FederationError::InvalidHeader(
                    "JWT header missing required 'kid' field for federation".to_string(),
                ))
            }
        };

        // Extract issuer from payload without validation
        let issuer = extract_issuer_from_payload(token)
            .ok_or_else(|| FederationError::InvalidHeader("missing iss claim".to_string()))?;

        // 2. Find matching anchor
        // SECURITY (FIND-R50-006): The issuer is extracted from the unverified JWT
        // payload and used ONLY to select from pre-configured trust anchors. The
        // JWKS URI comes from the anchor config, NOT from the JWT. After signature
        // verification below, we re-check that the verified issuer still matches.
        let anchor = match self.find_matching_anchor(&issuer) {
            Some(a) => a,
            None => return Ok(None), // No anchor matches — not a federated token
        };

        // 3. Get decoding key from JWKS
        let decoding_key =
            self.get_decoding_key(&anchor, &kid, &alg)
                .await
                .inspect_err(|_| {
                    let _ = anchor.failure_count.fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |v| Some(v.saturating_add(1)),
                    );
                })?;

        // 4. Validate JWT
        let mut validation = Validation::new(alg);
        validation.validate_exp = true;
        // SECURITY (FIND-R50-004): Validate nbf claim to reject pre-dated tokens,
        // matching the local OAuth path behavior.
        validation.validate_nbf = true;
        validation.set_issuer(&[&issuer]);
        // SECURITY (FIND-R50-002): When expected_audience is configured, enforce
        // audience validation to prevent cross-service token replay attacks.
        if let Some(ref aud) = self.expected_audience {
            validation.validate_aud = true;
            validation.set_audience(&[aud]);
        } else {
            validation.validate_aud = false;
        }
        // Allow 60s clock skew
        validation.leeway = 60;

        let token_data = jsonwebtoken::decode::<FederatedClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                let _ =
                    anchor
                        .failure_count
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                            Some(v.saturating_add(1))
                        });
                FederationError::JwtValidationFailed {
                    org_id: anchor.config.org_id.clone(),
                    source: e.to_string(),
                }
            })?;

        // FIND-R50-013: Validate extra claims are within bounds
        if let Err(reason) = token_data.claims.validate_extra_claims() {
            let _ = anchor
                .failure_count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_add(1))
                });
            return Err(FederationError::JwtValidationFailed {
                org_id: anchor.config.org_id.clone(),
                source: reason,
            });
        }

        // SECURITY (FIND-R50-006): After signature verification, re-check that
        // the verified token's issuer matches the anchor that was used for key
        // selection. This prevents an attacker from forging a JWT with issuer A
        // (to select anchor A's JWKS) while the actual verified token has a
        // different issuer B.
        if let Some(ref verified_iss) = token_data.claims.iss {
            if !issuer_pattern_matches(&anchor.config.issuer_pattern, verified_iss) {
                let _ =
                    anchor
                        .failure_count
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                            Some(v.saturating_add(1))
                        });
                return Err(FederationError::JwtValidationFailed {
                    org_id: anchor.config.org_id.clone(),
                    source: format!(
                        "verified token issuer '{}' does not match anchor pattern '{}'",
                        verified_iss, anchor.config.issuer_pattern
                    ),
                });
            }
        }

        // 5. Apply identity mappings
        let identity = self.apply_identity_mappings(&anchor, &token_data.claims);

        let _ = anchor
            .success_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });

        Ok(Some(FederatedIdentity {
            identity,
            org_id: anchor.config.org_id.clone(),
            trust_level: anchor.config.trust_level.clone(),
        }))
    }

    /// Get federation status for API/dashboard.
    pub fn status(&self) -> FederationStatus {
        FederationStatus {
            enabled: true,
            trust_anchor_count: self.anchors.len(),
            anchors: self
                .anchors
                .iter()
                .map(|a| {
                    let cache = a.jwks_cache.read().ok();
                    let (cached, last_fetched) = match cache.as_ref().and_then(|c| c.as_ref()) {
                        Some(c) => (true, Some(format!("{:?}", c.fetched_at.elapsed()))),
                        None => (false, None),
                    };
                    FederationAnchorStatus {
                        org_id: a.config.org_id.clone(),
                        display_name: a.config.display_name.clone(),
                        issuer_pattern: a.config.issuer_pattern.clone(),
                        trust_level: a.config.trust_level.clone(),
                        has_jwks_uri: a.config.jwks_uri.is_some(),
                        jwks_cached: cached,
                        jwks_last_fetched: last_fetched,
                        identity_mapping_count: a.config.identity_mappings.len(),
                        successful_validations: a.success_count.load(Ordering::SeqCst),
                        failed_validations: a.failure_count.load(Ordering::SeqCst),
                    }
                })
                .collect(),
        }
    }

    /// Get anchor info list for API (excludes JWKS keys).
    pub fn anchor_info(&self) -> Vec<FederationAnchorInfo> {
        self.anchors
            .iter()
            .map(|a| FederationAnchorInfo {
                org_id: a.config.org_id.clone(),
                display_name: a.config.display_name.clone(),
                issuer_pattern: a.config.issuer_pattern.clone(),
                trust_level: a.config.trust_level.clone(),
                has_jwks_uri: a.config.jwks_uri.is_some(),
                identity_mapping_count: a.config.identity_mappings.len(),
            })
            .collect()
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    fn find_matching_anchor(&self, issuer: &str) -> Option<Arc<CompiledAnchor>> {
        self.anchors
            .iter()
            .find(|a| issuer_pattern_matches(&a.config.issuer_pattern, issuer))
            .cloned()
    }

    async fn get_decoding_key(
        &self,
        anchor: &CompiledAnchor,
        kid: &str,
        alg: &Algorithm,
    ) -> Result<DecodingKey, FederationError> {
        let jwks_uri =
            anchor
                .config
                .jwks_uri
                .as_deref()
                .ok_or_else(|| FederationError::JwksFetchFailed {
                    org_id: anchor.config.org_id.clone(),
                    source: "no jwks_uri configured".to_string(),
                })?;

        // Check cache first (fast path via read lock)
        // SECURITY (FO-003): Fail-closed on poisoned read lock — treat as cache miss
        // and re-fetch from upstream, instead of using potentially corrupted data
        // via into_inner().
        {
            match anchor.jwks_cache.read() {
                Ok(cache_guard) => {
                    if let Some(ref cached) = *cache_guard {
                        if cached.fetched_at.elapsed() < self.cache_ttl {
                            return find_key_in_jwks(&cached.keys, kid, alg, &anchor.config.org_id);
                        }
                    }
                }
                Err(_) => {
                    tracing::error!(
                        target: "vellaveto::security",
                        org_id = %anchor.config.org_id,
                        "JWKS cache read lock poisoned — treating as cache miss (fail-closed)"
                    );
                    // Fall through to fetch fresh JWKS
                }
            }
        }

        // Cache miss or expired — fetch JWKS
        let jwks = self.fetch_jwks(jwks_uri, &anchor.config.org_id).await?;

        // Try to find key before caching
        let result = find_key_in_jwks(&jwks, kid, alg, &anchor.config.org_id);

        // Update cache
        // FIND-R50-014: On write-lock poisoning, clear stale/partial cache before writing.
        // The poisoned guard may contain partially-written data from a panicked thread.
        {
            let mut cache_guard = anchor.jwks_cache.write().unwrap_or_else(|e| {
                tracing::warn!(
                    "JWKS cache write lock poisoned for org '{}'; clearing stale cache",
                    anchor.config.org_id
                );
                let mut guard = e.into_inner();
                *guard = None; // Clear potentially partial data
                guard
            });
            *cache_guard = Some(CachedJwks {
                keys: jwks,
                fetched_at: Instant::now(),
            });
        }

        result
    }

    async fn fetch_jwks(
        &self,
        uri: &str,
        org_id: &str,
    ) -> Result<jsonwebtoken::jwk::JwkSet, FederationError> {
        let resp = self
            .http_client
            .get(uri)
            .timeout(self.fetch_timeout)
            .send()
            .await
            .map_err(|e| FederationError::JwksFetchFailed {
                org_id: org_id.to_string(),
                source: e.to_string(),
            })?;

        if !resp.status().is_success() {
            return Err(FederationError::JwksFetchFailed {
                org_id: org_id.to_string(),
                source: format!("HTTP {}", resp.status()),
            });
        }

        // SECURITY (FIND-R50-001): Check Content-Length header BEFORE downloading
        // to prevent OOM from malicious JWKS endpoints serving gigabytes.
        // SECURITY (R240-P3-PROXY-5): Compare in u64 space to avoid truncation on 32-bit.
        if let Some(len) = resp.content_length() {
            if len > MAX_JWKS_BODY_BYTES as u64 {
                return Err(FederationError::JwksFetchFailed {
                    org_id: org_id.to_string(),
                    source: format!(
                        "JWKS Content-Length {len} exceeds {MAX_JWKS_BODY_BYTES} byte limit"
                    ),
                });
            }
        }

        // SECURITY (FIND-R50-001): Read body in chunks with bounded accumulation.
        // Handles chunked-encoded responses that omit Content-Length.
        let capacity = std::cmp::min(
            resp.content_length().unwrap_or(8192) as usize,
            MAX_JWKS_BODY_BYTES,
        );
        let mut body = Vec::with_capacity(capacity);
        let mut resp = resp;
        while let Some(chunk) =
            resp.chunk()
                .await
                .map_err(|e| FederationError::JwksFetchFailed {
                    org_id: org_id.to_string(),
                    source: e.to_string(),
                })?
        {
            if body.len().saturating_add(chunk.len()) > MAX_JWKS_BODY_BYTES {
                return Err(FederationError::JwksFetchFailed {
                    org_id: org_id.to_string(),
                    source: format!("JWKS response exceeds {MAX_JWKS_BODY_BYTES} byte limit"),
                });
            }
            body.extend_from_slice(&chunk);
        }

        serde_json::from_slice(&body).map_err(|e| FederationError::JwksFetchFailed {
            org_id: org_id.to_string(),
            source: format!("invalid JWKS JSON: {e}"),
        })
    }

    fn apply_identity_mappings(
        &self,
        anchor: &CompiledAnchor,
        claims: &FederatedClaims,
    ) -> AgentIdentity {
        let mut identity_claims: HashMap<String, serde_json::Value> = HashMap::new();

        // Always inject federation metadata
        identity_claims.insert(
            "federation.org_id".to_string(),
            serde_json::Value::String(anchor.config.org_id.clone()),
        );
        identity_claims.insert(
            "federation.trust_level".to_string(),
            serde_json::Value::String(anchor.config.trust_level.clone()),
        );
        if let Some(ref iss) = claims.iss {
            identity_claims.insert(
                "federation.issuer".to_string(),
                serde_json::Value::String(iss.clone()),
            );
        }

        let mut subject = claims.sub.clone();

        // Apply each identity mapping
        for mapping in &anchor.config.identity_mappings {
            if let Some(value) = extract_claim_value(claims, &mapping.external_claim) {
                // SECURITY (FIND-R50-005): Sanitize claim values before template
                // substitution to prevent template injection and control character
                // injection. Strip control characters, limit length, and reject
                // values containing template syntax characters.
                let sanitized = sanitize_claim_for_template(&value);

                let rendered = mapping
                    .id_template
                    .replace("{claim_value}", &sanitized)
                    .replace("{org_id}", &anchor.config.org_id);

                identity_claims.insert(
                    "principal.type".to_string(),
                    serde_json::Value::String(mapping.internal_principal_type.clone()),
                );
                identity_claims.insert(
                    "principal.id".to_string(),
                    serde_json::Value::String(rendered.clone()),
                );

                // Use the first mapping's rendered value as subject
                if mapping.external_claim == "sub" || mapping.external_claim == "email" {
                    subject = Some(rendered);
                }
            }
        }

        AgentIdentity {
            issuer: claims.iss.clone(),
            subject,
            audience: Vec::new(),
            claims: identity_claims,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════════════════════

/// SECURITY (FIND-R50-005): Sanitize a claim value before template substitution.
///
/// - Strips control characters (U+0000..U+001F, U+007F..U+009F)
/// - Truncates to `MAX_TEMPLATE_CLAIM_VALUE_LEN` bytes
/// - Strips template syntax characters (`{`, `}`) to prevent nested injection
fn sanitize_claim_for_template(value: &str) -> String {
    let sanitized: String = value
        .chars()
        // SECURITY (IMP-R154-003): Also strip Unicode format chars
        .filter(|c| {
            !c.is_control()
                && !vellaveto_types::is_unicode_format_char(*c)
                && *c != '{'
                && *c != '}'
        })
        .collect();
    if sanitized.len() > MAX_TEMPLATE_CLAIM_VALUE_LEN {
        // Truncate at a char boundary
        let mut end = MAX_TEMPLATE_CLAIM_VALUE_LEN;
        while end > 0 && !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized[..end].to_string()
    } else {
        sanitized
    }
}

/// Extract a claim value from federated claims. Supports nested dot notation.
fn extract_claim_value(claims: &FederatedClaims, claim_path: &str) -> Option<String> {
    // Direct fields first
    match claim_path {
        "sub" => return claims.sub.clone(),
        "iss" => return claims.iss.clone(),
        "email" => return claims.email.clone(),
        _ => {}
    }

    // Try extra claims with dot notation
    let parts: Vec<&str> = claim_path.splitn(10, '.').collect();
    let mut current: Option<&serde_json::Value> = claims.extra.get(parts[0]);

    for part in &parts[1..] {
        current = current.and_then(|v| v.get(part));
    }

    current.and_then(|v| match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => {
            // FIND-R50-018: Join array elements with per-element and total length bounds.
            let mut total_len = 0usize;
            let joined: Vec<String> = arr
                .iter()
                .take(64) // Bound iteration count
                .filter_map(|item| {
                    item.as_str().map(|s| {
                        // Cap each element to MAX_CLAIM_ELEMENT_LEN
                        if s.len() > MAX_CLAIM_ELEMENT_LEN {
                            s[..MAX_CLAIM_ELEMENT_LEN].to_string()
                        } else {
                            s.to_string()
                        }
                    })
                })
                .take_while(|s| {
                    // Cap total joined length (including commas)
                    let added = if total_len == 0 { s.len() } else { s.len() + 1 };
                    if total_len + added > MAX_CLAIM_JOINED_LEN {
                        return false;
                    }
                    total_len += added;
                    true
                })
                .collect();
            if joined.is_empty() {
                None
            } else {
                Some(joined.join(","))
            }
        }
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

/// Maximum base64-encoded JWT payload size before decode (64 KB).
/// SECURITY (FIND-R50-031): Prevents OOM from oversized JWT payloads
/// before base64 decoding, which would expand the data further.
const MAX_JWT_PAYLOAD_B64_LEN: usize = 65_536;

/// Extract issuer from JWT payload without validation.
fn extract_issuer_from_payload(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.splitn(4, '.').collect();
    if parts.len() < 2 {
        return None;
    }
    // SECURITY (FIND-R50-031): Reject oversized payloads before decoding.
    if parts[1].len() > MAX_JWT_PAYLOAD_B64_LEN {
        return None;
    }
    use base64::Engine;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    payload.get("iss")?.as_str().map(String::from)
}

/// Simple glob-style issuer pattern matching with `*` wildcards.
///
/// SECURITY (FIND-R50-012): Consecutive wildcards (`**`) are collapsed into
/// a single `*` before matching, and pattern complexity is bounded.
fn issuer_pattern_matches(pattern: &str, issuer: &str) -> bool {
    if pattern == issuer {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }

    // SECURITY (FIND-R50-012): Normalize consecutive wildcards into single `*`.
    // This prevents patterns like "**" from causing unexpected matching behavior.
    let normalized: String = {
        let mut result = String::with_capacity(pattern.len());
        let mut prev_star = false;
        for ch in pattern.chars() {
            if ch == '*' {
                if !prev_star {
                    result.push(ch);
                }
                prev_star = true;
            } else {
                result.push(ch);
                prev_star = false;
            }
        }
        result
    };

    // Split pattern by `*` and check that all parts appear in order
    let parts: Vec<&str> = normalized.split('*').collect();

    // Bound pattern complexity: reject patterns with more than 10 wildcard segments
    if parts.len() > 11 {
        return false;
    }

    let mut remaining = issuer;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // First part must be a prefix
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
        } else if i == parts.len() - 1 && !part.is_empty() {
            // Last part must be a suffix
            if !remaining.ends_with(part) {
                return false;
            }
            remaining = "";
        } else {
            // Middle parts must appear somewhere
            match remaining.find(part) {
                Some(pos) => remaining = &remaining[pos + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Convert a JWK `KeyAlgorithm` to a JWT `Algorithm` using explicit matching.
///
/// SECURITY (FIND-R50-008): Uses proper enum mapping instead of Debug format
/// string comparison, which is fragile across library versions.
///
/// Returns `None` for encryption-only algorithms that have no signing equivalent.
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

/// Find a decoding key in a JWKS set by kid and algorithm.
///
/// SECURITY (FIND-R50-007): JWKs without a `kid` field are skipped (not treated
/// as wildcard matches). A kidless JWK would otherwise match any JWT kid value.
///
/// SECURITY (FIND-R50-008): Algorithm matching uses explicit enum mapping via
/// `key_algorithm_to_algorithm` instead of Debug format string comparison.
fn find_key_in_jwks(
    jwks: &jsonwebtoken::jwk::JwkSet,
    kid: &str,
    alg: &Algorithm,
    org_id: &str,
) -> Result<DecodingKey, FederationError> {
    for key in &jwks.keys {
        // SECURITY (FIND-R50-007): Require JWKs to have a `kid` field.
        // A JWK without `kid` is skipped — it must not act as a wildcard.
        match &key.common.key_id {
            Some(key_kid) => {
                if !kid.is_empty() && key_kid != kid {
                    continue; // kid mismatch — skip
                }
            }
            None => {
                // JWK has no kid — skip it and log a warning
                tracing::warn!(
                    org_id = %org_id,
                    "skipping JWK without kid field in JWKS for org '{}'",
                    org_id
                );
                continue;
            }
        }

        // SECURITY (FIND-R50-008): Use explicit algorithm mapping, not Debug format.
        if let Some(ref key_alg) = key.common.key_algorithm {
            match key_algorithm_to_algorithm(key_alg) {
                Some(mapped) if &mapped == alg => {} // match — continue to key construction
                _ => continue,                       // no match or encryption-only — skip
            }
        }

        // Try to build decoding key
        if let Ok(dk) = DecodingKey::from_jwk(key) {
            return Ok(dk);
        }
    }

    Err(FederationError::NoMatchingKey {
        org_id: org_id.to_string(),
        kid: kid.to_string(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> FederationConfig {
        FederationConfig {
            enabled: true,
            trust_anchors: vec![FederationTrustAnchor {
                org_id: "partner-org".to_string(),
                display_name: "Partner Organization".to_string(),
                jwks_uri: Some("https://auth.partner.com/.well-known/jwks.json".to_string()),
                issuer_pattern: "https://auth.partner.com".to_string(),
                identity_mappings: vec![vellaveto_types::abac::IdentityMapping {
                    external_claim: "sub".to_string(),
                    internal_principal_type: "agent".to_string(),
                    id_template: "partner-org:{claim_value}".to_string(),
                }],
                trust_level: "limited".to_string(),
            }],
            jwks_cache_ttl_secs: 300,
            jwks_fetch_timeout_secs: 10,
            expected_audience: None,
        }
    }

    fn test_config_wildcard() -> FederationConfig {
        FederationConfig {
            enabled: true,
            trust_anchors: vec![FederationTrustAnchor {
                org_id: "acme".to_string(),
                display_name: "ACME Corp".to_string(),
                jwks_uri: Some("https://auth.acme.com/.well-known/jwks.json".to_string()),
                issuer_pattern: "https://auth.acme.com/*".to_string(),
                identity_mappings: vec![],
                trust_level: "full".to_string(),
            }],
            jwks_cache_ttl_secs: 300,
            jwks_fetch_timeout_secs: 10,
            expected_audience: None,
        }
    }

    #[test]
    fn test_new_valid_config_compiles_anchors() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client);
        assert!(resolver.is_ok());
        let resolver = resolver.expect("test config should be valid");
        assert_eq!(resolver.anchors.len(), 1);
    }

    #[test]
    fn test_new_invalid_anchor_fails() {
        let config = FederationConfig {
            enabled: true,
            trust_anchors: vec![FederationTrustAnchor {
                org_id: String::new(), // Invalid
                display_name: "Bad".to_string(),
                jwks_uri: None,
                issuer_pattern: "https://x.com".to_string(),
                identity_mappings: vec![],
                trust_level: "limited".to_string(),
            }],
            jwks_cache_ttl_secs: 300,
            jwks_fetch_timeout_secs: 10,
            expected_audience: None,
        };
        let client = reqwest::Client::new();
        assert!(FederationResolver::new(&config, client).is_err());
    }

    #[test]
    fn test_issuer_pattern_exact_match() {
        assert!(issuer_pattern_matches(
            "https://auth.partner.com",
            "https://auth.partner.com"
        ));
    }

    #[test]
    fn test_issuer_pattern_no_match() {
        assert!(!issuer_pattern_matches(
            "https://auth.partner.com",
            "https://auth.evil.com"
        ));
    }

    #[test]
    fn test_issuer_pattern_glob_wildcard_suffix() {
        assert!(issuer_pattern_matches(
            "https://auth.acme.com/*",
            "https://auth.acme.com/tenant-1"
        ));
    }

    #[test]
    fn test_issuer_pattern_glob_wildcard_middle() {
        assert!(issuer_pattern_matches(
            "https://*.acme.com/auth",
            "https://tenant1.acme.com/auth"
        ));
    }

    #[test]
    fn test_issuer_pattern_glob_wildcard_no_match() {
        assert!(!issuer_pattern_matches(
            "https://auth.acme.com/*",
            "https://auth.evil.com/tenant"
        ));
    }

    // SECURITY (FIND-R50-012): Consecutive wildcards are collapsed.
    #[test]
    fn test_issuer_pattern_consecutive_wildcards_collapsed() {
        // "**" should behave the same as "*"
        assert!(issuer_pattern_matches(
            "https://auth.acme.com/**",
            "https://auth.acme.com/tenant-1"
        ));
        assert!(!issuer_pattern_matches(
            "https://auth.acme.com/**",
            "https://auth.evil.com/tenant"
        ));
    }

    // SECURITY (FIND-R50-012): Pattern with `*.*` works correctly.
    #[test]
    fn test_issuer_pattern_star_dot_star() {
        assert!(issuer_pattern_matches(
            "https://*.*",
            "https://auth.example.com"
        ));
        assert!(!issuer_pattern_matches(
            "https://*.*",
            "https://nosubdomain"
        ));
    }

    #[test]
    fn test_find_matching_anchor_exact() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        let anchor = resolver.find_matching_anchor("https://auth.partner.com");
        assert!(anchor.is_some());
        assert_eq!(anchor.expect("should match").config.org_id, "partner-org");
    }

    #[test]
    fn test_find_matching_anchor_wildcard() {
        let config = test_config_wildcard();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        let anchor = resolver.find_matching_anchor("https://auth.acme.com/tenant-1");
        assert!(anchor.is_some());
        assert_eq!(anchor.expect("should match").config.org_id, "acme");
    }

    #[test]
    fn test_find_matching_anchor_no_match() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        assert!(resolver
            .find_matching_anchor("https://auth.evil.com")
            .is_none());
    }

    #[test]
    fn test_extract_claim_value_sub() {
        let claims = FederatedClaims {
            sub: Some("agent-123".to_string()),
            iss: Some("https://auth.example.com".to_string()),
            email: None,
            extra: HashMap::new(),
        };
        assert_eq!(
            extract_claim_value(&claims, "sub"),
            Some("agent-123".to_string())
        );
    }

    #[test]
    fn test_extract_claim_value_nested() {
        let mut extra = HashMap::new();
        extra.insert(
            "realm_access".to_string(),
            serde_json::json!({"roles": ["admin", "user"]}),
        );
        let claims = FederatedClaims {
            sub: None,
            iss: None,
            email: None,
            extra,
        };
        assert_eq!(
            extract_claim_value(&claims, "realm_access.roles"),
            Some("admin,user".to_string())
        );
    }

    #[test]
    fn test_extract_claim_value_missing() {
        let claims = FederatedClaims {
            sub: None,
            iss: None,
            email: None,
            extra: HashMap::new(),
        };
        assert_eq!(extract_claim_value(&claims, "nonexistent"), None);
    }

    #[test]
    fn test_apply_identity_mappings_injects_federation_metadata() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        let claims = FederatedClaims {
            sub: Some("agent-456".to_string()),
            iss: Some("https://auth.partner.com".to_string()),
            email: None,
            extra: HashMap::new(),
        };
        let identity = resolver.apply_identity_mappings(&resolver.anchors[0], &claims);
        assert_eq!(
            identity.claims.get("federation.org_id"),
            Some(&serde_json::Value::String("partner-org".to_string()))
        );
        assert_eq!(
            identity.claims.get("federation.trust_level"),
            Some(&serde_json::Value::String("limited".to_string()))
        );
        assert_eq!(
            identity.claims.get("federation.issuer"),
            Some(&serde_json::Value::String(
                "https://auth.partner.com".to_string()
            ))
        );
    }

    #[test]
    fn test_apply_identity_mappings_template_substitution() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        let claims = FederatedClaims {
            sub: Some("agent-789".to_string()),
            iss: Some("https://auth.partner.com".to_string()),
            email: None,
            extra: HashMap::new(),
        };
        let identity = resolver.apply_identity_mappings(&resolver.anchors[0], &claims);
        assert_eq!(
            identity.claims.get("principal.id"),
            Some(&serde_json::Value::String(
                "partner-org:agent-789".to_string()
            ))
        );
        assert_eq!(
            identity.claims.get("principal.type"),
            Some(&serde_json::Value::String("agent".to_string()))
        );
    }

    // SECURITY (FIND-R50-005): Template injection via claim values is prevented.
    #[test]
    fn test_apply_identity_mappings_sanitizes_control_chars() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        let claims = FederatedClaims {
            sub: Some("agent\x00\x0A\x0Dinjected".to_string()),
            iss: Some("https://auth.partner.com".to_string()),
            email: None,
            extra: HashMap::new(),
        };
        let identity = resolver.apply_identity_mappings(&resolver.anchors[0], &claims);
        let principal_id = identity
            .claims
            .get("principal.id")
            .and_then(|v| v.as_str())
            .expect("principal.id must exist");
        // Control characters should be stripped
        assert!(!principal_id.contains('\x00'));
        assert!(!principal_id.contains('\x0A'));
        assert!(!principal_id.contains('\x0D'));
        assert!(principal_id.contains("agentinjected"));
    }

    // SECURITY (FIND-R50-005): Template syntax in claim values is stripped.
    #[test]
    fn test_apply_identity_mappings_strips_template_syntax() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        let claims = FederatedClaims {
            sub: Some("{claim_value}evil{org_id}".to_string()),
            iss: Some("https://auth.partner.com".to_string()),
            email: None,
            extra: HashMap::new(),
        };
        let identity = resolver.apply_identity_mappings(&resolver.anchors[0], &claims);
        let principal_id = identity
            .claims
            .get("principal.id")
            .and_then(|v| v.as_str())
            .expect("principal.id must exist");
        // Template braces should be stripped from the claim value
        assert!(!principal_id.contains('{'));
        assert!(!principal_id.contains('}'));
        assert!(principal_id.contains("claim_valueevilorg_id"));
    }

    // SECURITY (FIND-R50-005): Overly long claim values are truncated.
    #[test]
    fn test_sanitize_claim_for_template_truncates_long_values() {
        let long_value = "a".repeat(2000);
        let sanitized = sanitize_claim_for_template(&long_value);
        assert!(sanitized.len() <= MAX_TEMPLATE_CLAIM_VALUE_LEN);
    }

    // SECURITY (FIND-R50-008): Algorithm mapping uses explicit enum match.
    #[test]
    fn test_key_algorithm_to_algorithm_explicit_mapping() {
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
        // Encryption-only returns None
        assert_eq!(key_algorithm_to_algorithm(&KeyAlgorithm::RSA1_5), None);
    }

    #[test]
    fn test_status_reports_anchors() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        let status = resolver.status();
        assert!(status.enabled);
        assert_eq!(status.trust_anchor_count, 1);
        assert_eq!(status.anchors.len(), 1);
        assert_eq!(status.anchors[0].org_id, "partner-org");
        assert_eq!(status.anchors[0].trust_level, "limited");
        assert!(!status.anchors[0].jwks_cached);
    }

    #[test]
    fn test_anchor_info() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");
        let infos = resolver.anchor_info();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].org_id, "partner-org");
        assert!(infos[0].has_jwks_uri);
        assert_eq!(infos[0].identity_mapping_count, 1);
    }

    #[test]
    fn test_extract_issuer_from_payload_valid() {
        // Construct a minimal JWT with iss claim
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"iss":"https://auth.example.com","sub":"test"}"#);
        let token = format!("{header}.{payload}.fake-sig");
        assert_eq!(
            extract_issuer_from_payload(&token),
            Some("https://auth.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_issuer_from_payload_missing_iss() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"test"}"#);
        let token = format!("{header}.{payload}.sig");
        assert_eq!(extract_issuer_from_payload(&token), None);
    }

    #[tokio::test]
    async fn test_validate_unmatched_issuer_returns_none() {
        let config = test_config();
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");

        // Construct a JWT with non-matching issuer (includes kid per FIND-R50-032)
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"iss":"https://auth.unknown.com","sub":"test","exp":9999999999}"#);
        let token = format!("{header}.{payload}.fake-sig");

        let result = resolver.validate_federated_token(&token).await;
        assert!(result.is_ok());
        assert!(result.expect("should be Ok").is_none());
    }

    #[tokio::test]
    async fn test_validate_matched_issuer_no_jwks_uri_returns_error() {
        let config = FederationConfig {
            enabled: true,
            trust_anchors: vec![FederationTrustAnchor {
                org_id: "no-jwks".to_string(),
                display_name: "No JWKS".to_string(),
                jwks_uri: None, // No JWKS URI
                issuer_pattern: "https://auth.nojwks.com".to_string(),
                identity_mappings: vec![],
                trust_level: "limited".to_string(),
            }],
            jwks_cache_ttl_secs: 300,
            jwks_fetch_timeout_secs: 10,
            expected_audience: None,
        };
        let client = reqwest::Client::new();
        let resolver = FederationResolver::new(&config, client).expect("valid config");

        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT","kid":"key-1"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"iss":"https://auth.nojwks.com","sub":"test","exp":9999999999}"#);
        let token = format!("{header}.{payload}.fake-sig");

        let result = resolver.validate_federated_token(&token).await;
        assert!(result.is_err());
        match result.expect_err("should be err") {
            FederationError::JwksFetchFailed { org_id, .. } => {
                assert_eq!(org_id, "no-jwks");
            }
            other => panic!("Expected JwksFetchFailed, got: {other}"),
        }
    }
}
