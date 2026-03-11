// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! OAuth 2.1, API key, and agent identity authentication.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Deref;
use subtle::ConstantTimeEq;
use vellaveto_mcp::mediation::build_secondary_acis_envelope_with_security_context;
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{Action, ReplayStatus, SignatureVerificationStatus, Verdict};

use super::helpers::oauth_dpop_failure_security_context;
use super::{ProxyState, X_AGENT_IDENTITY};
use crate::oauth::{OAuthClaims, OAuthError};
use crate::proxy_metrics::{record_dpop_failure, record_dpop_replay_detected};

/// Build the effective request URI from headers and bind address.
///
/// When behind a trusted reverse proxy, uses X-Forwarded-Proto and
/// X-Forwarded-Host headers. Otherwise falls back to Host header or
/// the bind address.
pub(super) fn build_effective_request_uri(
    headers: &HeaderMap,
    bind_addr: SocketAddr,
    original_uri: &axum::http::Uri,
    from_trusted_proxy: bool,
) -> String {
    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty());

    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty() && !v.contains('/'));

    let host_header = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty() && !v.contains('/'));

    let default_proto = if bind_addr.port() == 443 {
        "https"
    } else {
        "http"
    };

    let proto = if from_trusted_proxy {
        forwarded_proto.unwrap_or(default_proto)
    } else {
        default_proto
    };

    let authority = if from_trusted_proxy {
        forwarded_host.or(host_header)
    } else {
        host_header
    }
    .map(ToString::to_string)
    .unwrap_or_else(|| bind_addr.to_string());

    let path_and_query = original_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    format!("{proto}://{authority}{path_and_query}")
}

fn dpop_mode_label(mode: crate::oauth::DpopMode) -> &'static str {
    match mode {
        crate::oauth::DpopMode::Off => "off",
        crate::oauth::DpopMode::Optional => "optional",
        crate::oauth::DpopMode::Required => "required",
    }
}

fn dpop_failure_label(error: &OAuthError) -> &'static str {
    match error {
        OAuthError::MissingDpopProof => "missing_proof",
        OAuthError::DpopReplayDetected => "replay_detected",
        OAuthError::InvalidDpopProof(_) => "invalid_proof",
        _ => "validation_error",
    }
}

/// Parameters for DPoP validation failure auditing.
struct DpopAuditParams<'a> {
    session_hint: Option<&'a str>,
    method: &'a str,
    effective_uri: &'a str,
    oauth_subject: &'a str,
    has_dpop_header: bool,
    dpop_mode: crate::oauth::DpopMode,
    dpop_reason: &'a str,
}

#[derive(Debug, Clone)]
pub(super) struct OAuthValidationEvidence {
    pub claims: OAuthClaims,
    pub dpop_proof_verified: bool,
}

impl OAuthValidationEvidence {
    pub fn signature_status(&self) -> SignatureVerificationStatus {
        if self.dpop_proof_verified {
            SignatureVerificationStatus::Verified
        } else {
            SignatureVerificationStatus::Missing
        }
    }

    pub fn replay_status(&self) -> ReplayStatus {
        if self.dpop_proof_verified {
            ReplayStatus::Fresh
        } else {
            ReplayStatus::NotChecked
        }
    }
}

impl Deref for OAuthValidationEvidence {
    type Target = OAuthClaims;

    fn deref(&self) -> &Self::Target {
        &self.claims
    }
}

fn extract_custom_identity_claims(identity_token: &str) -> Option<HashMap<String, Value>> {
    const RESERVED_CLAIMS: &[&str] = &[
        "iss", "sub", "aud", "exp", "iat", "nbf", "scope", "resource", "cnf",
    ];

    let payload_segment = identity_token.split('.').nth(1)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).ok()?;
    let mut payload =
        serde_json::from_slice::<serde_json::Map<String, Value>>(&payload_bytes).ok()?;

    for key in RESERVED_CLAIMS {
        payload.remove(*key);
    }

    Some(payload.into_iter().collect())
}

async fn audit_dpop_validation_failure(
    state: &ProxyState,
    params: DpopAuditParams<'_>,
) -> Result<(), vellaveto_audit::AuditError> {
    let action = Action::new(
        "oauth",
        "dpop_validate",
        json!({
            "method": params.method,
            "uri": params.effective_uri,
            "dpop_mode": dpop_mode_label(params.dpop_mode),
        }),
    );

    let mut metadata = serde_json::Map::new();
    metadata.insert("source".to_string(), json!("http_proxy"));
    metadata.insert("auth_type".to_string(), json!("oauth_dpop"));
    metadata.insert("http_method".to_string(), json!(params.method));
    metadata.insert("effective_uri".to_string(), json!(params.effective_uri));
    metadata.insert("oauth_subject".to_string(), json!(params.oauth_subject));
    metadata.insert(
        "dpop_mode".to_string(),
        json!(dpop_mode_label(params.dpop_mode)),
    );
    metadata.insert("dpop_reason".to_string(), json!(params.dpop_reason));
    metadata.insert("has_dpop_header".to_string(), json!(params.has_dpop_header));
    if let Some(session_id) = params.session_hint {
        metadata.insert("session".to_string(), json!(session_id));
    }

    let verdict = Verdict::Deny {
        reason: format!("OAuth DPoP validation failed: {}", params.dpop_reason),
    };
    let auth_security_context =
        oauth_dpop_failure_security_context(params.dpop_reason, params.has_dpop_header);
    let envelope = build_secondary_acis_envelope_with_security_context(
        &action,
        &verdict,
        DecisionOrigin::PolicyEngine,
        "http",
        params.session_hint,
        Some(&auth_security_context),
    );
    state
        .audit
        .log_entry_with_acis(&action, &verdict, Value::Object(metadata), envelope)
        .await
}

#[allow(clippy::result_large_err)]
pub(super) async fn validate_oauth(
    state: &ProxyState,
    headers: &HeaderMap,
    method: &str,
    effective_uri: &str,
    session_hint: Option<&str>,
) -> Result<Option<OAuthValidationEvidence>, Response> {
    let validator = match &state.oauth {
        Some(v) => v,
        None => return Ok(None),
    };

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let auth_value = match auth_header {
        Some(h) => h,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing Authorization header. Expected: Bearer <token>"})),
            )
                .into_response());
        }
    };

    let bearer_token = match crate::oauth::extract_bearer_token(auth_value) {
        Ok(token) => token,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired token"})),
            )
                .into_response());
        }
    };

    match validator.validate_token(auth_value).await {
        Ok(claims) => {
            let dpop_header = headers.get("dpop").and_then(|v| v.to_str().ok());
            let dpop_proof_verified = validator.config().dpop_mode != crate::oauth::DpopMode::Off
                && dpop_header.is_some();
            if let Err(e) = validator
                .validate_dpop_proof(
                    dpop_header,
                    bearer_token,
                    method,
                    effective_uri,
                    Some(&claims),
                )
                .await
            {
                let dpop_reason = dpop_failure_label(&e);
                record_dpop_failure(dpop_reason);
                if matches!(&e, OAuthError::DpopReplayDetected) {
                    record_dpop_replay_detected();
                }
                if let Err(audit_err) = audit_dpop_validation_failure(
                    state,
                    DpopAuditParams {
                        session_hint,
                        method,
                        effective_uri,
                        oauth_subject: &claims.sub,
                        has_dpop_header: dpop_header.is_some(),
                        dpop_mode: validator.config().dpop_mode,
                        dpop_reason,
                    },
                )
                .await
                {
                    tracing::warn!(
                        "Failed to audit OAuth DPoP validation failure: {}",
                        audit_err
                    );
                }
                tracing::warn!("OAuth DPoP validation failed: {}", e);
                let message = match &e {
                    OAuthError::MissingDpopProof => "Missing DPoP proof",
                    _ => "Invalid or expired token",
                };
                return Err(
                    (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response(),
                );
            }
            tracing::debug!("OAuth token validated for subject: {}", claims.sub);
            Ok(Some(OAuthValidationEvidence {
                claims,
                dpop_proof_verified,
            }))
        }
        Err(OAuthError::InsufficientScope { required, found }) => {
            tracing::warn!(
                "OAuth scope check failed: required={}, found={}",
                required,
                found
            );
            // RFC 6750 §3.1: WWW-Authenticate header with insufficient_scope error.
            // SECURITY: Sanitize scope string — no double-quotes or control chars
            // to prevent header injection.
            let sanitized_scope: String = required
                .chars()
                .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
                .collect();
            let www_auth =
                format!("Bearer error=\"insufficient_scope\", scope=\"{sanitized_scope}\"");
            Err((
                StatusCode::FORBIDDEN,
                [(axum::http::header::WWW_AUTHENTICATE, www_auth)],
                Json(json!({
                    "error": "insufficient_scope",
                    "required_scope": sanitized_scope
                })),
            )
                .into_response())
        }
        Err(e) => {
            tracing::debug!("OAuth token validation failed: {}", e);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired token"})),
            )
                .into_response())
        }
    }
}

/// Validate the API key from the request headers.
///
/// Returns `Ok(())` if authentication passes (key matches, no key configured,
/// or OAuth is enabled — OAuth subsumes API key auth since both use the
/// Authorization header).
/// Returns `Err(response)` with HTTP 401 if the key is missing or invalid.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
#[allow(clippy::result_large_err)]
pub(super) fn validate_api_key(state: &ProxyState, headers: &HeaderMap) -> Result<(), Response> {
    // When OAuth is configured, it handles authentication via JWTs.
    // Both use the Authorization: Bearer header, so we defer to OAuth.
    if state.oauth.is_some() {
        return Ok(());
    }

    let api_key = match &state.api_key {
        Some(key) => key,
        None => return Ok(()), // No key configured (--allow-anonymous)
    };

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        // RFC 7235: Authorization scheme comparison is case-insensitive.
        Some(h) if h.len() > 7 && h[..7].eq_ignore_ascii_case("bearer ") => {
            let token = &h[7..];
            // SECURITY (FIND-008): Hash before comparing to prevent length oracle.
            // ct_eq short-circuits on length mismatch; hashing normalizes to 32 bytes.
            use sha2::{Digest, Sha256};
            let token_hash = Sha256::digest(token.as_bytes());
            let key_hash = Sha256::digest(api_key.as_bytes());
            if token_hash.ct_eq(&key_hash).into() {
                Ok(())
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid API key"})),
                )
                    .into_response())
            }
        }
        _ => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Authentication required"})),
        )
            .into_response()),
    }
}

/// OWASP ASI07: Extract and validate the agent identity from X-Agent-Identity header.
///
/// The header contains a signed JWT that provides cryptographic attestation of
/// the agent's identity. When present, it is validated using the same OAuth
/// infrastructure (JWKS, algorithm checks) to ensure signature integrity.
///
/// **Phase 39 — Federation:** When a federation resolver is configured, the
/// token is first checked against federation trust anchors. If the issuer
/// matches a federated anchor, the token is validated via that anchor's JWKS.
/// If no anchor matches, validation falls through to the local OAuth path.
/// If a federation anchor matches but validation fails, the request is
/// rejected (fail-closed).
///
/// Returns `Ok(Some(identity))` if the header is present and valid.
/// Returns `Ok(None)` if the header is not present (backwards compatible).
/// Returns `Err(response)` if the header is present but invalid/expired.
///
/// Unlike the OAuth `Authorization` header which is mandatory when configured,
/// the `X-Agent-Identity` header is optional — it provides additional identity
/// information when available but does not block requests when absent.
#[allow(clippy::result_large_err)]
pub(super) async fn validate_agent_identity(
    state: &ProxyState,
    headers: &HeaderMap,
) -> Result<Option<vellaveto_types::AgentIdentity>, Response> {
    let identity_token = match headers.get(X_AGENT_IDENTITY).and_then(|v| v.to_str().ok()) {
        Some(token) if !token.is_empty() => token,
        _ => return Ok(None), // No header = no attestation (backwards compatible)
    };

    // Phase 39: Try federation resolver first if configured.
    // Federation takes priority — if an anchor matches, we use its result.
    // If no anchor matches (Ok(None)), we fall through to local OAuth.
    // If an anchor matches but validation fails (Err), we fail-closed.
    if let Some(ref federation) = state.federation {
        match federation.validate_federated_token(identity_token).await {
            Ok(Some(federated)) => {
                tracing::debug!(
                    org_id = %federated.org_id,
                    trust_level = %federated.trust_level,
                    subject = ?federated.identity.subject,
                    "Federated agent identity validated"
                );
                return Ok(Some(federated.identity));
            }
            Ok(None) => {
                // No matching anchor — fall through to local OAuth
                tracing::trace!("No federation anchor matched, falling through to OAuth");
            }
            Err(e) => {
                // SECURITY: Fail-closed — a matched anchor that fails validation
                // must reject the request. Log details server-side only.
                tracing::warn!("Federation identity validation failed: {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32001,
                            "message": "Invalid agent identity token"
                        },
                        "id": null
                    })),
                )
                    .into_response());
            }
        }
    }

    // Reuse the OAuth validator if configured (same JWKS, same algorithms)
    let validator = match &state.oauth {
        Some(v) => v,
        None => {
            // No OAuth configured — cannot validate JWT signature.
            // SECURITY: Log a warning but do not fail. This allows deployments
            // that use API keys for auth but still want identity attestation
            // to be aware that the JWT is not validated.
            tracing::warn!(
                "X-Agent-Identity header present but no OAuth configured to validate it — \
                 identity claims will not be used (configure OAuth for JWT validation)"
            );
            return Ok(None);
        }
    };

    // Validate the JWT using the same infrastructure as OAuth tokens
    match validator
        .validate_token(&format!("Bearer {identity_token}"))
        .await
    {
        Ok(claims) => {
            // Convert OAuthClaims to AgentIdentity
            let identity = vellaveto_types::AgentIdentity {
                issuer: if claims.iss.is_empty() {
                    None
                } else {
                    Some(claims.iss)
                },
                subject: if claims.sub.is_empty() {
                    None
                } else {
                    Some(claims.sub)
                },
                audience: claims.aud,
                claims: extract_custom_identity_claims(identity_token).unwrap_or_default(),
            };
            if let Err(error) = identity.validate() {
                tracing::warn!("X-Agent-Identity claims validation failed: {}", error);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32001,
                            "message": "Invalid agent identity token"
                        },
                        "id": null
                    })),
                )
                    .into_response());
            }

            tracing::debug!(
                "X-Agent-Identity validated: issuer={:?}, subject={:?}",
                identity.issuer,
                identity.subject
            );
            Ok(Some(identity))
        }
        Err(e) => {
            // SECURITY (R28-PROXY-5): Log details server-side only; return
            // generic error to client to prevent algorithm/kid enumeration.
            tracing::warn!("X-Agent-Identity JWT validation failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32001,
                        "message": "Invalid agent identity token"
                    },
                    "id": null
                })),
            )
                .into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    // =========================================================================
    // build_effective_request_uri tests
    // =========================================================================

    #[test]
    fn test_build_effective_request_uri_no_headers_uses_bind_addr() {
        let headers = HeaderMap::new();
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000));
        let uri: axum::http::Uri = "/mcp".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, false);
        assert_eq!(result, "http://127.0.0.1:3000/mcp");
    }

    #[test]
    fn test_build_effective_request_uri_port_443_uses_https() {
        let headers = HeaderMap::new();
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 443));
        let uri: axum::http::Uri = "/api/v1".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, false);
        assert_eq!(result, "https://0.0.0.0:443/api/v1");
    }

    #[test]
    fn test_build_effective_request_uri_host_header_used() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, "example.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));
        let uri: axum::http::Uri = "/mcp".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, false);
        assert_eq!(result, "http://example.com/mcp");
    }

    #[test]
    fn test_build_effective_request_uri_forwarded_headers_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "api.example.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));
        let uri: axum::http::Uri = "/mcp".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, true);
        assert_eq!(result, "https://api.example.com/mcp");
    }

    #[test]
    fn test_build_effective_request_uri_forwarded_headers_untrusted_proxy_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "evil.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));
        let uri: axum::http::Uri = "/mcp".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, false);
        // Untrusted: forwarded headers should be ignored, falls back to bind addr
        assert_eq!(result, "http://0.0.0.0:8080/mcp");
    }

    #[test]
    fn test_build_effective_request_uri_forwarded_proto_comma_separated() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https, http".parse().unwrap());
        headers.insert(axum::http::header::HOST, "example.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 80));
        let uri: axum::http::Uri = "/".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, true);
        assert_eq!(result, "https://example.com/");
    }

    #[test]
    fn test_build_effective_request_uri_forwarded_host_with_slash_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-host", "evil.com/path".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));
        let uri: axum::http::Uri = "/mcp".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, true);
        // Forwarded-Host with slash is filtered out, falls back to bind addr
        assert_eq!(result, "http://0.0.0.0:8080/mcp");
    }

    #[test]
    fn test_build_effective_request_uri_ipv6_bind_addr() {
        let headers = HeaderMap::new();
        let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3000, 0, 0));
        let uri: axum::http::Uri = "/mcp".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, false);
        assert_eq!(result, "http://[::1]:3000/mcp");
    }

    #[test]
    fn test_build_effective_request_uri_empty_host_header_uses_bind() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, "".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9090));
        let uri: axum::http::Uri = "/api".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, false);
        assert_eq!(result, "http://10.0.0.1:9090/api");
    }

    #[test]
    fn test_build_effective_request_uri_path_and_query_preserved() {
        let headers = HeaderMap::new();
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000));
        let uri: axum::http::Uri = "/mcp?trace=true&debug=1".parse().unwrap();
        let result = build_effective_request_uri(&headers, bind, &uri, false);
        assert_eq!(result, "http://127.0.0.1:3000/mcp?trace=true&debug=1");
    }

    // =========================================================================
    // dpop_mode_label tests
    // =========================================================================

    #[test]
    fn test_dpop_mode_label_off() {
        assert_eq!(dpop_mode_label(crate::oauth::DpopMode::Off), "off");
    }

    #[test]
    fn test_dpop_mode_label_optional() {
        assert_eq!(
            dpop_mode_label(crate::oauth::DpopMode::Optional),
            "optional"
        );
    }

    #[test]
    fn test_dpop_mode_label_required() {
        assert_eq!(
            dpop_mode_label(crate::oauth::DpopMode::Required),
            "required"
        );
    }

    // =========================================================================
    // dpop_failure_label tests
    // =========================================================================

    #[test]
    fn test_dpop_failure_label_missing_proof() {
        assert_eq!(
            dpop_failure_label(&OAuthError::MissingDpopProof),
            "missing_proof"
        );
    }

    #[test]
    fn test_dpop_failure_label_replay_detected() {
        assert_eq!(
            dpop_failure_label(&OAuthError::DpopReplayDetected),
            "replay_detected"
        );
    }

    #[test]
    fn test_dpop_failure_label_invalid_proof() {
        assert_eq!(
            dpop_failure_label(&OAuthError::InvalidDpopProof("bad".to_string())),
            "invalid_proof"
        );
    }

    #[test]
    fn test_dpop_failure_label_other_error_is_validation_error() {
        assert_eq!(
            dpop_failure_label(&OAuthError::InvalidFormat),
            "validation_error"
        );
    }

    #[test]
    fn test_extract_custom_identity_claims_filters_standard_fields() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": "https://issuer.example",
                "sub": "spiffe://cluster/ns/app",
                "aud": ["mcp-server"],
                "scope": "tool:read",
                "namespace": "prod",
                "service_account": "frontend",
                "execution_is_ephemeral": true,
            }))
            .expect("serialize payload"),
        );
        let token = format!("{header}.{payload}.sig");

        let claims = extract_custom_identity_claims(&token).expect("custom claims");

        assert_eq!(claims.get("namespace"), Some(&json!("prod")));
        assert_eq!(claims.get("service_account"), Some(&json!("frontend")));
        assert_eq!(claims.get("execution_is_ephemeral"), Some(&json!(true)));
        assert!(!claims.contains_key("iss"));
        assert!(!claims.contains_key("sub"));
        assert!(!claims.contains_key("aud"));
        assert!(!claims.contains_key("scope"));
    }

    #[test]
    fn test_extract_custom_identity_claims_invalid_token_returns_none() {
        assert!(extract_custom_identity_claims("not-a-jwt").is_none());
    }
}
