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
use serde_json::{json, Value};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use vellaveto_types::{Action, Verdict};

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

    format!("{}://{}{}", proto, authority, path_and_query)
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

    state
        .audit
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: format!("OAuth DPoP validation failed: {}", params.dpop_reason),
            },
            Value::Object(metadata),
        )
        .await
}

#[allow(clippy::result_large_err)]
pub(super) async fn validate_oauth(
    state: &ProxyState,
    headers: &HeaderMap,
    method: &str,
    effective_uri: &str,
    session_hint: Option<&str>,
) -> Result<Option<OAuthClaims>, Response> {
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
            Ok(Some(claims))
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
            let www_auth = format!(
                "Bearer error=\"insufficient_scope\", scope=\"{}\"",
                sanitized_scope
            );
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
        .validate_token(&format!("Bearer {}", identity_token))
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
                claims: std::collections::HashMap::new(),
            };

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
