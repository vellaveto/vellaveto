// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Utility functions for the HTTP proxy: DNS resolution, bounded reads,
//! annotation extraction, and manifest verification.

use bytes::Bytes;
use serde_json::Value;
use vellaveto_approval::ApprovalStatus;
use vellaveto_audit::AuditLogger;
use vellaveto_config::{ManifestConfig, ToolManifest};
use vellaveto_engine::acis::fingerprint_action;
use vellaveto_mcp::mediation::build_secondary_acis_envelope;
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{Action, Verdict};

use super::ProxyState;
use crate::session::SessionStore;

/// Resolve target domains to IP addresses for DNS rebinding protection.
///
/// Populates `action.resolved_ips` with the IP addresses that each target domain
/// resolves to. If DNS resolution fails for a domain, no IPs are added for it —
/// the engine will deny the action fail-closed if IP rules are configured.
pub(super) async fn resolve_domains(action: &mut Action) {
    /// SECURITY (IMP-R160-003): Cap resolved IPs to prevent OOM from domains with
    /// many A/AAAA records. Parity with stdio relay (FIND-R80-004).
    const MAX_RESOLVED_IPS: usize = 100;

    if action.target_domains.is_empty() {
        return;
    }
    let mut resolved = Vec::new();
    for domain in &action.target_domains {
        if resolved.len() >= MAX_RESOLVED_IPS {
            tracing::warn!(
                domain = %domain,
                "Resolved IPs cap ({}) reached — skipping remaining domains",
                MAX_RESOLVED_IPS,
            );
            break;
        }
        // Strip port if present (domain might be "example.com:8080")
        let host = domain.split(':').next().unwrap_or(domain);
        match tokio::net::lookup_host((host, 0)).await {
            Ok(addrs) => {
                for addr in addrs {
                    if resolved.len() >= MAX_RESOLVED_IPS {
                        tracing::warn!(
                            domain = %domain,
                            "Resolved IPs cap ({}) reached during DNS iteration",
                            MAX_RESOLVED_IPS,
                        );
                        break;
                    }
                    resolved.push(addr.ip().to_string());
                }
            }
            Err(e) => {
                tracing::warn!(
                    domain = %domain,
                    error = %e,
                    "DNS resolution failed — resolved_ips will be empty for this domain"
                );
                // Fail-closed: engine will deny if ip_rules configured but no IPs resolved
            }
        }
    }
    action.resolved_ips = resolved;
}

/// Extract a presented approval ID from a JSON-RPC message `_meta`.
///
/// Accepts both top-level `_meta` and nested `params._meta`, matching the
/// stdio relay path. Length-capped and control-char filtered so malformed
/// approval IDs fail closed before any store lookup.
pub(super) fn extract_approval_id_from_meta(msg: &Value) -> Option<String> {
    vellaveto_approval::extract_presented_approval_id_from_rpc_meta(msg)
}

/// Validate a presented approval against the current proxy session and action.
pub(super) async fn presented_approval_matches_action(
    state: &ProxyState,
    session_id: &str,
    presented_approval_id: Option<&str>,
    action: &Action,
) -> Result<Option<String>, ()> {
    let Some(approval_id) = presented_approval_id else {
        return Ok(None);
    };

    let Some(store) = state.approval_store.as_ref() else {
        tracing::warn!(
            approval_id = %approval_id,
            "Presented approval cannot be verified without an approval store"
        );
        return Err(());
    };

    let approval = match store.get(approval_id).await {
        Ok(approval) => approval,
        Err(e) => {
            tracing::warn!(
                approval_id = %approval_id,
                error = ?e,
                "Presented approval lookup failed"
            );
            return Err(());
        }
    };

    if approval.status != ApprovalStatus::Approved {
        tracing::warn!(
            approval_id = %approval_id,
            status = ?approval.status,
            "Presented approval is not approved"
        );
        return Err(());
    }

    // Fail closed on approvals that predate action-fingerprint binding.
    if approval.action_fingerprint.is_none() {
        tracing::warn!(
            approval_id = %approval_id,
            "Presented approval missing action fingerprint binding"
        );
        return Err(());
    }

    let action_fingerprint = fingerprint_action(action);
    if !approval.scope_matches(Some(session_id), Some(action_fingerprint.as_str())) {
        tracing::warn!(
            approval_id = %approval_id,
            session_id = %session_id,
            "Presented approval scope does not match the current proxy session and action"
        );
        return Err(());
    }

    Ok(Some(approval_id.to_string()))
}

/// Consume a presented approval once the request is about to be forwarded.
pub(super) async fn consume_presented_approval(
    state: &ProxyState,
    session_id: &str,
    approval_id: Option<&str>,
    action: &Action,
) -> Result<(), ()> {
    let Some(approval_id) = approval_id else {
        return Ok(());
    };

    let Some(store) = state.approval_store.as_ref() else {
        tracing::warn!(
            approval_id = %approval_id,
            "Presented approval cannot be consumed without an approval store"
        );
        return Err(());
    };

    let action_fingerprint = fingerprint_action(action);
    match store
        .consume_approved(
            approval_id,
            Some(session_id),
            Some(action_fingerprint.as_str()),
        )
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::warn!(
                approval_id = %approval_id,
                session_id = %session_id,
                "Presented approval could not be consumed for this proxy session and action"
            );
            Err(())
        }
        Err(e) => {
            tracing::warn!(
                approval_id = %approval_id,
                error = ?e,
                "Presented approval consume failed"
            );
            Err(())
        }
    }
}

/// Read a response body with a size limit to prevent OOM.
///
/// Uses chunked reading so oversized responses are rejected before fully
/// buffering into memory. This prevents a malicious or misconfigured upstream
/// from sending an infinite SSE stream or oversized JSON response.
pub(super) async fn read_bounded_response(
    mut resp: reqwest::Response,
    max_size: usize,
) -> Result<Bytes, String> {
    // Fast path: if Content-Length is known and exceeds limit, reject immediately
    if let Some(len) = resp.content_length() {
        // SECURITY (R240-P3-PROXY-1): Compare in u64 space to avoid truncation on 32-bit.
        if len > max_size as u64 {
            return Err(format!("Response too large: {len} bytes (max {max_size})"));
        }
    }

    let capacity = std::cmp::min(
        resp.content_length()
            .map(|l| l.min(max_size as u64) as usize)
            .unwrap_or(8192),
        max_size,
    );
    let mut body = Vec::with_capacity(capacity);

    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        // SECURITY (FIND-R74-001): Use saturating_add to prevent theoretical overflow.
        if body.len().saturating_add(chunk.len()) > max_size {
            return Err(format!("Response exceeded {max_size} byte limit"));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(Bytes::from(body))
}

// Message classification and action extraction use the shared
// vellaveto_mcp::extractor module to ensure identical behavior
// between the stdio and HTTP proxies (Challenge 3 fix).

/// Extract tool annotations from a tools/list response and update session state.
///
/// Delegates to the shared `vellaveto_mcp::rug_pull` module for detection logic,
/// then updates session state and audits any detected events.
pub(super) async fn extract_annotations_from_response(
    response: &Value,
    session_id: &str,
    sessions: &SessionStore,
    audit: &AuditLogger,
    known_tools: &std::collections::HashSet<String>,
) {
    // Extract current known tools and first-list flag from session
    let (known, is_first_list) = match sessions.get_mut(session_id) {
        Some(mut s) => {
            let first = !s.tools_list_seen;
            s.tools_list_seen = true;
            (s.known_tools.clone(), first)
        }
        None => return,
    };

    // Run shared detection algorithm with squatting detection
    let result = vellaveto_mcp::rug_pull::detect_rug_pull_and_squatting(
        response,
        &known,
        is_first_list,
        known_tools,
    );

    // Update session state with detection results
    // SECURITY (FIND-R52-SESSION-001): Use bounded `insert_known_tool` instead of
    // direct assignment to enforce the MAX_KNOWN_TOOLS capacity limit.
    if let Some(mut s) = sessions.get_mut(session_id) {
        // Clear existing tools first, then re-insert through bounded method.
        // This ensures the updated set respects capacity limits.
        s.known_tools.clear();
        for (name, annotations) in &result.updated_known {
            if !s.insert_known_tool(name.clone(), annotations.clone()) {
                tracing::warn!(
                    session_id = %session_id,
                    "Known tools capacity reached during rug-pull update; truncating"
                );
                break;
            }
        }
        for name in result.flagged_tool_names() {
            // SECURITY (FIND-R51-014): Use bounded insertion for flagged tools.
            s.insert_flagged_tool(name.to_string());
            // SECURITY (R240-PROXY-1): Also record in global registry so the flag
            // survives session eviction (timeout or capacity pressure).
            sessions.flag_tool_globally(name.to_string());
        }
    }

    // Audit any detected events
    vellaveto_mcp::rug_pull::audit_rug_pull_events(&result, audit, "http_proxy").await;
}

/// Verify a tools/list response against the session's pinned manifest.
///
/// On the first tools/list response, builds and pins the manifest.
/// On subsequent responses, verifies against the pinned manifest and
/// audits any discrepancies.
pub(super) async fn verify_manifest_from_response(
    response: &Value,
    session_id: &str,
    sessions: &SessionStore,
    manifest_config: &ManifestConfig,
    audit: &AuditLogger,
) {
    if !manifest_config.enabled {
        return;
    }

    // Check if we already have a pinned manifest
    let has_pinned = sessions
        .get_mut(session_id)
        .map(|s| s.pinned_manifest.is_some())
        .unwrap_or(false);

    if !has_pinned {
        // First tools/list: pin the manifest
        if let Some(manifest) = ToolManifest::from_tools_list(response) {
            tracing::info!(
                "Session {}: pinned tool manifest ({} tools)",
                session_id,
                manifest.tools.len()
            );
            if let Some(mut s) = sessions.get_mut(session_id) {
                s.pinned_manifest = Some(manifest);
            }
        }
    } else {
        // Subsequent tools/list: verify against pinned
        let pinned = sessions
            .get_mut(session_id)
            .and_then(|s| s.pinned_manifest.clone());

        if let Some(pinned) = pinned {
            if let Err(discrepancies) = manifest_config.verify_manifest(&pinned, response) {
                tracing::warn!(
                    "SECURITY: Session {}: tool manifest verification FAILED: {:?}",
                    session_id,
                    discrepancies
                );
                let action = Action::new(
                    "vellaveto",
                    "manifest_verification",
                    serde_json::json!({
                        "session": session_id,
                        "discrepancies": discrepancies,
                        "pinned_tool_count": pinned.tools.len(),
                    }),
                );
                let manifest_verdict = Verdict::Deny {
                    reason: format!("Manifest verification failed: {discrepancies:?}"),
                };
                let envelope = build_secondary_acis_envelope(
                    &action,
                    &manifest_verdict,
                    DecisionOrigin::PolicyEngine,
                    "http",
                    Some(session_id),
                );
                if let Err(e) = audit
                    .log_entry_with_acis(
                        &action,
                        &manifest_verdict,
                        serde_json::json!({
                            "source": "http_proxy",
                            "event": "manifest_verification_failed",
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit manifest failure: {}", e);
                }
            }
        }
    }
}
