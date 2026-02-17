//! Utility functions for the HTTP proxy: DNS resolution, bounded reads,
//! annotation extraction, and manifest verification.

use bytes::Bytes;
use serde_json::Value;
use vellaveto_audit::AuditLogger;
use vellaveto_config::{ManifestConfig, ToolManifest};
use vellaveto_types::{Action, Verdict};

use crate::session::SessionStore;

/// Resolve target domains to IP addresses for DNS rebinding protection.
///
/// Populates `action.resolved_ips` with the IP addresses that each target domain
/// resolves to. If DNS resolution fails for a domain, no IPs are added for it —
/// the engine will deny the action fail-closed if IP rules are configured.
pub(super) async fn resolve_domains(action: &mut Action) {
    if action.target_domains.is_empty() {
        return;
    }
    let mut resolved = Vec::new();
    for domain in &action.target_domains {
        // Strip port if present (domain might be "example.com:8080")
        let host = domain.split(':').next().unwrap_or(domain);
        match tokio::net::lookup_host((host, 0)).await {
            Ok(addrs) => {
                for addr in addrs {
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
        if len as usize > max_size {
            return Err(format!(
                "Response too large: {} bytes (max {})",
                len, max_size
            ));
        }
    }

    let capacity = std::cmp::min(resp.content_length().unwrap_or(8192) as usize, max_size);
    let mut body = Vec::with_capacity(capacity);

    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > max_size {
            return Err(format!("Response exceeded {} byte limit", max_size));
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
    if let Some(mut s) = sessions.get_mut(session_id) {
        s.known_tools = result.updated_known.clone();
        for name in result.flagged_tool_names() {
            // SECURITY (FIND-R51-014): Use bounded insertion for flagged tools.
            s.insert_flagged_tool(name.to_string());
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
                if let Err(e) = audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: format!("Manifest verification failed: {:?}", discrepancies),
                        },
                        serde_json::json!({
                            "source": "http_proxy",
                            "event": "manifest_verification_failed",
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit manifest failure: {}", e);
                }
            }
        }
    }
}
