//! Response inspection: injection scanning, DLP scanning, rug-pull detection,
//! schema validation, and response header attachment.

use axum::response::Response;
use serde_json::{json, Value};
use vellaveto_mcp::inspection::{
    inspect_for_injection, scan_notification_for_secrets, scan_response_for_secrets,
    scan_text_for_secrets, scan_tool_descriptions, scan_tool_descriptions_with_scanner,
};
use vellaveto_mcp::output_validation::ValidationResult;
use vellaveto_types::{Action, EvaluationTrace, Verdict};

use super::call_chain::take_tracked_tool_call;
use super::helpers::{extract_annotations_from_response, verify_manifest_from_response};
use super::{ProxyState, MCP_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID};
use crate::proxy_metrics::record_dlp_finding;

/// Extract text content from an MCP result for injection inspection.
pub(super) fn extract_text_from_result(result: &Value) -> String {
    let mut text_parts = Vec::new();

    // Extract from content array
    if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
        for item in content {
            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                text_parts.push(text.to_string());
            }
            // SECURITY (R12-RESP-13): Also scan resource.text in content items.
            // Matches the coverage of scan_response_for_injection in inspection.rs.
            if let Some(text) = item
                .get("resource")
                .and_then(|r| r.get("text"))
                .and_then(|t| t.as_str())
            {
                text_parts.push(text.to_string());
            }
            // SECURITY (R30-PROXY-5): Scan resource.blob — base64-encoded content
            // that could contain injection payloads. Decode and scan the raw bytes
            // as UTF-8 lossy to catch text-based attacks embedded in binary data.
            if let Some(blob) = item
                .get("resource")
                .and_then(|r| r.get("blob"))
                .and_then(|b| b.as_str())
            {
                // SECURITY (R31-PROXY-4): Try both STANDARD and URL_SAFE alphabets.
                // MCP resource blobs may use either encoding variant.
                use base64::Engine as _;
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD
                    .decode(blob)
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(blob))
                {
                    let text = String::from_utf8_lossy(&decoded);
                    if !text.is_empty() {
                        text_parts.push(text.into_owned());
                    }
                }
            }
            // SECURITY (R38-PROXY-1): Serialize the entire annotations object,
            // not just audience. MCP annotations can have arbitrary fields that
            // may contain injection payloads. The shared function in vellaveto-mcp
            // inspection.rs already serializes the full object — match that behavior.
            if let Some(annotations) = item.get("annotations") {
                text_parts.push(annotations.to_string());
            }
        }
    }

    // SECURITY (R31-MCP-5): Scan instructionsForUser — this field contains text
    // shown directly to the user and is a prime vector for social engineering
    // injection attacks where the server tries to manipulate user decisions.
    if let Some(instructions) = result.get("instructionsForUser").and_then(|i| i.as_str()) {
        text_parts.push(instructions.to_string());
    }

    // Also check structuredContent
    if let Some(structured) = result.get("structuredContent") {
        text_parts.push(structured.to_string());
    }

    // SECURITY (R30-PROXY-3): Scan _meta field — MCP tool results may include
    // a _meta object with arbitrary string values that could carry injection
    // payloads. Serialize the entire _meta object to catch any nested strings.
    if let Some(meta) = result.get("_meta") {
        if meta.is_object() {
            text_parts.push(meta.to_string());
        }
    }

    text_parts.join("\n")
}

/// Scan SSE event data payloads for prompt injection patterns.
///
/// Parses SSE events (delimited by `\n\n`), extracts `data:` lines,
/// and inspects each payload for injection. Detections are logged as
/// audit entries with a Deny verdict.
///
/// Scans SSE events for prompt injection patterns.
///
/// Returns `true` if injection matches were found, `false` otherwise.
/// The caller should check `state.injection_blocking` and block the response
/// when this returns `true` and blocking is enabled.
pub(super) async fn scan_sse_events_for_injection(
    sse_bytes: &[u8],
    session_id: &str,
    state: &ProxyState,
) -> bool {
    // SECURITY (R11-RESP-5): Use lossy UTF-8 conversion instead of skipping.
    // A malicious server could embed non-UTF-8 bytes to bypass injection scanning.
    let sse_text = String::from_utf8_lossy(sse_bytes);

    // SECURITY (R17-SSE-1): Normalize SSE line endings per W3C spec.
    // SSE allows \r\n, \r, or \n as line terminators. A malicious server using
    // \r\r delimiters would bypass split("\n\n"), causing events to merge and
    // potentially exceed MAX_SSE_EVENT_SIZE (skipping all scanning).
    let normalized = sse_text.replace("\r\n", "\n").replace('\r', "\n");
    let events: Vec<&str> = normalized.split("\n\n").collect();
    let mut all_matches: Vec<String> = Vec::new();

    for event in &events {
        // SECURITY (R11-RESP-4): Concatenate all data: lines per event before scanning.
        // SSE spec says multiple data: lines are joined with \n. An attacker can split
        // an injection payload across data: lines to evade per-line scanning.
        let mut data_parts: Vec<&str> = Vec::new();
        for line in event.lines() {
            // SECURITY (R26-PROXY-3, R31-PROXY-5): Trim ASCII whitespace AND Unicode NBSP
            // before prefix check. Without NBSP handling, a malicious server can prefix
            // "data:" lines with U+00A0 to bypass SSE injection scanning.
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(rest) = trimmed.strip_prefix("data:") {
                data_parts.push(rest.trim_start());
            }
        }

        // SECURITY (R34-PROXY-7, R37-PROXY-4): Scan SSE event:, id:, and retry: fields for injection.
        // These fields are forwarded verbatim to the client and could carry
        // injection payloads that bypass data-only scanning.
        for line in event.lines() {
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(value) = trimmed
                .strip_prefix("event:")
                .or_else(|| trimmed.strip_prefix("id:"))
                .or_else(|| trimmed.strip_prefix("retry:"))
            {
                let value = value.trim();
                if !value.is_empty() {
                    let field_matches: Vec<String> =
                        if let Some(ref scanner) = state.injection_scanner {
                            scanner
                                .inspect(value)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        } else {
                            inspect_for_injection(value)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        };
                    if !field_matches.is_empty() {
                        all_matches.extend(field_matches);
                    }
                }
            }
        }

        // SECURITY (R42-PROXY-3): Scan SSE comment lines for injection.
        // Comments (lines starting with ':') are ignored by browsers but may
        // be logged or displayed by non-browser MCP clients, making them a
        // viable injection vector.
        for line in event.lines() {
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(comment) = trimmed.strip_prefix(':') {
                let comment = comment.trim();
                if !comment.is_empty() {
                    let comment_matches: Vec<String> =
                        if let Some(ref scanner) = state.injection_scanner {
                            scanner
                                .inspect(comment)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        } else {
                            inspect_for_injection(comment)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        };
                    if !comment_matches.is_empty() {
                        all_matches.extend(comment_matches);
                    }
                }
            }
        }

        if data_parts.is_empty() {
            continue;
        }

        let data_payload = data_parts.join("\n");
        if data_payload.trim().is_empty() {
            continue;
        }
        // SECURITY (R18-SSE-OVERSIZE): Oversized events are treated as suspicious.
        // A malicious server can pad events to exceed the size limit and bypass scanning.
        // Fail-closed: flag as injection match so blocking mode will reject the stream.
        if data_payload.len() > state.limits.max_sse_event_bytes {
            tracing::warn!(
                "SECURITY: Oversized SSE event ({} bytes > {} limit) — \
                 treating as suspicious (potential scan evasion)",
                data_payload.len(),
                state.limits.max_sse_event_bytes,
            );
            all_matches.push(format!("oversized_sse_event({}bytes)", data_payload.len()));
            continue;
        }

        // Try to parse as JSON (MCP SSE typically sends JSON-RPC in data lines)
        if let Ok(json_val) = serde_json::from_str::<Value>(&data_payload) {
            // Scan result content
            if let Some(result) = json_val.get("result") {
                let text = extract_text_from_result(result);
                if !text.is_empty() {
                    let matches: Vec<String> = if let Some(ref scanner) = state.injection_scanner {
                        scanner
                            .inspect(&text)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    } else {
                        inspect_for_injection(&text)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    };
                    all_matches.extend(matches);
                }

                // SECURITY (R34-PROXY-1): SSE tools/list responses must also be scanned
                // for injection in tool descriptions, matching the JSON response path.
                // Without this, a malicious server can embed injection payloads in tool
                // description or inputSchema fields and deliver them via SSE to bypass
                // the injection scanner that only checks content[].text fields.
                if result.get("tools").and_then(|t| t.as_array()).is_some() {
                    let desc_findings = if let Some(ref scanner) = state.injection_scanner {
                        scan_tool_descriptions_with_scanner(&json_val, scanner)
                    } else {
                        scan_tool_descriptions(&json_val)
                    };
                    for finding in &desc_findings {
                        all_matches.extend(
                            finding
                                .matched_patterns
                                .iter()
                                .map(|p| format!("tool_desc({}): {}", finding.tool_name, p)),
                        );
                    }
                }
            }

            // Scan error fields
            if let Some(error) = json_val.get("error") {
                let mut error_text = String::new();
                if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                    error_text.push_str(msg);
                    error_text.push('\n');
                }
                if let Some(data) = error.get("data") {
                    if let Some(s) = data.as_str() {
                        error_text.push_str(s);
                    } else {
                        error_text.push_str(&data.to_string());
                    }
                }
                if !error_text.is_empty() {
                    let matches: Vec<String> = if let Some(ref scanner) = state.injection_scanner {
                        scanner
                            .inspect(&error_text)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    } else {
                        inspect_for_injection(&error_text)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    };
                    all_matches.extend(matches);
                }
            }
        } else {
            // Not JSON — scan concatenated raw text
            let matches: Vec<String> = if let Some(ref scanner) = state.injection_scanner {
                scanner
                    .inspect(&data_payload)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                inspect_for_injection(&data_payload)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            };
            all_matches.extend(matches);
        }
    }

    let found = !all_matches.is_empty();
    if found {
        tracing::warn!(
            "SECURITY: Potential prompt injection in SSE response! \
             Session: {}, Patterns: {:?}, Blocking: {}",
            session_id,
            all_matches,
            state.injection_blocking
        );
        let verdict = if state.injection_blocking {
            Verdict::Deny {
                reason: format!(
                    "SSE response blocked: prompt injection detected ({:?})",
                    all_matches
                ),
            }
        } else {
            Verdict::Allow
        };
        let action = Action::new(
            "vellaveto",
            "sse_response_inspection",
            json!({
                "matched_patterns": all_matches,
                "session": session_id,
                "event_count": events.len(),
                "blocking": state.injection_blocking,
            }),
        );
        if let Err(e) = state
            .audit
            .log_entry(
                &action,
                &verdict,
                json!({
                    "source": "http_proxy",
                    "event": "sse_injection_detected",
                }),
            )
            .await
        {
            tracing::warn!("Failed to audit SSE injection detection: {}", e);
        }
    }
    found
}

/// Scan SSE event data payloads for DLP secret patterns.
///
/// Parses SSE events, extracts JSON-RPC result payloads, and scans
/// them for secrets (AWS keys, GitHub tokens, etc). Findings are logged
/// as audit entries. Returns `true` if any secrets were detected.
///
/// # Known Limitation (FIND-R44-027)
///
/// SSE streaming can split a secret across multiple `data:` lines within
/// a single event, or across event boundaries. This scanner concatenates
/// `data:` lines per event (R11-RESP-4) but cannot detect secrets split
/// across separate SSE events. A malicious server could fragment a secret
/// like "AKIA" + "IOSFODNN7EXAMPLE" across two events to evade detection.
/// Mitigation: use `response_dlp_blocking` with a downstream reassembly
/// buffer, or rely on request-side DLP to catch secrets when they are
/// subsequently used in tool call parameters.
pub(super) async fn scan_sse_events_for_dlp(
    sse_bytes: &[u8],
    session_id: &str,
    state: &ProxyState,
) -> bool {
    let mut secrets_found = false;
    // SECURITY (R11-RESP-5): Use lossy UTF-8 conversion instead of skipping.
    let sse_text = String::from_utf8_lossy(sse_bytes);

    // SECURITY (R17-SSE-1): Normalize SSE line endings per W3C spec (see injection scanner).
    let normalized = sse_text.replace("\r\n", "\n").replace('\r', "\n");

    // SECURITY (R11-RESP-4): Concatenate data: lines per event before scanning.
    for event in normalized.split("\n\n") {
        let mut data_parts: Vec<&str> = Vec::new();
        for line in event.lines() {
            // SECURITY (R26-PROXY-3, R31-PROXY-5): Trim ASCII whitespace AND Unicode NBSP
            // before prefix check. Without NBSP handling, a malicious server can prefix
            // "data:" lines with U+00A0 to bypass SSE injection scanning.
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(rest) = trimmed.strip_prefix("data:") {
                data_parts.push(rest.trim_start());
            }
        }

        // SECURITY (R34-PROXY-7, R37-PROXY-4): Scan SSE event:, id:, and retry: fields for DLP secrets.
        // These fields are forwarded verbatim to the client and could carry
        // secret data that bypasses data-only DLP scanning.
        for line in event.lines() {
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(value) = trimmed
                .strip_prefix("event:")
                .or_else(|| trimmed.strip_prefix("id:"))
                .or_else(|| trimmed.strip_prefix("retry:"))
            {
                let value = value.trim();
                if !value.is_empty() {
                    let field_dlp = scan_text_for_secrets(value, "sse_field(event/id/retry)");
                    if !field_dlp.is_empty() {
                        secrets_found = true;
                        let patterns: Vec<String> = field_dlp
                            .iter()
                            .map(|f| format!("{}:{}", f.pattern_name, f.location))
                            .collect();
                        tracing::warn!(
                            "SECURITY: Secrets detected in SSE event:/id:/retry: field! \
                             Session: {}, Findings: {:?}",
                            session_id,
                            patterns,
                        );
                    }
                }
            }
        }

        // SECURITY (R42-PROXY-4): Scan SSE comment lines for secrets.
        // Comments (lines starting with ':') are ignored by browsers but may
        // be logged or displayed by non-browser MCP clients. Secrets embedded
        // in comment lines bypass data-only DLP scanning.
        for line in event.lines() {
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(comment) = trimmed.strip_prefix(':') {
                let comment = comment.trim();
                if !comment.is_empty() {
                    let comment_dlp = scan_text_for_secrets(comment, "sse_comment");
                    if !comment_dlp.is_empty() {
                        secrets_found = true;
                        let patterns: Vec<String> = comment_dlp
                            .iter()
                            .map(|f| format!("{}:{}", f.pattern_name, f.location))
                            .collect();
                        tracing::warn!(
                            "SECURITY: Secrets detected in SSE comment line! \
                             Session: {}, Findings: {:?}",
                            session_id,
                            patterns,
                        );
                    }
                }
            }
        }

        if data_parts.is_empty() {
            continue;
        }
        let data_payload = data_parts.join("\n");
        if data_payload.trim().is_empty() {
            continue;
        }
        // SECURITY (R18-SSE-OVERSIZE): Oversized events are treated as suspicious.
        // Fail-closed: flag as found so blocking mode will reject the entire stream.
        if data_payload.len() > state.limits.max_sse_event_bytes {
            tracing::warn!(
                "SECURITY: Oversized SSE event ({} bytes > {} limit) — \
                 treating as suspicious for DLP (potential scan evasion)",
                data_payload.len(),
                state.limits.max_sse_event_bytes,
            );
            secrets_found = true;
            continue;
        }

        let dlp_findings = if let Ok(json_val) = serde_json::from_str::<Value>(&data_payload) {
            // SECURITY (R19-SSE-NOTIF-DLP): SSE streams can carry both responses
            // (result/error) and notifications (method+params, no id). The original
            // code only called scan_response_for_secrets which scans result/error
            // fields, missing secrets in notification params entirely.
            let mut findings = scan_response_for_secrets(&json_val);
            if json_val.get("method").is_some() {
                findings.extend(scan_notification_for_secrets(&json_val));
            }
            findings
        } else {
            // SECURITY (R17-SSE-4): Non-JSON SSE data must also be scanned.
            // A malicious upstream can embed secrets in plain-text SSE data lines
            // (e.g., `data: AKIAIOSFODNN7EXAMPLE\n\n`) to bypass JSON-only DLP.
            scan_text_for_secrets(&data_payload, "sse_data(raw)")
        };

        if !dlp_findings.is_empty() {
            // IMPROVEMENT_PLAN 1.1: Record DLP metrics
            for finding in &dlp_findings {
                record_dlp_finding(&finding.pattern_name);
            }
            secrets_found = true;
            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{}:{}", f.pattern_name, f.location))
                .collect();
            tracing::warn!(
                "SECURITY: Secrets detected in SSE tool response! \
                 Session: {}, Findings: {:?}, Blocking: {}",
                session_id,
                patterns,
                state.response_dlp_blocking,
            );
            let verdict = if state.response_dlp_blocking {
                Verdict::Deny {
                    reason: format!("SSE response DLP blocked: {:?}", patterns),
                }
            } else {
                Verdict::Allow
            };
            let action = Action::new(
                "vellaveto",
                "sse_response_dlp_scan",
                json!({
                    "findings": patterns,
                    "session": session_id,
                    "finding_count": dlp_findings.len(),
                }),
            );
            if let Err(e) = state
                .audit
                .log_entry(
                    &action,
                    &verdict,
                    json!({
                        "source": "http_proxy",
                        "event": "sse_response_dlp_alert",
                        "blocked": state.response_dlp_blocking,
                        "dlp_detail": format!(
                            "Secrets detected in SSE response: {:?}",
                            patterns
                        ),
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit SSE DLP finding: {}", e);
            }
        }
    }
    secrets_found
}

/// Process SSE events for rug-pull detection and manifest verification.
///
/// SECURITY (R18-SSE-RUG): The JSON response path calls `extract_annotations_from_response`
/// and `verify_manifest_from_response` on every response. Without this function, a malicious
/// server could bypass rug-pull detection and manifest pinning by returning tools/list
/// responses via SSE instead of JSON.
pub(super) async fn check_sse_for_rug_pull_and_manifest(
    sse_bytes: &[u8],
    session_id: &str,
    state: &ProxyState,
    injection_found: bool,
    // SECURITY (R32-PROXY-2): Also skip recording when DLP found secrets,
    // not just when injection was detected.
    dlp_found: bool,
    // SECURITY: Skip memory fingerprint recording when output-schema validation failed.
    schema_violation_found: bool,
) {
    let sse_text = String::from_utf8_lossy(sse_bytes);
    let normalized = sse_text.replace("\r\n", "\n").replace('\r', "\n");

    for event in normalized.split("\n\n") {
        let mut data_parts: Vec<&str> = Vec::new();
        for line in event.lines() {
            // SECURITY (R26-PROXY-3, R31-PROXY-5): Trim ASCII whitespace AND Unicode NBSP
            // before prefix check. Without NBSP handling, a malicious server can prefix
            // "data:" lines with U+00A0 to bypass SSE injection scanning.
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(rest) = trimmed.strip_prefix("data:") {
                data_parts.push(rest.trim_start());
            }
        }
        if data_parts.is_empty() {
            continue;
        }
        let data_payload = data_parts.join("\n");
        if data_payload.trim().is_empty() {
            continue;
        }
        // SECURITY (R18-SSE-OVERSIZE): Log oversized events for rug-pull/manifest.
        // We skip processing but warn — the injection/DLP scanners handle blocking.
        if data_payload.len() > state.limits.max_sse_event_bytes {
            tracing::warn!(
                "SECURITY: Oversized SSE event ({} bytes) skipped for rug-pull/manifest check",
                data_payload.len(),
            );
            continue;
        }

        if let Ok(json_val) = serde_json::from_str::<Value>(&data_payload) {
            // Rug-pull detection: extract annotations from tools/list responses
            extract_annotations_from_response(
                &json_val,
                session_id,
                &state.sessions,
                &state.audit,
                &state.known_tools,
            )
            .await;

            // Manifest verification: verify tools/list against pinned manifest
            if let Some(ref manifest_cfg) = state.manifest_config {
                verify_manifest_from_response(
                    &json_val,
                    session_id,
                    &state.sessions,
                    manifest_cfg,
                    &state.audit,
                )
                .await;
            }

            // OWASP ASI06: Record SSE response fingerprints for memory poisoning detection.
            // SECURITY (R27-PROXY-1): Skip recording when injection was detected (even in
            // log-only mode). Recording fingerprints from known-malicious responses would
            // cause false-positive poisoning blocks when the agent later uses legitimate
            // parameter values that happened to appear in the injection-laced response.
            // SECURITY (R32-PROXY-2): Also skip when DLP found secrets — recording
            // fingerprints from secret-containing responses would poison the tracker.
            // SECURITY: Also skip when schema validation failed.
            if !injection_found && !dlp_found && !schema_violation_found {
                if let Some(mut session) = state.sessions.get_mut(session_id) {
                    session.memory_tracker.record_response(&json_val);
                }
            }
        }
    }
}

/// Register output schemas from tools/list responses in SSE events.
///
/// Parses SSE events looking for JSON-RPC responses containing tools/list
/// results and registers their output schemas in the registry.
pub(super) fn register_schemas_from_sse(sse_bytes: &[u8], state: &ProxyState) {
    // SECURITY (R11-RESP-5): Use lossy UTF-8 conversion to avoid silent bypass.
    let sse_text = String::from_utf8_lossy(sse_bytes);

    // SECURITY (R17-SSE-1): Normalize SSE line endings per W3C spec.
    let normalized = sse_text.replace("\r\n", "\n").replace('\r', "\n");

    // SECURITY (R11-RESP-4): Concatenate data: lines per event before parsing.
    for event in normalized.split("\n\n") {
        let mut data_parts: Vec<&str> = Vec::new();
        for line in event.lines() {
            // SECURITY (R26-PROXY-3, R31-PROXY-5): Trim ASCII whitespace AND Unicode NBSP
            // before prefix check. Without NBSP handling, a malicious server can prefix
            // "data:" lines with U+00A0 to bypass SSE injection scanning.
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(rest) = trimmed.strip_prefix("data:") {
                data_parts.push(rest.trim_start());
            }
        }
        if data_parts.is_empty() {
            continue;
        }
        let data_payload = data_parts.join("\n");
        if data_payload.trim().is_empty() {
            continue;
        }
        // SECURITY (R18-SSE-OVERSIZE): Log oversized events for schema registration.
        if data_payload.len() > state.limits.max_sse_event_bytes {
            tracing::warn!(
                "SECURITY: Oversized SSE event ({} bytes) skipped for schema registration",
                data_payload.len(),
            );
            continue;
        }

        if let Ok(json_val) = serde_json::from_str::<Value>(&data_payload) {
            // register_from_tools_list checks for result.tools internally
            state
                .output_schema_registry
                .register_from_tools_list(&json_val);
        }
    }
}

/// Validate `structuredContent` in SSE JSON-RPC payloads against registered output schemas.
///
/// Returns `true` when at least one schema violation is detected.
pub(super) async fn scan_sse_events_for_output_schema(
    sse_bytes: &[u8],
    session_id: &str,
    state: &ProxyState,
) -> bool {
    // SECURITY (R11-RESP-5): Use lossy UTF-8 conversion to avoid silent bypass.
    let sse_text = String::from_utf8_lossy(sse_bytes);
    // SECURITY (R17-SSE-1): Normalize SSE line endings per W3C spec.
    let normalized = sse_text.replace("\r\n", "\n").replace('\r', "\n");

    let mut violation_found = false;
    for event in normalized.split("\n\n") {
        let mut data_parts: Vec<&str> = Vec::new();
        for line in event.lines() {
            let trimmed = line.trim_start_matches([' ', '\t', '\u{00A0}']);
            if let Some(rest) = trimmed.strip_prefix("data:") {
                data_parts.push(rest.trim_start());
            }
        }
        if data_parts.is_empty() {
            continue;
        }

        let data_payload = data_parts.join("\n");
        if data_payload.trim().is_empty() || data_payload.len() > state.limits.max_sse_event_bytes {
            continue;
        }

        let Ok(json_val) = serde_json::from_str::<Value>(&data_payload) else {
            continue;
        };
        let Some(result) = json_val.get("result") else {
            continue;
        };
        let Some(structured) = result.get("structuredContent") else {
            continue;
        };

        // Consume tracked tool mapping for this response id when structuredContent appears.
        let tracked_tool_name =
            take_tracked_tool_call(&state.sessions, session_id, json_val.get("id"));
        let meta_tool_name = result
            .get("_meta")
            .and_then(|m| m.get("tool"))
            .and_then(|t| t.as_str());
        let tool_name = match (meta_tool_name, tracked_tool_name.as_deref()) {
            (Some(meta), Some(tracked)) if !meta.eq_ignore_ascii_case(tracked) => {
                tracing::warn!(
                    "SECURITY: SSE structuredContent tool mismatch (meta='{}', tracked='{}'); using tracked tool name",
                    meta,
                    tracked
                );
                tracked
            }
            (Some(meta), _) => meta,
            (None, Some(tracked)) => tracked,
            (None, None) => "unknown",
        };

        match state.output_schema_registry.validate(tool_name, structured) {
            ValidationResult::Invalid { violations } => {
                violation_found = true;
                tracing::warn!(
                    "SECURITY: SSE structuredContent validation failed for tool '{}': {:?}",
                    tool_name,
                    violations
                );
                let action = Action::new(
                    "vellaveto",
                    "output_schema_violation",
                    json!({
                        "tool": tool_name,
                        "violations": violations,
                        "session": session_id,
                        "transport": "sse",
                    }),
                );
                if let Err(e) = state
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: format!(
                                "SSE structuredContent validation failed: {:?}",
                                violations
                            ),
                        },
                        json!({"source": "http_proxy", "event": "output_schema_violation_sse"}),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit SSE output schema violation: {}", e);
                }
            }
            ValidationResult::Valid => {
                tracing::debug!("SSE structuredContent validated for tool '{}'", tool_name);
            }
            ValidationResult::NoSchema => {
                tracing::debug!(
                    "No output schema registered for SSE tool '{}', skipping validation",
                    tool_name
                );
            }
        }
    }

    violation_found
}

/// Add the Mcp-Session-Id and MCP-Protocol-Version headers to a response.
pub(super) fn attach_session_header(mut response: Response, session_id: &str) -> Response {
    if let Ok(value) = session_id.parse() {
        response.headers_mut().insert(MCP_SESSION_ID, value);
    }
    if let Ok(value) = MCP_PROTOCOL_VERSION.parse() {
        response
            .headers_mut()
            .insert(MCP_PROTOCOL_VERSION_HEADER, value);
    }
    response
}

/// Attach evaluation trace as an X-Vellaveto-Trace header for allowed (forwarded) requests.
///
/// Header value is capped at 4KB to prevent oversized HTTP responses from
/// deeply nested traces.
pub(super) fn attach_trace_header(
    mut response: Response,
    trace: Option<EvaluationTrace>,
) -> Response {
    const MAX_TRACE_HEADER_BYTES: usize = 4096;
    if let Some(t) = trace {
        if let Ok(json_str) = serde_json::to_string(&t) {
            if json_str.len() <= MAX_TRACE_HEADER_BYTES {
                if let Ok(value) = json_str.parse() {
                    response.headers_mut().insert("x-vellaveto-trace", value);
                }
            } else {
                tracing::debug!(
                    "Trace header too large ({} bytes), omitting from response",
                    json_str.len()
                );
            }
        }
    }
    response
}
