// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Remediation guidance for failed attack tests.

/// Return remediation guidance for a given attack class prefix (e.g., "A1").
pub fn guidance(attack_id: &str) -> &'static str {
    let prefix = attack_id.split('.').next().unwrap_or(attack_id);
    match prefix {
        "A1" => concat!(
            "Implement a multi-layer injection scanner: (1) strip invisible Unicode ",
            "(zero-width, bidi, tags), (2) NFKC-normalize, (3) decode encodings ",
            "(base64, ROT13, HTML entities, Punycode), (4) match against known ",
            "injection patterns using Aho-Corasick. Scan all tool response content ",
            "including resource blobs.",
        ),
        "A2" => concat!(
            "Hash tool schemas (inputSchema + annotations) on first observation using ",
            "RFC 8785 canonical JSON. Compare on subsequent sessions. Alert on any ",
            "change including new tools, removed tools, parameter additions, and ",
            "annotation mutations (e.g., destructiveHint false→true).",
        ),
        "A3" => concat!(
            "Enforce parameter-level constraints (regex, glob, domain) on all parameter ",
            "values. Iteratively decode percent-encoding before constraint evaluation. ",
            "Validate nested/deep parameters. Implement deny-by-default for unmatched actions.",
        ),
        "A4" => concat!(
            "Implement a 5-layer DLP decoder: iteratively apply base64, percent-encoding, ",
            "hex, and mixed chains up to 5 layers deep. Match decoded output against ",
            "secret patterns (AWS keys, GitHub tokens, private key headers, JWTs). ",
            "Scan error messages and all response fields.",
        ),
        "A5" => concat!(
            "Enforce deny-by-default access control. Implement priority-based policy ",
            "evaluation (higher priority wins). Prevent privilege escalation through ",
            "delegation — delegated capabilities must be a strict subset of the parent. ",
            "Block self-approval (same principal creating and approving).",
        ),
        "A6" => concat!(
            "Scan tool responses for memory poisoning patterns: instructions that attempt ",
            "to modify agent behavior, inject persistent prompts, or override system ",
            "instructions. Block responses containing memory poisoning — do not just ",
            "log them.",
        ),
        "A7" => concat!(
            "Normalize tool names using NFKC before policy lookup. Detect homoglyphs ",
            "(Cyrillic/Greek → Latin mapping). Flag mixed-script tool names. Strip ",
            "invisible characters from tool names before evaluation.",
        ),
        "A8" => concat!(
            "Implement a tamper-evident audit log using SHA-256 hash chains. Each entry ",
            "must include entry_hash and prev_hash fields linking it to the previous entry. ",
            "Use length-prefixed encoding to prevent hash collision attacks.",
        ),
        "A9" => concat!(
            "Validate URLs against SSRF allowlists. Resolve DNS and check the resolved IP ",
            "against private ranges (RFC 1918, link-local, loopback). Detect IPv4-mapped ",
            "IPv6 (::ffff:x.x.x.x) and NAT64 (64:ff9b::/96) bypass attempts. Block ",
            "cloud metadata endpoints (169.254.169.254).",
        ),
        "A10" => concat!(
            "Implement per-tool and per-agent rate limiting with sliding time windows. ",
            "Enforce time-windowed policies correctly. Use circuit breakers for cascading ",
            "failure protection. Ensure counters use saturating arithmetic to prevent ",
            "overflow-based resets.",
        ),
        "A11" => concat!(
            "Scan elicitation schemas for credential harvesting patterns. Detect password ",
            "fields, hidden credential fields in oneOf/anyOf schemas, and secrets in ",
            "additionalProperties. Apply DLP scanning to elicitation responses.",
        ),
        "A12" => concat!(
            "Apply the same security controls to sampling/createMessage requests as to ",
            "regular tool calls. Scan resource URIs for sensitive file access. Deny ",
            "empty or malformed resource URIs.",
        ),
        "A13" => concat!(
            "Implement cross-call DLP tracking: maintain per-session overlap buffers ",
            "(~150 bytes per field) to detect secrets split across multiple tool calls. ",
            "Track field values across calls within a session window.",
        ),
        "A14" => concat!(
            "Validate tool call outputs against the declared outputSchema. Reject extra ",
            "fields when additionalProperties is false. Enforce type constraints, string ",
            "length bounds, and regex patterns on output values.",
        ),
        "A15" => concat!(
            "Validate agent identity on every request. Reject agent IDs containing control ",
            "characters, Unicode format characters, or exceeding length limits. Detect ",
            "homoglyph-based identity spoofing (e.g., Cyrillic 'а' vs Latin 'a'). Enforce ",
            "ABAC policies requiring authenticated agent identity.",
        ),
        "A16" => concat!(
            "Implement circuit breakers with configurable failure thresholds and cooldown ",
            "periods. Protect downstream services from cascading failures. Use saturating ",
            "arithmetic on failure counters to prevent u64 overflow resets.",
        ),
        _ => "No specific remediation guidance available for this attack class.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_classes_have_guidance() {
        for prefix in &[
            "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "A13",
            "A14", "A15", "A16",
        ] {
            let g = guidance(prefix);
            assert!(
                !g.contains("No specific remediation"),
                "Missing guidance for {prefix}"
            );
        }
    }

    #[test]
    fn test_guidance_from_full_id() {
        let g = guidance("A1.1");
        assert!(g.contains("injection scanner"));
    }

    #[test]
    fn test_unknown_class_returns_default() {
        let g = guidance("A99");
        assert!(g.contains("No specific remediation"));
    }
}
