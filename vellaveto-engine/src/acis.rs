// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! ACIS action fingerprinting.
//!
//! Provides [`compute_action_fingerprint`] — the canonical SHA-256 fingerprint
//! used by every enforcement path (policy evaluation, approval binding, audit
//! logging) to identify an action without exposing parameters.

use sha2::{Digest, Sha256};

/// Compute a deterministic SHA-256 action fingerprint.
///
/// Hash input: `tool \0 function \0 path1 \0 path2 … \0 domain1 \0 domain2 …`.
/// Target paths and domains are sorted for determinism.  Parameters are
/// deliberately excluded (may contain secrets).
///
/// Returns a 64-character lowercase hex string.
pub fn compute_action_fingerprint(
    tool: &str,
    function: &str,
    target_paths: &[String],
    target_domains: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tool.as_bytes());
    hasher.update(b"\0");
    hasher.update(function.as_bytes());

    let mut sorted_paths: Vec<&str> = target_paths.iter().map(|s| s.as_str()).collect();
    sorted_paths.sort_unstable();
    for p in &sorted_paths {
        hasher.update(b"\0");
        hasher.update(p.as_bytes());
    }

    let mut sorted_domains: Vec<&str> = target_domains.iter().map(|s| s.as_str()).collect();
    sorted_domains.sort_unstable();
    for d in &sorted_domains {
        hasher.update(b"\0");
        hasher.update(d.as_bytes());
    }

    hex::encode(hasher.finalize())
}

/// Compute a fingerprint directly from an [`Action`](vellaveto_types::Action).
pub fn fingerprint_action(action: &vellaveto_types::Action) -> String {
    compute_action_fingerprint(
        &action.tool,
        &action.function,
        &action.target_paths,
        &action.target_domains,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_deterministic_order_independence() {
        let fp1 = compute_action_fingerprint(
            "read",
            "get",
            &["/b".into(), "/a".into()],
            &["z.com".into(), "a.com".into()],
        );
        let fp2 = compute_action_fingerprint(
            "read",
            "get",
            &["/a".into(), "/b".into()],
            &["a.com".into(), "z.com".into()],
        );
        assert_eq!(fp1, fp2, "fingerprint must be order-independent");
    }

    #[test]
    fn test_fingerprint_differs_on_tool() {
        let fp1 = compute_action_fingerprint("read", "get", &[], &[]);
        let fp2 = compute_action_fingerprint("write", "get", &[], &[]);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_differs_on_function() {
        let fp1 = compute_action_fingerprint("tool", "read", &[], &[]);
        let fp2 = compute_action_fingerprint("tool", "write", &[], &[]);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_is_64_hex_chars() {
        let fp = compute_action_fingerprint("t", "f", &[], &[]);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fingerprint_includes_paths_and_domains() {
        let fp_empty = compute_action_fingerprint("t", "f", &[], &[]);
        let fp_path = compute_action_fingerprint("t", "f", &["/etc/passwd".into()], &[]);
        let fp_domain = compute_action_fingerprint("t", "f", &[], &["evil.com".into()]);
        assert_ne!(fp_empty, fp_path);
        assert_ne!(fp_empty, fp_domain);
        assert_ne!(fp_path, fp_domain);
    }

    #[test]
    fn test_fingerprint_action_helper() {
        let action = vellaveto_types::Action {
            tool: "file_write".into(),
            function: "write".into(),
            parameters: Default::default(),
            target_paths: vec!["/tmp/out.txt".into()],
            target_domains: vec![],
            resolved_ips: vec![],
        };
        let fp = fingerprint_action(&action);
        let expected =
            compute_action_fingerprint("file_write", "write", &["/tmp/out.txt".into()], &[]);
        assert_eq!(fp, expected);
    }
}
