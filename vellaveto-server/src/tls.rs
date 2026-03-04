// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! TLS/mTLS module — re-exports from `vellaveto-tls` shared crate (R233-TLS-8).
//!
//! All production code lives in `vellaveto-tls` to eliminate duplication between
//! `vellaveto-server` and `vellaveto-http-proxy`. This module re-exports the
//! public API so that `crate::tls::*` imports continue to work.

pub use vellaveto_tls::{
    build_tls_acceptor, effective_kex_groups_for_policy, extract_client_cert_info,
    extract_spiffe_ids, ClientCertInfo, SpiffeIdentity, TlsError,
};

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_config::{TlsConfig, TlsMode};

    // Verify re-exported API works through the server's module path.

    #[test]
    fn test_reexport_spiffe_identity_parse() {
        let id = SpiffeIdentity::parse("spiffe://example.org/workload/frontend").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.workload_path, "/workload/frontend");
    }

    #[test]
    fn test_reexport_tls_mode_none_returns_none() {
        let config = TlsConfig {
            mode: TlsMode::None,
            ..Default::default()
        };
        let result = build_tls_acceptor(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_reexport_client_cert_info_default() {
        let info = ClientCertInfo::default();
        assert!(info.spiffe_ids.is_empty());
        assert!(info.common_name.is_none());
        assert!(!info.verified);
    }

    #[test]
    fn test_reexport_extract_spiffe_ids_empty() {
        let empty = extract_spiffe_ids(&[]);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_reexport_extract_client_cert_info_garbage() {
        let info = extract_client_cert_info(b"not a certificate");
        assert!(info.spiffe_ids.is_empty());
        assert!(info.common_name.is_none());
    }

    #[test]
    fn test_reexport_tls_error_display() {
        let err = TlsError::Config("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
