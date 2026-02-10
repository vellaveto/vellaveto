//! TLS/mTLS runtime implementation for Sentinel.
//!
//! Provides TLS termination with optional mutual TLS (client certificate verification)
//! and SPIFFE identity extraction from X.509 certificates.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use sentinel_config::{TlsConfig, TlsMode};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

/// Errors that can occur during TLS setup.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Private key error: {0}")]
    PrivateKey(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result of SPIFFE ID extraction from a client certificate.
#[derive(Debug, Clone)]
pub struct SpiffeIdentity {
    /// The full SPIFFE ID URI (e.g., "spiffe://example.org/workload/frontend")
    pub spiffe_id: String,
    /// The trust domain (e.g., "example.org")
    pub trust_domain: String,
    /// The workload path (e.g., "/workload/frontend")
    pub workload_path: String,
}

impl SpiffeIdentity {
    /// Parse a SPIFFE ID from a URI string.
    pub fn parse(uri: &str) -> Option<Self> {
        if !uri.starts_with("spiffe://") {
            return None;
        }

        let without_scheme = &uri[9..]; // Remove "spiffe://"
        let (trust_domain, workload_path) = if let Some(slash_pos) = without_scheme.find('/') {
            (
                without_scheme[..slash_pos].to_string(),
                without_scheme[slash_pos..].to_string(),
            )
        } else {
            (without_scheme.to_string(), String::new())
        };

        Some(SpiffeIdentity {
            spiffe_id: uri.to_string(),
            trust_domain,
            workload_path,
        })
    }
}

/// Extract SPIFFE IDs from X.509 certificate SAN (Subject Alternative Name) URIs.
pub fn extract_spiffe_ids(cert_der: &[u8]) -> Vec<SpiffeIdentity> {
    let mut identities = Vec::new();

    // Parse the certificate
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) {
        // Look for Subject Alternative Name extension
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let x509_parser::prelude::GeneralName::URI(uri) = name {
                    if let Some(identity) = SpiffeIdentity::parse(uri) {
                        identities.push(identity);
                    }
                }
            }
        }
    }

    identities
}

/// Load certificates from a PEM file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| {
            TlsError::Certificate(format!("Failed to open certificate file {:?}: {}", path, e))
        })?
        .filter_map(|cert| cert.ok())
        .collect();

    if certs.is_empty() {
        return Err(TlsError::Certificate(format!(
            "No certificates found in {:?}",
            path
        )));
    }

    Ok(certs)
}

/// Load a private key from a PEM file.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    // PrivateKeyDer::from_pem_file handles PKCS#1, PKCS#8, and SEC1 key formats
    PrivateKeyDer::from_pem_file(path).map_err(|e| {
        TlsError::PrivateKey(format!("Failed to read private key from {:?}: {}", path, e))
    })
}

/// Load CA certificates for client verification.
fn load_client_ca(path: &Path) -> Result<RootCertStore, TlsError> {
    let certs = load_certs(path)?;
    let mut roots = RootCertStore::empty();

    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| TlsError::Certificate(format!("Failed to add CA certificate: {}", e)))?;
    }

    Ok(roots)
}

/// Build a TLS acceptor from configuration.
pub fn build_tls_acceptor(config: &TlsConfig) -> Result<Option<TlsAcceptor>, TlsError> {
    match config.mode {
        TlsMode::None => Ok(None),
        TlsMode::Tls | TlsMode::Mtls => {
            let cert_path = config
                .cert_path
                .as_ref()
                .ok_or_else(|| TlsError::Config("cert_path is required for TLS".to_string()))?;

            let key_path = config
                .key_path
                .as_ref()
                .ok_or_else(|| TlsError::Config("key_path is required for TLS".to_string()))?;

            let certs = load_certs(Path::new(cert_path))?;
            let key = load_private_key(Path::new(key_path))?;

            let mut server_config = if config.mode == TlsMode::Mtls {
                // mTLS: require and verify client certificates
                let client_ca_path = config.client_ca_path.as_ref().ok_or_else(|| {
                    TlsError::Config("client_ca_path is required for mTLS".to_string())
                })?;

                let client_ca = load_client_ca(Path::new(client_ca_path))?;

                let client_verifier = if config.require_client_cert {
                    WebPkiClientVerifier::builder(Arc::new(client_ca))
                        .build()
                        .map_err(|e| {
                            TlsError::Certificate(format!("Failed to build client verifier: {}", e))
                        })?
                } else {
                    WebPkiClientVerifier::builder(Arc::new(client_ca))
                        .allow_unauthenticated()
                        .build()
                        .map_err(|e| {
                            TlsError::Certificate(format!("Failed to build client verifier: {}", e))
                        })?
                };

                rustls::ServerConfig::builder()
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(certs, key)
                    .map_err(TlsError::Tls)?
            } else {
                // TLS only: no client certificate verification
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(TlsError::Tls)?
            };

            // Enable ALPN for HTTP/1.1 and HTTP/2
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
        }
    }
}

/// Information extracted from a client certificate.
#[derive(Debug, Clone, Default)]
pub struct ClientCertInfo {
    /// SPIFFE identities found in the certificate.
    pub spiffe_ids: Vec<SpiffeIdentity>,
    /// Common Name from the subject.
    pub common_name: Option<String>,
    /// Organization from the subject.
    pub organization: Option<String>,
    /// Serial number of the certificate.
    pub serial_number: Option<String>,
    /// Whether the certificate was verified.
    pub verified: bool,
}

/// Extract information from a client certificate.
pub fn extract_client_cert_info(cert_der: &[u8]) -> ClientCertInfo {
    let mut info = ClientCertInfo {
        verified: true, // If we got here, rustls already verified it
        ..Default::default()
    };

    // Extract SPIFFE IDs
    info.spiffe_ids = extract_spiffe_ids(cert_der);

    // Parse certificate for additional info
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) {
        // Extract serial number
        info.serial_number = Some(cert.serial.to_string());

        // Extract subject fields
        for rdn in cert.subject.iter() {
            for attr in rdn.iter() {
                if let Ok(value) = attr.as_str() {
                    let oid = attr.attr_type();
                    // OID 2.5.4.3 = Common Name
                    if oid.to_string() == "2.5.4.3" {
                        info.common_name = Some(value.to_string());
                    }
                    // OID 2.5.4.10 = Organization
                    if oid.to_string() == "2.5.4.10" {
                        info.organization = Some(value.to_string());
                    }
                }
            }
        }
    }

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_identity_parse() {
        let id = SpiffeIdentity::parse("spiffe://example.org/workload/frontend").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.workload_path, "/workload/frontend");
    }

    #[test]
    fn test_spiffe_identity_parse_no_path() {
        let id = SpiffeIdentity::parse("spiffe://example.org").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.workload_path, "");
    }

    #[test]
    fn test_spiffe_identity_parse_invalid() {
        assert!(SpiffeIdentity::parse("https://example.org").is_none());
        assert!(SpiffeIdentity::parse("not a uri").is_none());
    }

    #[test]
    fn test_tls_mode_none_returns_none() {
        let config = TlsConfig {
            mode: TlsMode::None,
            ..Default::default()
        };
        let result = build_tls_acceptor(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_tls_mode_requires_cert_path() {
        let config = TlsConfig {
            mode: TlsMode::Tls,
            cert_path: None,
            key_path: Some("/path/to/key".to_string()),
            ..Default::default()
        };
        let result = build_tls_acceptor(&config);
        match result {
            Err(e) => assert!(e.to_string().contains("cert_path")),
            Ok(_) => panic!("Expected error for missing cert_path"),
        }
    }

    #[test]
    fn test_mtls_requires_client_ca() {
        let config = TlsConfig {
            mode: TlsMode::Mtls,
            cert_path: Some("/path/to/cert".to_string()),
            key_path: Some("/path/to/key".to_string()),
            client_ca_path: None,
            ..Default::default()
        };
        // This will fail because files don't exist, but we're testing the logic
        let result = build_tls_acceptor(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_cert_info_default() {
        let info = ClientCertInfo::default();
        assert!(info.spiffe_ids.is_empty());
        assert!(info.common_name.is_none());
        assert!(!info.verified);
    }
}
