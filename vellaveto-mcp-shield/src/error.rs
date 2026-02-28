//! Shield error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("sanitization failed: {0}")]
    Sanitization(String),

    #[error("desanitization failed: {0}")]
    Desanitization(String),

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("session isolation error: {0}")]
    SessionIsolation(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("credential vault error: {0}")]
    CredentialVault(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
