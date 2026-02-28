//! Consumer Shield: bidirectional PII sanitization, session isolation,
//! encrypted local audit, and credential-based session unlinkability
//! for consumer AI interactions.

pub mod credential_vault;
pub mod crypto;
pub mod error;
pub mod local_audit;
pub mod sanitizer;
pub mod session_isolator;
pub mod session_unlinker;

#[cfg(test)]
mod tests;

pub use credential_vault::CredentialVault;
pub use crypto::EncryptedAuditStore;
pub use error::ShieldError;
pub use local_audit::LocalAuditManager;
pub use sanitizer::QuerySanitizer;
pub use session_isolator::SessionIsolator;
pub use session_unlinker::SessionUnlinker;
