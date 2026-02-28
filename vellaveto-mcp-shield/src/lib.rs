//! Consumer Shield: bidirectional PII sanitization, session isolation,
//! and encrypted local audit for consumer AI interactions.

pub mod crypto;
pub mod error;
pub mod local_audit;
pub mod sanitizer;
pub mod session_isolator;

#[cfg(test)]
mod tests;

pub use crypto::EncryptedAuditStore;
pub use error::ShieldError;
pub use local_audit::LocalAuditManager;
pub use sanitizer::QuerySanitizer;
pub use session_isolator::SessionIsolator;
