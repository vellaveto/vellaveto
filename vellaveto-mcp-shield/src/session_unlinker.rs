// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Session unlinkability via credential rotation.
//!
//! Each session consumes a fresh blind credential from the vault.
//! No session-to-session linkability is possible because each credential
//! is cryptographically independent (RFC 9474 blind signatures).

use crate::credential_vault::CredentialVault;
use crate::error::ShieldError;
use std::collections::HashMap;
use std::sync::Mutex;
use vellaveto_types::shield::{BlindCredential, SessionCredentialBinding};

/// Maximum concurrent unlinked sessions.
const MAX_UNLINKED_SESSIONS: usize = 1_000;

/// Manages session unlinkability through credential rotation.
///
/// Each new session is bound to a fresh blind credential from the vault.
/// The binding is stored locally and never sent to the provider.
/// When the session ends, the credential is marked consumed.
pub struct SessionUnlinker {
    /// Active session-to-credential bindings (session_id → binding).
    bindings: Mutex<HashMap<String, SessionBinding>>,
    /// Monotonic binding sequence counter.
    sequence: Mutex<u64>,
    /// Maximum concurrent sessions.
    max_sessions: usize,
    /// Credential vault for consuming/marking credentials.
    vault: CredentialVault,
}

/// Internal binding state.
struct SessionBinding {
    credential: BlindCredential,
    vault_index: usize,
    sequence: u64,
}

impl SessionUnlinker {
    /// Create a new session unlinker with an owned credential vault.
    pub fn new(vault: CredentialVault) -> Self {
        Self {
            bindings: Mutex::new(HashMap::new()),
            sequence: Mutex::new(0),
            max_sessions: MAX_UNLINKED_SESSIONS,
            vault,
        }
    }

    /// Create with custom session limit.
    pub fn with_max_sessions(vault: CredentialVault, max_sessions: usize) -> Self {
        Self {
            bindings: Mutex::new(HashMap::new()),
            sequence: Mutex::new(0),
            max_sessions: max_sessions.min(MAX_UNLINKED_SESSIONS),
            vault,
        }
    }

    /// Get a reference to the underlying credential vault.
    pub fn vault(&self) -> &CredentialVault {
        &self.vault
    }

    /// Start a new unlinkable session by consuming a credential from the vault.
    ///
    /// Returns the blind credential to present to the provider.
    /// Fail-closed: if no credentials are available, the session cannot start.
    pub fn start_session(&self, session_id: &str) -> Result<BlindCredential, ShieldError> {
        if vellaveto_types::has_dangerous_chars(session_id) {
            return Err(ShieldError::SessionIsolation(
                "session_id contains dangerous characters".to_string(),
            ));
        }

        let mut bindings = self
            .bindings
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("bindings lock poisoned: {e}")))?;

        if bindings.contains_key(session_id) {
            return Err(ShieldError::SessionIsolation(format!(
                "session '{session_id}' already active"
            )));
        }

        if bindings.len() >= self.max_sessions {
            return Err(ShieldError::SessionIsolation(
                "unlinked session capacity exhausted (fail-closed)".to_string(),
            ));
        }

        // SECURITY (R236-SHIELD-1): Acquire sequence lock BEFORE consuming a
        // credential. If the sequence lock is poisoned, we fail without
        // orphaning a credential in Active state.
        let seq = {
            let mut sequence = self.sequence.lock().map_err(|e| {
                ShieldError::SessionIsolation(format!("sequence lock poisoned: {e}"))
            })?;
            let current = *sequence;
            *sequence = sequence.saturating_add(1);
            current
        };

        // Consume a credential from the vault (after sequence lock acquired)
        let (credential, vault_index) = self.vault.consume_credential()?;

        bindings.insert(
            session_id.to_string(),
            SessionBinding {
                credential: credential.clone(),
                vault_index,
                sequence: seq,
            },
        );

        Ok(credential)
    }

    /// End a session, marking its credential as consumed in the vault.
    pub fn end_session(&self, session_id: &str) -> Result<(), ShieldError> {
        let mut bindings = self
            .bindings
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("bindings lock poisoned: {e}")))?;

        let binding = bindings.remove(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation(format!("unknown session: {session_id}"))
        })?;

        self.vault.mark_consumed(binding.vault_index)
    }

    /// Get the credential for an active session.
    ///
    /// Used when the session needs to re-present its credential
    /// (e.g., after a transport reconnection).
    pub fn get_session_credential(&self, session_id: &str) -> Result<BlindCredential, ShieldError> {
        let bindings = self
            .bindings
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("bindings lock poisoned: {e}")))?;

        let binding = bindings.get(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation(format!("unknown session: {session_id}"))
        })?;

        Ok(binding.credential.clone())
    }

    /// Get the binding metadata for an active session (for local audit).
    pub fn get_binding(&self, session_id: &str) -> Result<SessionCredentialBinding, ShieldError> {
        let bindings = self
            .bindings
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("bindings lock poisoned: {e}")))?;

        let binding = bindings.get(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation(format!("unknown session: {session_id}"))
        })?;

        Ok(SessionCredentialBinding {
            session_id: session_id.to_string(),
            credential_index: binding.vault_index,
            binding_sequence: binding.sequence,
        })
    }

    /// Get the number of active sessions.
    ///
    /// SECURITY (R236-SHIELD-5): Returns 0 on lock poisoning (fail-closed:
    /// prevents end_session from being skipped) with error logging.
    pub fn active_session_count(&self) -> usize {
        match self.bindings.lock() {
            Ok(b) => b.len(),
            Err(e) => {
                tracing::error!("bindings lock poisoned in active_session_count: {e}");
                0
            }
        }
    }

    /// Check whether a session is active.
    ///
    /// SECURITY (R236-SHIELD-5): Returns false on lock poisoning (fail-closed)
    /// with error logging.
    pub fn is_session_active(&self, session_id: &str) -> bool {
        match self.bindings.lock() {
            Ok(b) => b.contains_key(session_id),
            Err(e) => {
                tracing::error!("bindings lock poisoned in is_session_active: {e}");
                false
            }
        }
    }
}

impl std::fmt::Debug for SessionUnlinker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionUnlinker")
            .field("active_sessions", &self.active_session_count())
            .field("max_sessions", &self.max_sessions)
            .finish()
    }
}
