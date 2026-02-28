// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Audit query extension — a built-in read-only extension.
//!
//! Handles `x-vellaveto-audit/stats` to return basic audit system status.
//! Serves as the reference implementation for the extension framework.

use crate::extension_registry::ExtensionHandler;
use serde_json::{json, Value};
use vellaveto_types::{ExtensionDescriptor, ExtensionError};

/// Extension ID for the audit query extension.
pub const EXTENSION_ID: &str = "x-vellaveto-audit";

/// The audit query method.
pub const METHOD_STATS: &str = "x-vellaveto-audit/stats";

/// Built-in audit query extension.
///
/// Provides read-only access to audit system status via the
/// `x-vellaveto-audit/stats` method.
pub struct AuditQueryExtension {
    descriptor: ExtensionDescriptor,
}

impl AuditQueryExtension {
    /// Create a new audit query extension instance.
    pub fn new() -> Self {
        Self {
            descriptor: ExtensionDescriptor {
                id: EXTENSION_ID.to_string(),
                name: "Vellaveto Audit Query".to_string(),
                version: "1.0.0".to_string(),
                capabilities: vec!["read".to_string()],
                methods: vec![METHOD_STATS.to_string()],
                signature: None,
                public_key: None,
            },
        }
    }
}

impl Default for AuditQueryExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionHandler for AuditQueryExtension {
    fn on_load(&self, _descriptor: &ExtensionDescriptor) -> Result<(), ExtensionError> {
        Ok(())
    }

    fn on_unload(&self, _extension_id: &str) {
        // No cleanup needed
    }

    fn handle_method(&self, method: &str, _params: &Value) -> Result<Value, ExtensionError> {
        match method {
            METHOD_STATS => Ok(json!({
                "status": "ok",
                "extension": EXTENSION_ID,
                "version": "1.0.0",
            })),
            _ => Err(ExtensionError::MethodNotFound(format!(
                "Unknown method: {}",
                method
            ))),
        }
    }

    fn descriptor(&self) -> &ExtensionDescriptor {
        &self.descriptor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_query_stats() {
        let ext = AuditQueryExtension::new();
        let result = ext.handle_method(METHOD_STATS, &json!({})).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["extension"], EXTENSION_ID);
        assert_eq!(result["version"], "1.0.0");
    }

    #[test]
    fn test_audit_query_unknown_method() {
        let ext = AuditQueryExtension::new();
        let result = ext.handle_method("x-vellaveto-audit/unknown", &json!({}));
        assert!(matches!(result, Err(ExtensionError::MethodNotFound(_))));
    }

    #[test]
    fn test_audit_query_descriptor() {
        let ext = AuditQueryExtension::new();
        let desc = ext.descriptor();
        assert_eq!(desc.id, EXTENSION_ID);
        assert_eq!(desc.methods, vec![METHOD_STATS]);
        assert!(desc.validate().is_ok());
    }

    #[test]
    fn test_audit_query_on_load() {
        let ext = AuditQueryExtension::new();
        assert!(ext.on_load(&ext.descriptor).is_ok());
    }
}
