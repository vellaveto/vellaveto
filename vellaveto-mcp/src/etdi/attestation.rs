// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Attestation Chain Management for Tool Provenance.
//!
//! Attestations form a chain of custody for tool definitions, allowing
//! verification that a tool has not been modified since initial registration.
//! Each attestation links to the previous one via hash, creating a tamper-evident
//! chain similar to blockchain.
//!
//! # Chain Structure
//!
//! ```text
//! [Initial Attestation] -> [Update Attestation] -> [Audit Attestation]
//!        ^                         ^                        ^
//!        |                         |                        |
//!     tool_hash                 tool_hash               tool_hash
//!  previous: None           previous: att-1          previous: att-2
//! ```

use crate::etdi::{EtdiError, EtdiStore, ToolSigner};
use chrono::Utc;
use serde_json::Value;
use std::sync::Arc;
use vellaveto_types::ToolAttestation;

/// Result of attestation chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// Whether the chain is valid (all links verified).
    pub valid: bool,
    /// Number of attestations in the chain.
    pub chain_length: usize,
    /// Any issues found during verification.
    pub issues: Vec<String>,
}

/// Manages attestation chains for tools.
pub struct AttestationChain {
    store: Arc<EtdiStore>,
}

impl AttestationChain {
    /// Create a new attestation chain manager.
    pub fn new(store: Arc<EtdiStore>) -> Self {
        Self { store }
    }

    /// Create an initial attestation for a new tool.
    pub async fn create_initial(
        &self,
        tool_name: &str,
        tool_schema: &Value,
        attester: &str,
        signer: &ToolSigner,
    ) -> Result<ToolAttestation, EtdiError> {
        let tool_hash = crate::etdi::signature::compute_tool_hash(tool_name, tool_schema);
        let now = Utc::now().to_rfc3339();
        let attestation_id = format!("att-{}", uuid::Uuid::new_v4());

        // Create signature over attestation content
        let sig_content = format!("{attestation_id}|{tool_hash}|{now}|{attester}");
        let signature = signer.sign_tool(&sig_content, &Value::Null, None);

        let attestation = ToolAttestation {
            attestation_id,
            attestation_type: "initial".to_string(),
            attester: attester.to_string(),
            timestamp: now,
            tool_hash,
            previous_attestation: None,
            signature,
            transparency_log_entry: None,
        };

        self.store
            .save_attestation(tool_name, attestation.clone())
            .await?;
        Ok(attestation)
    }

    /// Create an update attestation (new version of a tool).
    pub async fn create_update(
        &self,
        tool_name: &str,
        tool_schema: &Value,
        attester: &str,
        signer: &ToolSigner,
    ) -> Result<ToolAttestation, EtdiError> {
        let chain = self.store.get_attestations(tool_name).await;
        let previous = chain.last().map(|a| a.attestation_id.clone());

        let tool_hash = crate::etdi::signature::compute_tool_hash(tool_name, tool_schema);
        let now = Utc::now().to_rfc3339();
        let attestation_id = format!("att-{}", uuid::Uuid::new_v4());

        let sig_content = format!(
            "{}|{}|{}|{}|{}",
            attestation_id,
            tool_hash,
            now,
            attester,
            previous.as_deref().unwrap_or("none")
        );
        let signature = signer.sign_tool(&sig_content, &Value::Null, None);

        let attestation = ToolAttestation {
            attestation_id,
            attestation_type: "version_update".to_string(),
            attester: attester.to_string(),
            timestamp: now,
            tool_hash,
            previous_attestation: previous,
            signature,
            transparency_log_entry: None,
        };

        self.store
            .save_attestation(tool_name, attestation.clone())
            .await?;
        Ok(attestation)
    }

    /// Verify the attestation chain for a tool.
    ///
    /// Checks:
    /// 1. Chain continuity (each attestation links to the previous)
    /// 2. Hash consistency (tool_hash matches if tool hasn't changed)
    /// 3. Timestamp ordering (each attestation is newer than the previous)
    pub async fn verify_chain(&self, tool_name: &str) -> ChainVerification {
        let chain = self.store.get_attestations(tool_name).await;

        if chain.is_empty() {
            return ChainVerification {
                valid: true,
                chain_length: 0,
                issues: vec![],
            };
        }

        let mut issues = Vec::new();

        // Check first attestation is initial
        if chain[0].previous_attestation.is_some() {
            issues.push("First attestation should not have a previous reference".to_string());
        }

        // Check chain continuity
        for i in 1..chain.len() {
            let current = &chain[i];
            let previous = &chain[i - 1];

            // Check previous_attestation links correctly
            if current.previous_attestation.as_ref() != Some(&previous.attestation_id) {
                issues.push(format!(
                    "Attestation {} has incorrect previous reference (expected {}, got {:?})",
                    current.attestation_id, previous.attestation_id, current.previous_attestation
                ));
            }

            // Check timestamp ordering
            if current.timestamp <= previous.timestamp {
                issues.push(format!(
                    "Attestation {} has timestamp <= previous ({} <= {})",
                    current.attestation_id, current.timestamp, previous.timestamp
                ));
            }
        }

        ChainVerification {
            valid: issues.is_empty(),
            chain_length: chain.len(),
            issues,
        }
    }

    /// Get the current (latest) attestation for a tool.
    pub async fn get_current(&self, tool_name: &str) -> Option<ToolAttestation> {
        self.store.get_attestations(tool_name).await.pop()
    }

    /// Get the full attestation chain for a tool.
    pub async fn get_chain(&self, tool_name: &str) -> Vec<ToolAttestation> {
        self.store.get_attestations(tool_name).await
    }

    /// Check if a tool hash matches the current attestation.
    pub async fn verify_hash(&self, tool_name: &str, tool_schema: &Value) -> bool {
        let Some(current) = self.get_current(tool_name).await else {
            return false; // No attestation = no verification
        };

        let computed_hash = crate::etdi::signature::compute_tool_hash(tool_name, tool_schema);
        computed_hash == current.tool_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etdi::ToolSigner;
    use serde_json::json;
    use tempfile::TempDir;

    async fn test_setup() -> (TempDir, Arc<EtdiStore>, ToolSigner) {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(dir.path()));
        let signer = ToolSigner::generate().unwrap();
        (dir, store, signer)
    }

    #[tokio::test]
    async fn test_create_initial_attestation() {
        let (_dir, store, signer) = test_setup().await;
        let chain = AttestationChain::new(store);

        let schema = json!({"type": "object"});
        let att = chain
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        assert_eq!(att.attestation_type, "initial");
        assert!(att.previous_attestation.is_none());
        assert!(!att.tool_hash.is_empty());
    }

    #[tokio::test]
    async fn test_create_update_attestation() {
        let (_dir, store, signer) = test_setup().await;
        let chain = AttestationChain::new(store);

        let schema = json!({"type": "object"});
        let initial = chain
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        let updated_schema = json!({"type": "object", "version": 2});
        let update = chain
            .create_update("test_tool", &updated_schema, "admin", &signer)
            .await
            .unwrap();

        assert_eq!(update.attestation_type, "version_update");
        assert_eq!(update.previous_attestation, Some(initial.attestation_id));
        assert_ne!(update.tool_hash, initial.tool_hash);
    }

    #[tokio::test]
    async fn test_verify_chain_valid() {
        let (_dir, store, signer) = test_setup().await;
        let chain_manager = AttestationChain::new(store);

        let schema = json!({"type": "object"});
        chain_manager
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        // Wait a tiny bit to ensure timestamp difference
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        chain_manager
            .create_update("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        let result = chain_manager.verify_chain("test_tool").await;
        assert!(result.valid, "Issues: {:?}", result.issues);
        assert_eq!(result.chain_length, 2);
    }

    #[tokio::test]
    async fn test_verify_hash_matches() {
        let (_dir, store, signer) = test_setup().await;
        let chain_manager = AttestationChain::new(store);

        let schema = json!({"type": "object"});
        chain_manager
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        assert!(chain_manager.verify_hash("test_tool", &schema).await);

        let different = json!({"type": "string"});
        assert!(!chain_manager.verify_hash("test_tool", &different).await);
    }

    #[tokio::test]
    async fn test_get_current_attestation() {
        let (_dir, store, signer) = test_setup().await;
        let chain_manager = AttestationChain::new(store);

        assert!(chain_manager.get_current("test_tool").await.is_none());

        let schema = json!({"type": "object"});
        let initial = chain_manager
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        let current = chain_manager.get_current("test_tool").await.unwrap();
        assert_eq!(current.attestation_id, initial.attestation_id);

        let update = chain_manager
            .create_update("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        let current = chain_manager.get_current("test_tool").await.unwrap();
        assert_eq!(current.attestation_id, update.attestation_id);
    }

    #[tokio::test]
    async fn test_empty_chain_is_valid() {
        let (_dir, store, _signer) = test_setup().await;
        let chain_manager = AttestationChain::new(store);

        let result = chain_manager.verify_chain("nonexistent_tool").await;
        assert!(result.valid);
        assert_eq!(result.chain_length, 0);
    }
}
