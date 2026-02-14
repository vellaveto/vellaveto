//! Version Pinning and Drift Detection for ETDI.
//!
//! Allows administrators to lock tools to specific versions or version constraints,
//! preventing unauthorized updates. When a tool's version or definition hash drifts
//! from the pinned state, alerts are generated.
//!
//! # Pinning Modes
//!
//! - **Exact version**: Pin to a specific version string (e.g., "1.2.3")
//! - **Constraint**: Pin to a semver range (e.g., "^1.2.0", ">=1.0,<2.0")
//! - **Hash**: Always verify the definition hash matches
//!
//! # Enforcement Modes
//!
//! - **warn**: Log warnings but allow the tool
//! - **block**: Block tools that don't match their pin

use crate::etdi::{EtdiError, EtdiStore};
use chrono::Utc;
use vellaveto_types::{ToolVersionPin, VersionDriftAlert};
use serde_json::Value;
use std::sync::Arc;

/// Result of version pin check.
#[derive(Debug, Clone, PartialEq)]
pub enum PinCheckResult {
    /// No pin exists for this tool.
    NoPinExists,
    /// Tool matches the pin.
    Matches,
    /// Version mismatch detected.
    VersionDrift(VersionDriftAlert),
    /// Hash mismatch detected.
    HashDrift(VersionDriftAlert),
}

impl PinCheckResult {
    /// Returns true if the check passed (no drift).
    pub fn is_ok(&self) -> bool {
        matches!(self, PinCheckResult::NoPinExists | PinCheckResult::Matches)
    }

    /// Returns the drift alert if any.
    pub fn drift_alert(&self) -> Option<&VersionDriftAlert> {
        match self {
            PinCheckResult::VersionDrift(a) | PinCheckResult::HashDrift(a) => Some(a),
            _ => None,
        }
    }
}

/// Manages version pins for tools.
pub struct VersionPinManager {
    store: Arc<EtdiStore>,
    /// Whether to block on drift (true) or just warn (false).
    blocking: bool,
}

impl VersionPinManager {
    /// Create a new version pin manager.
    pub fn new(store: Arc<EtdiStore>, blocking: bool) -> Self {
        Self { store, blocking }
    }

    /// Pin a tool to a specific version.
    pub async fn pin_version(
        &self,
        tool_name: &str,
        version: &str,
        definition_hash: &str,
        pinned_by: &str,
    ) -> Result<ToolVersionPin, EtdiError> {
        let pin = ToolVersionPin {
            tool_name: tool_name.to_string(),
            pinned_version: Some(version.to_string()),
            version_constraint: None,
            definition_hash: definition_hash.to_string(),
            pinned_at: Utc::now().to_rfc3339(),
            pinned_by: pinned_by.to_string(),
        };

        self.store.save_pin(pin.clone()).await?;
        Ok(pin)
    }

    /// Pin a tool to a version constraint.
    pub async fn pin_constraint(
        &self,
        tool_name: &str,
        constraint: &str,
        definition_hash: &str,
        pinned_by: &str,
    ) -> Result<ToolVersionPin, EtdiError> {
        // Validate constraint syntax
        semver::VersionReq::parse(constraint).map_err(|e| {
            EtdiError::InvalidSignature(format!("Invalid semver constraint: {}", e))
        })?;

        let pin = ToolVersionPin {
            tool_name: tool_name.to_string(),
            pinned_version: None,
            version_constraint: Some(constraint.to_string()),
            definition_hash: definition_hash.to_string(),
            pinned_at: Utc::now().to_rfc3339(),
            pinned_by: pinned_by.to_string(),
        };

        self.store.save_pin(pin.clone()).await?;
        Ok(pin)
    }

    /// Pin a tool to its current hash only (no version constraint).
    pub async fn pin_hash(
        &self,
        tool_name: &str,
        definition_hash: &str,
        pinned_by: &str,
    ) -> Result<ToolVersionPin, EtdiError> {
        let pin = ToolVersionPin {
            tool_name: tool_name.to_string(),
            pinned_version: None,
            version_constraint: None,
            definition_hash: definition_hash.to_string(),
            pinned_at: Utc::now().to_rfc3339(),
            pinned_by: pinned_by.to_string(),
        };

        self.store.save_pin(pin.clone()).await?;
        Ok(pin)
    }

    /// Remove a pin for a tool.
    pub async fn unpin(&self, tool_name: &str) -> Result<bool, EtdiError> {
        self.store.remove_pin(tool_name).await
    }

    /// Check if a tool matches its pin.
    ///
    /// # Arguments
    ///
    /// * `tool_name` - Name of the tool
    /// * `version` - Current version of the tool (from metadata, may be None)
    /// * `schema` - Current tool schema
    pub async fn check_pin(
        &self,
        tool_name: &str,
        version: Option<&str>,
        schema: &Value,
    ) -> PinCheckResult {
        let Some(pin) = self.store.get_pin(tool_name).await else {
            return PinCheckResult::NoPinExists;
        };

        let current_hash = crate::etdi::signature::compute_tool_hash(tool_name, schema);
        let now = Utc::now().to_rfc3339();

        // First check hash (always checked)
        if current_hash != pin.definition_hash {
            return PinCheckResult::HashDrift(VersionDriftAlert::hash_mismatch(
                tool_name,
                &pin.definition_hash,
                &current_hash,
                self.blocking,
                &now,
            ));
        }

        // Check exact version if pinned
        if let Some(ref pinned_version) = pin.pinned_version {
            if let Some(current) = version {
                if current != pinned_version {
                    return PinCheckResult::VersionDrift(VersionDriftAlert::version_mismatch(
                        tool_name,
                        pinned_version,
                        current,
                        self.blocking,
                        &now,
                    ));
                }
            }
        }

        // Check version constraint if set
        if let Some(ref constraint_str) = pin.version_constraint {
            if let Some(current) = version {
                if let Ok(constraint) = semver::VersionReq::parse(constraint_str) {
                    if let Ok(ver) = semver::Version::parse(current) {
                        if !constraint.matches(&ver) {
                            return PinCheckResult::VersionDrift(VersionDriftAlert {
                                tool: tool_name.to_string(),
                                expected_version: constraint_str.clone(),
                                actual_version: current.to_string(),
                                drift_type: "constraint_violation".to_string(),
                                blocking: self.blocking,
                                detected_at: now,
                            });
                        }
                    }
                }
            }
        }

        PinCheckResult::Matches
    }

    /// Get the pin for a tool.
    pub async fn get_pin(&self, tool_name: &str) -> Option<ToolVersionPin> {
        self.store.get_pin(tool_name).await
    }

    /// List all pins.
    pub async fn list_pins(&self) -> Vec<ToolVersionPin> {
        self.store.list_pins().await
    }

    /// Check if blocking mode is enabled.
    pub fn is_blocking(&self) -> bool {
        self.blocking
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    async fn test_setup() -> (TempDir, Arc<EtdiStore>) {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(dir.path()));
        (dir, store)
    }

    #[tokio::test]
    async fn test_pin_version() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let hash = crate::etdi::signature::compute_tool_hash("test_tool", &json!({}));
        let pin = manager
            .pin_version("test_tool", "1.0.0", &hash, "admin")
            .await
            .unwrap();

        assert_eq!(pin.pinned_version, Some("1.0.0".to_string()));
        assert!(pin.version_constraint.is_none());
    }

    #[tokio::test]
    async fn test_pin_constraint() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let hash = crate::etdi::signature::compute_tool_hash("test_tool", &json!({}));
        let pin = manager
            .pin_constraint("test_tool", "^1.2.0", &hash, "admin")
            .await
            .unwrap();

        assert!(pin.pinned_version.is_none());
        assert_eq!(pin.version_constraint, Some("^1.2.0".to_string()));
    }

    #[tokio::test]
    async fn test_pin_constraint_invalid() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let result = manager
            .pin_constraint("test_tool", "not-a-valid-constraint", "hash", "admin")
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_check_pin_no_pin() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let result = manager.check_pin("unknown_tool", None, &json!({})).await;
        assert_eq!(result, PinCheckResult::NoPinExists);
    }

    #[tokio::test]
    async fn test_check_pin_matches() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let schema = json!({"type": "object"});
        let hash = crate::etdi::signature::compute_tool_hash("test_tool", &schema);
        manager
            .pin_version("test_tool", "1.0.0", &hash, "admin")
            .await
            .unwrap();

        let result = manager.check_pin("test_tool", Some("1.0.0"), &schema).await;
        assert_eq!(result, PinCheckResult::Matches);
    }

    #[tokio::test]
    async fn test_check_pin_hash_drift() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, true);

        let schema = json!({"type": "object"});
        let hash = crate::etdi::signature::compute_tool_hash("test_tool", &schema);
        manager
            .pin_version("test_tool", "1.0.0", &hash, "admin")
            .await
            .unwrap();

        let different_schema = json!({"type": "string"});
        let result = manager
            .check_pin("test_tool", Some("1.0.0"), &different_schema)
            .await;

        match result {
            PinCheckResult::HashDrift(alert) => {
                assert_eq!(alert.drift_type, "hash_mismatch");
                assert!(alert.blocking);
            }
            _ => panic!("Expected HashDrift, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_check_pin_version_drift() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let schema = json!({"type": "object"});
        let hash = crate::etdi::signature::compute_tool_hash("test_tool", &schema);
        manager
            .pin_version("test_tool", "1.0.0", &hash, "admin")
            .await
            .unwrap();

        let result = manager.check_pin("test_tool", Some("2.0.0"), &schema).await;

        match result {
            PinCheckResult::VersionDrift(alert) => {
                assert_eq!(alert.expected_version, "1.0.0");
                assert_eq!(alert.actual_version, "2.0.0");
                assert!(!alert.blocking);
            }
            _ => panic!("Expected VersionDrift, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_check_pin_constraint_matches() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let schema = json!({"type": "object"});
        let hash = crate::etdi::signature::compute_tool_hash("test_tool", &schema);
        manager
            .pin_constraint("test_tool", "^1.0.0", &hash, "admin")
            .await
            .unwrap();

        // 1.2.3 matches ^1.0.0
        let result = manager.check_pin("test_tool", Some("1.2.3"), &schema).await;
        assert_eq!(result, PinCheckResult::Matches);
    }

    #[tokio::test]
    async fn test_check_pin_constraint_violated() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let schema = json!({"type": "object"});
        let hash = crate::etdi::signature::compute_tool_hash("test_tool", &schema);
        manager
            .pin_constraint("test_tool", "^1.0.0", &hash, "admin")
            .await
            .unwrap();

        // 2.0.0 does NOT match ^1.0.0
        let result = manager.check_pin("test_tool", Some("2.0.0"), &schema).await;

        match result {
            PinCheckResult::VersionDrift(alert) => {
                assert_eq!(alert.drift_type, "constraint_violation");
            }
            _ => panic!("Expected VersionDrift, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_unpin() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        let hash = "abc123".to_string();
        manager
            .pin_version("test_tool", "1.0.0", &hash, "admin")
            .await
            .unwrap();

        assert!(manager.get_pin("test_tool").await.is_some());

        let removed = manager.unpin("test_tool").await.unwrap();
        assert!(removed);
        assert!(manager.get_pin("test_tool").await.is_none());
    }

    #[tokio::test]
    async fn test_list_pins() {
        let (_dir, store) = test_setup().await;
        let manager = VersionPinManager::new(store, false);

        manager
            .pin_version("tool1", "1.0.0", "hash1", "admin")
            .await
            .unwrap();
        manager
            .pin_version("tool2", "2.0.0", "hash2", "admin")
            .await
            .unwrap();

        let pins = manager.list_pins().await;
        assert_eq!(pins.len(), 2);
    }

    #[tokio::test]
    async fn test_pin_check_result_is_ok() {
        assert!(PinCheckResult::NoPinExists.is_ok());
        assert!(PinCheckResult::Matches.is_ok());

        let alert = VersionDriftAlert::version_mismatch("t", "1", "2", false, "now");
        assert!(!PinCheckResult::VersionDrift(alert).is_ok());
    }
}
