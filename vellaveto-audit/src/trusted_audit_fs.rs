// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Explicit trusted boundary for audit filesystem operations.
//!
//! Verus proves the arithmetic and structural audit kernels around append,
//! rotation, and Merkle verification, but not the operating-system semantics
//! of file append, flush/sync, metadata, truncate, or rename. This module
//! centralizes those concrete filesystem calls behind a narrow surface.

use crate::types::AuditError;
use std::path::{Component, Path};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

/// Validate that a path does not contain traversal components (`..`).
///
/// This is the single trust boundary for all filesystem operations in this
/// module.  CodeQL flags paths derived from configuration as "user-provided";
/// this check satisfies the sanitisation requirement.
fn validate_safe_path(path: &Path) -> Result<(), AuditError> {
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path traversal (..) rejected in audit filesystem operation",
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Durability {
    FlushOnly,
    SyncData,
}

impl Durability {
    fn requires_sync_data(self) -> bool {
        matches!(self, Self::SyncData)
    }
}

async fn open_append_create_parent(path: &Path) -> Result<tokio::fs::File, AuditError> {
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(file) => Ok(file),
        Err(_) => {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .map_err(AuditError::from)
        }
    }
}

fn open_append_create_parent_sync(path: &Path) -> Result<std::fs::File, AuditError> {
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(_) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(AuditError::from)
        }
    }
}

#[cfg(unix)]
async fn set_owner_only_permissions_best_effort(path: &Path, label: &str) {
    use std::os::unix::fs::PermissionsExt;

    if let Err(e) = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "Failed to set {} permissions to 0o600",
            label
        );
    }
}

#[cfg(not(unix))]
async fn set_owner_only_permissions_best_effort(_path: &Path, _label: &str) {}

#[cfg(unix)]
fn set_owner_only_permissions_best_effort_sync(path: &Path, label: &str) {
    use std::os::unix::fs::PermissionsExt;

    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "Failed to set {} permissions to 0o600",
            label
        );
    }
}

#[cfg(not(unix))]
fn set_owner_only_permissions_best_effort_sync(_path: &Path, _label: &str) {}

pub(crate) async fn append_bytes(
    path: &Path,
    bytes: &[u8],
    durability: Durability,
    permissions_label: &str,
) -> Result<(), AuditError> {
    validate_safe_path(path)?;
    let mut file = open_append_create_parent(path).await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    if durability.requires_sync_data() {
        file.sync_data().await?;
    }
    set_owner_only_permissions_best_effort(path, permissions_label).await;
    Ok(())
}

pub(crate) fn append_bytes_sync(
    path: &Path,
    bytes: &[u8],
    durability: Durability,
    permissions_label: &str,
) -> Result<(), AuditError> {
    use std::io::Write;

    validate_safe_path(path)?;
    let mut file = open_append_create_parent_sync(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    if durability.requires_sync_data() {
        file.sync_data()?;
    }
    set_owner_only_permissions_best_effort_sync(path, permissions_label);
    Ok(())
}

pub(crate) async fn metadata_required(path: &Path) -> Result<std::fs::Metadata, AuditError> {
    validate_safe_path(path)?;
    tokio::fs::metadata(path).await.map_err(AuditError::from)
}

pub(crate) async fn metadata_if_exists(
    path: &Path,
) -> Result<Option<std::fs::Metadata>, AuditError> {
    validate_safe_path(path)?;
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(Some(metadata)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AuditError::Io(e)),
    }
}

pub(crate) fn metadata_required_sync(path: &Path) -> Result<std::fs::Metadata, AuditError> {
    validate_safe_path(path)?;
    std::fs::metadata(path).map_err(AuditError::from)
}

pub(crate) fn metadata_if_exists_sync(
    path: &Path,
) -> Result<Option<std::fs::Metadata>, AuditError> {
    validate_safe_path(path)?;
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AuditError::Io(e)),
    }
}

pub(crate) async fn read_to_string_required(path: &Path) -> Result<String, AuditError> {
    validate_safe_path(path)?;
    tokio::fs::read_to_string(path)
        .await
        .map_err(AuditError::from)
}

pub(crate) async fn read_to_string_if_exists(path: &Path) -> Result<Option<String>, AuditError> {
    validate_safe_path(path)?;
    match tokio::fs::read_to_string(path).await {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AuditError::Io(e)),
    }
}

pub(crate) fn read_required_sync(path: &Path) -> Result<Vec<u8>, AuditError> {
    validate_safe_path(path)?;
    std::fs::read(path).map_err(AuditError::from)
}

pub(crate) fn read_if_exists_sync(path: &Path) -> Result<Option<Vec<u8>>, AuditError> {
    validate_safe_path(path)?;
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AuditError::Io(e)),
    }
}

pub(crate) fn truncate_file_sync(path: &Path, len: u64) -> Result<(), AuditError> {
    validate_safe_path(path)?;
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(len)?;
    Ok(())
}

#[must_use = "modification times must be used for deterministic pruning"]
pub(crate) fn modified_time_or_epoch_sync(path: &Path) -> std::time::SystemTime {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
}

pub(crate) async fn rename_required(from: &Path, to: &Path) -> Result<(), AuditError> {
    validate_safe_path(from)?;
    validate_safe_path(to)?;
    tokio::fs::rename(from, to).await.map_err(AuditError::from)
}

pub(crate) async fn rename_if_exists(from: &Path, to: &Path) -> Result<bool, AuditError> {
    validate_safe_path(from)?;
    validate_safe_path(to)?;
    match tokio::fs::rename(from, to).await {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(AuditError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_append_bytes_sync_creates_parent_and_persists() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("nested").join("audit.log");

        append_bytes_sync(&path, b"entry\n", Durability::SyncData, "test audit file")
            .expect("append bytes");

        let bytes = std::fs::read(&path).expect("read appended file");
        assert_eq!(bytes, b"entry\n");
    }

    #[test]
    fn test_path_traversal_rejected() {
        let path = Path::new("/tmp/../etc/passwd");
        let result = append_bytes_sync(path, b"x", Durability::FlushOnly, "test");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path traversal"), "expected traversal rejection, got: {err}");
    }

    #[test]
    fn test_read_if_exists_sync_missing_is_none() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("missing.bin");

        let bytes = read_if_exists_sync(&path).expect("missing read");
        assert!(bytes.is_none());
    }

    #[test]
    fn test_truncate_file_sync_shrinks_file() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("leaf.bin");
        std::fs::write(&path, [1u8; 64]).expect("seed file");

        truncate_file_sync(&path, 32).expect("truncate");

        let metadata = std::fs::metadata(&path).expect("metadata");
        assert_eq!(metadata.len(), 32);
    }

    #[tokio::test]
    async fn test_append_bytes_creates_parent_and_persists() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("nested").join("manifest.jsonl");

        append_bytes(
            &path,
            b"{\"event\":1}\n",
            Durability::SyncData,
            "test manifest file",
        )
        .await
        .expect("append bytes");

        let content = tokio::fs::read_to_string(&path).await.expect("read file");
        assert_eq!(content, "{\"event\":1}\n");
    }

    #[tokio::test]
    async fn test_rename_if_exists_returns_false_for_missing_file() {
        let dir = TempDir::new().expect("temp dir");
        let from = dir.path().join("missing.log");
        let to = dir.path().join("rotated.log");

        let renamed = rename_if_exists(&from, &to).await.expect("rename");
        assert!(!renamed);
    }
}
