//! Immutable Audit Log Archive with Retention Policies.
//!
//! Extends the existing rotation system with:
//! 1. **Compression** — gzip-compress rotated log files (`.log` → `.log.gz`)
//! 2. **Retention enforcement** — Delete archives older than `record_retention_days`
//! 3. **Archive manifest** — Records archive events in the rotation manifest
//!
//! # Architecture
//!
//! Archive maintenance runs at rotation time (not as a separate background task).
//! When `compress_archives` is enabled, just-rotated files are compressed inline.
//! Retention is enforced by checking file modification timestamps against the
//! configured `record_retention_days`.

use crate::logger::AuditLogger;
use crate::types::AuditError;
use std::path::{Path, PathBuf};

/// Archive configuration derived from compliance config.
#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    /// Whether to compress rotated audit logs. Default: true.
    pub compress: bool,
    /// Retention period in days. Archives older than this are deleted.
    pub retention_days: u32,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            compress: true,
            retention_days: 365,
        }
    }
}

/// Report of archive maintenance operations.
#[derive(Debug, Default)]
pub struct ArchiveReport {
    /// Files that were compressed.
    pub compressed: Vec<PathBuf>,
    /// Files that were deleted due to retention policy.
    pub deleted: Vec<PathBuf>,
    /// Non-fatal errors encountered during maintenance.
    pub errors: Vec<String>,
}

/// Compress a rotated log file using gzip.
///
/// Renames `audit.2026-01-01T00-00-00.log` → `audit.2026-01-01T00-00-00.log.gz`.
/// The original file is removed after successful compression.
pub async fn compress_rotated_file(path: &Path) -> Result<PathBuf, AuditError> {
    use std::io::Write;

    let content = tokio::fs::read(path).await.map_err(AuditError::Io)?;
    let original_len = content.len();

    let gz_path = PathBuf::from(format!("{}.gz", path.display()));

    // Compress in blocking task to avoid blocking the async runtime
    let gz_path_clone = gz_path.clone();
    let compressed = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, AuditError> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&content)
            .map_err(AuditError::Io)?;
        encoder.finish().map_err(AuditError::Io)
    })
    .await
    .map_err(|e| AuditError::Validation(format!("Compression task failed: {}", e)))??;

    tokio::fs::write(&gz_path_clone, &compressed)
        .await
        .map_err(AuditError::Io)?;

    // Remove original after successful compression
    tokio::fs::remove_file(path).await.map_err(AuditError::Io)?;

    tracing::info!(
        "Compressed audit archive: {} -> {} ({} -> {} bytes)",
        path.display(),
        gz_path_clone.display(),
        original_len,
        compressed.len(),
    );

    Ok(gz_path_clone)
}

/// Enforce retention policy: delete archives older than `retention_days`.
///
/// Returns list of deleted file paths.
pub async fn enforce_retention(
    logger: &AuditLogger,
    retention_days: u32,
) -> Result<Vec<PathBuf>, AuditError> {
    let rotated_files = logger.list_rotated_files()?;
    let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(retention_days));
    let mut deleted = Vec::new();

    for path in rotated_files {
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(AuditError::Io(e)),
        };

        let modified = metadata
            .modified()
            .map_err(|e| AuditError::Io(e))?;

        let modified_dt: chrono::DateTime<chrono::Utc> = modified.into();

        if modified_dt < cutoff {
            tokio::fs::remove_file(&path)
                .await
                .map_err(AuditError::Io)?;
            tracing::info!(
                "Deleted expired audit archive: {} (modified: {})",
                path.display(),
                modified_dt.to_rfc3339(),
            );
            deleted.push(path);
        }
    }

    Ok(deleted)
}

/// Run archive maintenance: compress uncompressed rotated files + enforce retention.
pub async fn run_archive_maintenance(
    logger: &AuditLogger,
    config: &ArchiveConfig,
) -> Result<ArchiveReport, AuditError> {
    let mut report = ArchiveReport::default();

    // Phase 1: Compress uncompressed rotated files
    if config.compress {
        let rotated_files = logger.list_rotated_files()?;
        for path in rotated_files {
            let path_str = path.display().to_string();
            // Skip already-compressed files
            if path_str.ends_with(".gz") {
                continue;
            }
            match compress_rotated_file(&path).await {
                Ok(gz_path) => report.compressed.push(gz_path),
                Err(e) => report.errors.push(format!(
                    "Failed to compress {}: {}",
                    path.display(),
                    e
                )),
            }
        }
    }

    // Phase 2: Enforce retention
    match enforce_retention(logger, config.retention_days).await {
        Ok(deleted) => report.deleted = deleted,
        Err(e) => report.errors.push(format!("Retention enforcement failed: {}", e)),
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditLogger;

    #[tokio::test]
    async fn test_compress_rotated_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("audit.2026-01-01T00-00-00.log");
        std::fs::write(&file_path, "test log content\n").unwrap();

        let gz_path = compress_rotated_file(&file_path).await.unwrap();
        assert!(gz_path.exists());
        assert!(!file_path.exists(), "original should be removed");
        assert!(gz_path.display().to_string().ends_with(".gz"));
    }

    #[tokio::test]
    async fn test_compress_preserves_content() {
        use std::io::Read;

        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("audit.2026-01-01T00-00-00.log");
        let original_content = "line 1\nline 2\nline 3\n";
        std::fs::write(&file_path, original_content).unwrap();

        let gz_path = compress_rotated_file(&file_path).await.unwrap();

        // Decompress and verify
        let gz_bytes = std::fs::read(&gz_path).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(&gz_bytes[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, original_content);
    }

    #[tokio::test]
    async fn test_enforce_retention_deletes_old() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        std::fs::write(&log_path, "").unwrap();

        // Create an old rotated file
        let old_file = dir.path().join("audit.2020-01-01T00-00-00.log");
        std::fs::write(&old_file, "old data").unwrap();

        // Set modification time to 2 years ago
        let old_time = filetime::FileTime::from_unix_time(
            (chrono::Utc::now() - chrono::Duration::days(800)).timestamp(),
            0,
        );
        filetime::set_file_mtime(&old_file, old_time).unwrap();

        let logger = AuditLogger::new(log_path);
        let deleted = enforce_retention(&logger, 365).await.unwrap();
        assert_eq!(deleted.len(), 1);
        assert!(!old_file.exists());
    }

    #[tokio::test]
    async fn test_enforce_retention_keeps_recent() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        std::fs::write(&log_path, "").unwrap();

        // Create a recent rotated file
        let recent_file = dir.path().join("audit.2026-01-01T00-00-00.log");
        std::fs::write(&recent_file, "recent data").unwrap();

        let logger = AuditLogger::new(log_path);
        let deleted = enforce_retention(&logger, 365).await.unwrap();
        assert!(deleted.is_empty());
        assert!(recent_file.exists());
    }

    #[tokio::test]
    async fn test_enforce_retention_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        std::fs::write(&log_path, "").unwrap();

        let logger = AuditLogger::new(log_path);
        let deleted = enforce_retention(&logger, 365).await.unwrap();
        assert!(deleted.is_empty());
    }

    #[tokio::test]
    async fn test_run_archive_maintenance() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        std::fs::write(&log_path, "").unwrap();

        // Create an uncompressed rotated file
        let rotated = dir.path().join("audit.2026-01-10T00-00-00.log");
        std::fs::write(&rotated, "some data").unwrap();

        let logger = AuditLogger::new(log_path);
        let config = ArchiveConfig {
            compress: true,
            retention_days: 365,
        };
        let report = run_archive_maintenance(&logger, &config).await.unwrap();
        assert_eq!(report.compressed.len(), 1);
        assert!(report.errors.is_empty());
    }

    #[tokio::test]
    async fn test_archive_report_counts() {
        let report = ArchiveReport::default();
        assert!(report.compressed.is_empty());
        assert!(report.deleted.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_list_rotated_files_includes_gz() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        std::fs::write(&log_path, "").unwrap();

        // Create both .log and .log.gz rotated files
        let rotated_log = dir.path().join("audit.2026-01-01T00-00-00.log");
        std::fs::write(&rotated_log, "data").unwrap();
        let rotated_gz = dir.path().join("audit.2026-01-02T00-00-00.log.gz");
        std::fs::write(&rotated_gz, "compressed").unwrap();

        let logger = AuditLogger::new(log_path);
        let files = logger.list_rotated_files().unwrap();
        assert_eq!(files.len(), 2, "should include both .log and .log.gz files");
    }

    #[test]
    fn test_config_defaults() {
        let config = ArchiveConfig::default();
        assert!(config.compress);
        assert_eq!(config.retention_days, 365);
    }
}
