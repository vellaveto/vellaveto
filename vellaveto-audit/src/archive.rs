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
    /// Valid range: 1..=36500 (up to ~100 years). A value of 0 is treated as
    /// "keep forever" by `enforce_retention` since no file can be older than
    /// the cutoff.
    pub retention_days: u32,
}

/// Maximum retention period in days (~100 years).
const MAX_RETENTION_DAYS: u32 = 36500;

impl ArchiveConfig {
    /// Validate the archive configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.retention_days > MAX_RETENTION_DAYS {
            return Err(format!(
                "archive.retention_days {} exceeds maximum {}",
                self.retention_days, MAX_RETENTION_DAYS
            ));
        }
        // 0 is explicitly allowed as "keep forever"
        Ok(())
    }
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            compress: true,
            retention_days: 365,
        }
    }
}

/// SECURITY (FIND-R186-004): Maximum number of errors tracked in ArchiveReport.
const MAX_ARCHIVE_ERRORS: usize = 100;

/// Report of archive maintenance operations.
#[derive(Debug, Default)]
pub struct ArchiveReport {
    /// Files that were compressed.
    pub compressed: Vec<PathBuf>,
    /// Files that were deleted due to retention policy.
    pub deleted: Vec<PathBuf>,
    /// Non-fatal errors encountered during maintenance (capped at MAX_ARCHIVE_ERRORS).
    pub errors: Vec<String>,
}

/// Compress a rotated log file using gzip.
///
/// Renames `audit.2026-01-01T00-00-00.log` → `audit.2026-01-01T00-00-00.log.gz`.
/// The original file is removed after successful compression.
///
/// SECURITY (FIND-R46-006): TOCTOU race condition — the file is read and then
/// the compressed output is written as a separate operation. If the file contents
/// change between the read and the removal of the original, the compressed copy
/// may not reflect the final state. This is acceptable because:
/// 1. Compression runs only on rotated files, which are no longer being written to.
/// 2. The rotation manifest records the tail hash of the file at rotation time,
///    so any post-rotation modification is detectable via cross-rotation verification.
/// 3. File locking would not help because the write end has already been closed.
pub async fn compress_rotated_file(path: &Path) -> Result<PathBuf, AuditError> {
    use std::io::Write;

    // SECURITY (FIND-R52-AUDIT-008): Check file size before reading to prevent OOM
    // from adversarially large rotated files. 512 MB is far beyond any legitimate
    // rotated audit log (default rotation at 100 MB).
    const MAX_ARCHIVE_FILE_SIZE: u64 = 512 * 1024 * 1024;
    let metadata = tokio::fs::metadata(path).await.map_err(AuditError::Io)?;
    if metadata.len() > MAX_ARCHIVE_FILE_SIZE {
        return Err(AuditError::Validation(format!(
            "Archive file too large for compression: {} bytes (max {} bytes)",
            metadata.len(),
            MAX_ARCHIVE_FILE_SIZE
        )));
    }

    let content = tokio::fs::read(path).await.map_err(AuditError::Io)?;
    let original_len = content.len();

    let gz_path = PathBuf::from(format!("{}.gz", path.display()));

    // Compress in blocking task to avoid blocking the async runtime
    let gz_path_clone = gz_path.clone();
    let compressed = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, AuditError> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&content).map_err(AuditError::Io)?;
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
///
/// SECURITY (FIND-R46-005): Retention is based on filesystem `mtime` metadata,
/// which can be spoofed by an attacker with write access to the archive directory
/// (e.g., using `touch -t` or `filetime::set_file_mtime`). This means an attacker
/// could prevent old files from being deleted (by setting mtime to the future) or
/// force premature deletion of recent files (by setting mtime to the past).
///
/// Mitigations:
/// - The rotation manifest records timestamps at rotation time. Cross-reference
///   manifest timestamps for authoritative age when available.
/// - File permissions (0o600) restrict mtime modification to the file owner.
/// - For environments requiring tamper-proof retention, use an immutable storage
///   backend (e.g., AWS S3 Object Lock, WORM storage).
pub async fn enforce_retention(
    logger: &AuditLogger,
    retention_days: u32,
) -> Result<Vec<PathBuf>, AuditError> {
    let rotated_files = logger.list_rotated_files()?;

    // SECURITY (FIND-R165-001): retention_days=0 means "keep forever". Without this
    // guard, cutoff would be `now - 0 = now`, deleting ALL archives immediately.
    if retention_days == 0 {
        return Ok(Vec::new());
    }

    let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(retention_days));
    let mut deleted = Vec::new();

    for path in rotated_files {
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(AuditError::Io(e)),
        };

        let modified = metadata.modified().map_err(AuditError::Io)?;

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
                Err(e) => {
                    if report.errors.len() < MAX_ARCHIVE_ERRORS {
                        report
                            .errors
                            .push(format!("Failed to compress {}: {}", path.display(), e));
                    }
                }
            }
        }
    }

    // Phase 2: Enforce retention
    match enforce_retention(logger, config.retention_days).await {
        Ok(deleted) => report.deleted = deleted,
        Err(e) => {
            if report.errors.len() < MAX_ARCHIVE_ERRORS {
                report
                    .errors
                    .push(format!("Retention enforcement failed: {}", e));
            }
        }
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

    /// SECURITY (IMP-R110-006): Validate retention_days bounds.
    #[test]
    fn test_archive_config_validate_default_passes() {
        assert!(ArchiveConfig::default().validate().is_ok());
    }

    #[test]
    fn test_archive_config_validate_zero_retention_ok() {
        let config = ArchiveConfig {
            compress: true,
            retention_days: 0,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_archive_config_validate_max_retention_ok() {
        let config = ArchiveConfig {
            compress: true,
            retention_days: 36500,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_archive_config_validate_exceeds_max() {
        let config = ArchiveConfig {
            compress: true,
            retention_days: 36501,
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("retention_days"));
    }
}
