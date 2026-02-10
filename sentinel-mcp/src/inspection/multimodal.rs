//! Multimodal content safety scanning.
//!
//! This module provides detection of prompt injection attacks embedded in
//! non-text content such as images, audio, and documents.
//!
//! # Attack Vectors
//!
//! - **Image-embedded text**: Malicious instructions rendered as text in images
//! - **Steganography**: Hidden data in image pixels or audio samples
//! - **Document exploits**: Malicious content in PDFs, Office documents
//!
//! # Feature Flag
//!
//! This module requires the `multimodal` feature flag:
//!
//! ```toml
//! [dependencies]
//! sentinel-mcp = { version = "2.0", features = ["multimodal"] }
//! ```
//!
//! # Example
//!
//! ```ignore
//! use sentinel_mcp::inspection::multimodal::{MultimodalScanner, ContentType};
//!
//! let scanner = MultimodalScanner::new(config);
//! let result = scanner.scan_content(&image_bytes, ContentType::Image)?;
//!
//! if let Some(finding) = result.injection_detected {
//!     // Image contains embedded injection attempt
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::injection::InjectionScanner;

/// Content type for multimodal scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ContentType {
    /// Image content (PNG, JPEG, GIF, WebP, etc.)
    Image,
    /// Audio content (WAV, MP3, etc.)
    Audio,
    /// PDF document
    Pdf,
    /// Video content
    Video,
    /// Unknown or unsupported content type
    Unknown,
}

impl ContentType {
    /// Detect content type from MIME type string.
    pub fn from_mime(mime: &str) -> Self {
        let mime_lower = mime.to_lowercase();
        if mime_lower.starts_with("image/") {
            ContentType::Image
        } else if mime_lower.starts_with("audio/") {
            ContentType::Audio
        } else if mime_lower == "application/pdf" {
            ContentType::Pdf
        } else if mime_lower.starts_with("video/") {
            ContentType::Video
        } else {
            ContentType::Unknown
        }
    }

    /// Detect content type from magic bytes.
    pub fn from_magic_bytes(data: &[u8]) -> Self {
        if data.len() < 4 {
            return ContentType::Unknown;
        }

        // PNG: 89 50 4E 47
        if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
            return ContentType::Image;
        }

        // JPEG: FF D8 FF
        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return ContentType::Image;
        }

        // GIF: GIF87a or GIF89a
        if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
            return ContentType::Image;
        }

        // WebP: RIFF....WEBP
        if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
            return ContentType::Image;
        }

        // PDF: %PDF
        if data.starts_with(b"%PDF") {
            return ContentType::Pdf;
        }

        // WAV: RIFF....WAVE
        if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WAVE" {
            return ContentType::Audio;
        }

        // MP3: ID3 or FF FB
        if data.starts_with(b"ID3") || data.starts_with(&[0xFF, 0xFB]) {
            return ContentType::Audio;
        }

        ContentType::Unknown
    }
}

/// Configuration for multimodal scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultimodalConfig {
    /// Enable multimodal scanning. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Enable OCR for image text extraction. Default: true when enabled.
    #[serde(default = "default_true")]
    pub enable_ocr: bool,

    /// Maximum image size to process in bytes. Default: 10MB.
    #[serde(default = "default_max_image_size")]
    pub max_image_size: usize,

    /// OCR timeout in milliseconds. Default: 5000ms.
    #[serde(default = "default_ocr_timeout_ms")]
    pub ocr_timeout_ms: u64,

    /// Minimum confidence for OCR text. Default: 0.5.
    #[serde(default = "default_min_ocr_confidence")]
    pub min_ocr_confidence: f32,

    /// Enable steganography detection. Default: false (computationally expensive).
    #[serde(default)]
    pub enable_stego_detection: bool,

    /// Content types to scan. Default: [Image].
    #[serde(default = "default_content_types")]
    pub content_types: Vec<ContentType>,
}

fn default_true() -> bool {
    true
}

fn default_max_image_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_ocr_timeout_ms() -> u64 {
    5000
}

fn default_min_ocr_confidence() -> f32 {
    0.5
}

fn default_content_types() -> Vec<ContentType> {
    vec![ContentType::Image]
}

impl Default for MultimodalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enable_ocr: true,
            max_image_size: default_max_image_size(),
            ocr_timeout_ms: default_ocr_timeout_ms(),
            min_ocr_confidence: default_min_ocr_confidence(),
            enable_stego_detection: false,
            content_types: default_content_types(),
        }
    }
}

/// Result of multimodal content scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultimodalScanResult {
    /// Content type that was scanned.
    pub content_type: ContentType,

    /// Extracted text from the content (if any).
    pub extracted_text: Option<String>,

    /// OCR confidence score (0.0-1.0).
    pub ocr_confidence: Option<f32>,

    /// Injection patterns detected in extracted text.
    pub injection_findings: Vec<MultimodalInjectionFinding>,

    /// Steganography indicators detected.
    pub stego_indicators: Vec<StegoIndicator>,

    /// Scan duration in milliseconds.
    pub scan_duration_ms: u64,
}

/// Injection finding from multimodal content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultimodalInjectionFinding {
    /// Pattern that matched.
    pub pattern: String,

    /// Location in extracted text.
    pub text_location: Option<String>,

    /// Region in image (x, y, width, height) if applicable.
    pub image_region: Option<(u32, u32, u32, u32)>,

    /// Confidence score for this finding.
    pub confidence: f32,
}

/// Steganography detection indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegoIndicator {
    /// Type of steganography suspected.
    pub stego_type: String,

    /// Confidence score (0.0-1.0).
    pub confidence: f32,

    /// Additional details.
    pub details: String,
}

/// Multimodal content scanner.
///
/// Provides OCR-based text extraction and injection detection for
/// non-text content such as images.
pub struct MultimodalScanner {
    config: MultimodalConfig,
    injection_scanner: Option<InjectionScanner>,
}

impl MultimodalScanner {
    /// Create a new multimodal scanner with the given configuration.
    pub fn new(config: MultimodalConfig) -> Self {
        let injection_scanner = if config.enabled {
            InjectionScanner::from_config(&[], &[])
        } else {
            None
        };

        Self {
            config,
            injection_scanner,
        }
    }

    /// Create a scanner with a custom injection scanner.
    pub fn with_injection_scanner(config: MultimodalConfig, scanner: InjectionScanner) -> Self {
        Self {
            config,
            injection_scanner: Some(scanner),
        }
    }

    /// Check if scanning is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Scan content for injection attempts.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw content bytes
    /// * `content_type` - Type of content (or auto-detect if None)
    ///
    /// # Returns
    ///
    /// Scan result with any detected injection patterns.
    pub fn scan_content(
        &self,
        data: &[u8],
        content_type: Option<ContentType>,
    ) -> Result<MultimodalScanResult, MultimodalError> {
        let start = std::time::Instant::now();

        // Determine content type
        let content_type = content_type.unwrap_or_else(|| ContentType::from_magic_bytes(data));

        // Disabled scanner must be a fast no-op.
        if !self.config.enabled {
            return Ok(MultimodalScanResult {
                content_type,
                extracted_text: None,
                ocr_confidence: None,
                injection_findings: vec![],
                stego_indicators: vec![],
                scan_duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Check if we should scan this content type
        if !self.config.content_types.contains(&content_type) {
            return Ok(MultimodalScanResult {
                content_type,
                extracted_text: None,
                ocr_confidence: None,
                injection_findings: vec![],
                stego_indicators: vec![],
                scan_duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Check size limits
        if data.len() > self.config.max_image_size {
            return Err(MultimodalError::ContentTooLarge {
                size: data.len(),
                max: self.config.max_image_size,
            });
        }

        // Extract text based on content type
        let (extracted_text, ocr_confidence) = match content_type {
            ContentType::Image => self.extract_text_from_image(data)?,
            ContentType::Pdf => self.extract_text_from_pdf(data)?,
            _ => (None, None),
        };

        // Scan extracted text for injection patterns
        let injection_findings = if let (Some(ref text), Some(ref scanner)) =
            (&extracted_text, &self.injection_scanner)
        {
            self.scan_text_for_injection(text, scanner)
        } else {
            vec![]
        };

        // Check for steganography if enabled
        let stego_indicators = if self.config.enable_stego_detection {
            self.detect_steganography(data, content_type)?
        } else {
            vec![]
        };

        Ok(MultimodalScanResult {
            content_type,
            extracted_text,
            ocr_confidence,
            injection_findings,
            stego_indicators,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Extract text from image using OCR.
    ///
    /// This is a placeholder implementation. When the `multimodal` feature is
    /// enabled with actual OCR support, this will use Tesseract or similar.
    #[cfg(not(feature = "multimodal"))]
    fn extract_text_from_image(
        &self,
        _data: &[u8],
    ) -> Result<(Option<String>, Option<f32>), MultimodalError> {
        if !self.config.enable_ocr {
            return Ok((None, None));
        }

        // Fail closed when OCR is configured but unavailable in this build.
        Err(MultimodalError::OcrError(
            "OCR backend unavailable; build with `multimodal` feature".to_string(),
        ))
    }

    /// Extract text from image using OCR (with feature enabled).
    #[cfg(feature = "multimodal")]
    fn extract_text_from_image(
        &self,
        data: &[u8],
    ) -> Result<(Option<String>, Option<f32>), MultimodalError> {
        if !self.config.enable_ocr {
            return Ok((None, None));
        }

        use image::ImageReader;
        use std::io::Cursor;

        // Decode image
        let img = ImageReader::new(Cursor::new(data))
            .with_guessed_format()
            .map_err(|e| MultimodalError::ImageDecodeError(e.to_string()))?
            .decode()
            .map_err(|e| MultimodalError::ImageDecodeError(e.to_string()))?;

        // Convert to grayscale for OCR
        let _gray = img.to_luma8();

        // TODO: Integrate with actual OCR library (Tesseract)
        // Fail closed until OCR backend is wired.
        // In production, this should call an OCR engine and return extracted text.
        Err(MultimodalError::OcrError(
            "OCR backend not integrated yet".to_string(),
        ))
    }

    /// Extract text from PDF.
    fn extract_text_from_pdf(
        &self,
        _data: &[u8],
    ) -> Result<(Option<String>, Option<f32>), MultimodalError> {
        Err(MultimodalError::UnsupportedContentType(ContentType::Pdf))
    }

    /// Scan extracted text for injection patterns.
    fn scan_text_for_injection(
        &self,
        text: &str,
        scanner: &InjectionScanner,
    ) -> Vec<MultimodalInjectionFinding> {
        let matches = scanner.inspect(text);

        matches
            .into_iter()
            .map(|pattern| MultimodalInjectionFinding {
                pattern: pattern.to_string(),
                text_location: Some(text.chars().take(100).collect()),
                image_region: None,
                confidence: 0.9, // High confidence for pattern match
            })
            .collect()
    }

    /// Detect potential steganography in content.
    fn detect_steganography(
        &self,
        _data: &[u8],
        _content_type: ContentType,
    ) -> Result<Vec<StegoIndicator>, MultimodalError> {
        Err(MultimodalError::StegoError(
            "steganography backend not integrated yet".to_string(),
        ))
    }
}

/// Errors from multimodal scanning.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MultimodalError {
    #[error("Content too large: {size} bytes exceeds limit of {max} bytes")]
    ContentTooLarge { size: usize, max: usize },

    #[error("Failed to decode image: {0}")]
    ImageDecodeError(String),

    #[error("OCR failed: {0}")]
    OcrError(String),

    #[error("OCR timeout after {0:?}")]
    OcrTimeout(Duration),

    #[error("Unsupported content type: {0:?}")]
    UnsupportedContentType(ContentType),

    #[error("Steganography detection failed: {0}")]
    StegoError(String),
}

/// Scan a base64-encoded blob for injection.
///
/// Convenience function for scanning `resource.blob` fields in MCP responses.
pub fn scan_blob_for_injection(
    base64_data: &str,
    mime_type: Option<&str>,
    scanner: &MultimodalScanner,
) -> Result<Option<MultimodalScanResult>, MultimodalError> {
    use base64::Engine;

    if !scanner.is_enabled() {
        return Ok(None);
    }

    // Decode base64
    let data = base64::engine::general_purpose::STANDARD
        .decode(base64_data)
        .map_err(|e| MultimodalError::ImageDecodeError(format!("Invalid base64: {}", e)))?;

    // Determine content type
    let content_type = mime_type
        .map(ContentType::from_mime)
        .unwrap_or_else(|| ContentType::from_magic_bytes(&data));

    // Scan
    let result = scanner.scan_content(&data, Some(content_type))?;

    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_from_mime() {
        assert_eq!(ContentType::from_mime("image/png"), ContentType::Image);
        assert_eq!(ContentType::from_mime("image/jpeg"), ContentType::Image);
        assert_eq!(ContentType::from_mime("audio/wav"), ContentType::Audio);
        assert_eq!(ContentType::from_mime("application/pdf"), ContentType::Pdf);
        assert_eq!(ContentType::from_mime("video/mp4"), ContentType::Video);
        assert_eq!(ContentType::from_mime("text/plain"), ContentType::Unknown);
    }

    #[test]
    fn test_content_type_from_magic_bytes() {
        // PNG
        assert_eq!(
            ContentType::from_magic_bytes(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]),
            ContentType::Image
        );

        // JPEG
        assert_eq!(
            ContentType::from_magic_bytes(&[0xFF, 0xD8, 0xFF, 0xE0]),
            ContentType::Image
        );

        // PDF
        assert_eq!(ContentType::from_magic_bytes(b"%PDF-1.4"), ContentType::Pdf);

        // Unknown
        assert_eq!(
            ContentType::from_magic_bytes(&[0x00, 0x00]),
            ContentType::Unknown
        );
    }

    #[test]
    fn test_scanner_disabled_by_default() {
        let config = MultimodalConfig::default();
        let scanner = MultimodalScanner::new(config);
        assert!(!scanner.is_enabled());
    }

    #[test]
    fn test_content_too_large() {
        let config = MultimodalConfig {
            enabled: true,
            max_image_size: 100,
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        let large_data = vec![0u8; 1000];
        let result = scanner.scan_content(&large_data, Some(ContentType::Image));

        assert!(matches!(
            result,
            Err(MultimodalError::ContentTooLarge { .. })
        ));
    }

    // ═══════════════════════════════════════════════════
    // GAP-006: Additional edge case tests
    // ═══════════════════════════════════════════════════

    /// GAP-006: Test magic bytes detection with empty data
    #[test]
    fn test_content_type_from_magic_bytes_empty() {
        assert_eq!(ContentType::from_magic_bytes(&[]), ContentType::Unknown);
    }

    /// GAP-006: Test magic bytes detection with very short data
    #[test]
    fn test_content_type_from_magic_bytes_short() {
        assert_eq!(ContentType::from_magic_bytes(&[0x89]), ContentType::Unknown);
        assert_eq!(
            ContentType::from_magic_bytes(&[0x89, 0x50]),
            ContentType::Unknown
        );
        assert_eq!(
            ContentType::from_magic_bytes(&[0x89, 0x50, 0x4E]),
            ContentType::Unknown
        );
    }

    /// GAP-006: Test GIF magic bytes detection
    #[test]
    fn test_content_type_from_magic_bytes_gif() {
        // GIF87a
        assert_eq!(
            ContentType::from_magic_bytes(b"GIF87a\x00\x00"),
            ContentType::Image
        );
        // GIF89a
        assert_eq!(
            ContentType::from_magic_bytes(b"GIF89a\x00\x00"),
            ContentType::Image
        );
        // Invalid GIF (wrong version)
        assert_eq!(
            ContentType::from_magic_bytes(b"GIF90a\x00\x00"),
            ContentType::Unknown
        );
    }

    /// GAP-006: Test WebP magic bytes detection
    #[test]
    fn test_content_type_from_magic_bytes_webp() {
        // Valid WebP: RIFF....WEBP
        let webp_data = b"RIFF\x00\x00\x00\x00WEBP";
        assert_eq!(ContentType::from_magic_bytes(webp_data), ContentType::Image);

        // Too short to be WebP
        assert_eq!(
            ContentType::from_magic_bytes(b"RIFF\x00\x00\x00\x00WEB"),
            ContentType::Unknown
        );
    }

    /// GAP-006: Test WAV magic bytes detection
    #[test]
    fn test_content_type_from_magic_bytes_wav() {
        // Valid WAV: RIFF....WAVE
        let wav_data = b"RIFF\x00\x00\x00\x00WAVE";
        assert_eq!(ContentType::from_magic_bytes(wav_data), ContentType::Audio);
    }

    /// GAP-006: Test MP3 magic bytes detection
    #[test]
    fn test_content_type_from_magic_bytes_mp3() {
        // MP3 with ID3 header
        assert_eq!(
            ContentType::from_magic_bytes(b"ID3\x04\x00\x00"),
            ContentType::Audio
        );

        // MP3 sync word
        assert_eq!(
            ContentType::from_magic_bytes(&[0xFF, 0xFB, 0x90, 0x00]),
            ContentType::Audio
        );
    }

    /// GAP-006: Test MIME type case insensitivity
    #[test]
    fn test_content_type_from_mime_case_insensitive() {
        assert_eq!(ContentType::from_mime("IMAGE/PNG"), ContentType::Image);
        assert_eq!(ContentType::from_mime("Image/Jpeg"), ContentType::Image);
        assert_eq!(ContentType::from_mime("AUDIO/WAV"), ContentType::Audio);
        assert_eq!(ContentType::from_mime("APPLICATION/PDF"), ContentType::Pdf);
        assert_eq!(ContentType::from_mime("VIDEO/MP4"), ContentType::Video);
    }

    /// GAP-006: Test scanning skipped for content type not in allowed list
    #[test]
    fn test_scan_skipped_for_unlisted_content_type() {
        let config = MultimodalConfig {
            enabled: true,
            content_types: vec![ContentType::Image], // Only images
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        // PDF data that's within size limits
        let pdf_data = b"%PDF-1.4 small file";
        let result = scanner
            .scan_content(pdf_data, Some(ContentType::Pdf))
            .unwrap();

        // Should return immediately with no findings
        assert_eq!(result.content_type, ContentType::Pdf);
        assert!(result.extracted_text.is_none());
        assert!(result.injection_findings.is_empty());
    }

    /// GAP-006: Test scan returns quickly when disabled
    #[test]
    fn test_scan_disabled_scanner() {
        let config = MultimodalConfig {
            enabled: false,
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        assert!(!scanner.is_enabled());

        // Scanning with disabled scanner doesn't error
        let data = b"some data";
        let result = scanner.scan_content(data, Some(ContentType::Unknown));
        assert!(result.is_ok());
    }

    /// Disabled scanners should skip size checks and return an empty result.
    #[test]
    fn test_scan_disabled_skips_size_checks() {
        let config = MultimodalConfig {
            enabled: false,
            max_image_size: 1,
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);
        let large_data = vec![0u8; 1024];

        let result = scanner
            .scan_content(&large_data, Some(ContentType::Image))
            .unwrap();
        assert_eq!(result.content_type, ContentType::Image);
        assert!(result.injection_findings.is_empty());
    }

    /// GAP-006: Test config default values
    #[test]
    fn test_config_default_values() {
        let config = MultimodalConfig::default();

        assert!(!config.enabled);
        assert!(config.enable_ocr);
        assert_eq!(config.max_image_size, 10 * 1024 * 1024); // 10MB
        assert_eq!(config.ocr_timeout_ms, 5000);
        assert!((config.min_ocr_confidence - 0.5).abs() < f32::EPSILON);
        assert!(!config.enable_stego_detection);
        assert_eq!(config.content_types, vec![ContentType::Image]);
    }

    /// GAP-006: Test scan_blob_for_injection with disabled scanner
    #[test]
    fn test_scan_blob_disabled_scanner() {
        let config = MultimodalConfig {
            enabled: false,
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        let result = scan_blob_for_injection("SGVsbG8gV29ybGQ=", None, &scanner);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Returns None when disabled
    }

    /// GAP-006: Test scan_blob_for_injection with invalid base64
    #[test]
    fn test_scan_blob_invalid_base64() {
        let config = MultimodalConfig {
            enabled: true,
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        let result = scan_blob_for_injection("not-valid-base64!!!", None, &scanner);
        assert!(matches!(result, Err(MultimodalError::ImageDecodeError(_))));
    }

    /// GAP-006: Test scan_blob with MIME type hint
    #[test]
    fn test_scan_blob_with_mime_hint() {
        let config = MultimodalConfig {
            enabled: true,
            content_types: vec![ContentType::Pdf],
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        // base64 of "%PDF" (small PDF-like data)
        let base64_data =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"%PDF-1.4 test");

        let result = scan_blob_for_injection(&base64_data, Some("application/pdf"), &scanner);
        assert!(matches!(
            result,
            Err(MultimodalError::UnsupportedContentType(ContentType::Pdf))
        ));
    }

    /// GAP-006: Test content type auto-detection in scan_content
    #[test]
    fn test_scan_content_auto_detect_type() {
        let config = MultimodalConfig {
            enabled: true,
            enable_ocr: false,
            content_types: vec![ContentType::Image, ContentType::Pdf],
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        // PNG magic bytes
        let png_data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = scanner.scan_content(&png_data, None).unwrap();
        assert_eq!(result.content_type, ContentType::Image);

        // PDF magic bytes
        let pdf_data = b"%PDF-1.4 test content";
        let result = scanner.scan_content(pdf_data, None);
        assert!(matches!(
            result,
            Err(MultimodalError::UnsupportedContentType(ContentType::Pdf))
        ));
    }

    #[cfg(not(feature = "multimodal"))]
    #[test]
    fn test_scan_image_without_multimodal_feature_fails_closed() {
        let config = MultimodalConfig {
            enabled: true,
            enable_ocr: true,
            content_types: vec![ContentType::Image],
            max_image_size: 1024,
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);
        let image_data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A];

        let result = scanner.scan_content(&image_data, Some(ContentType::Image));
        assert!(matches!(result, Err(MultimodalError::OcrError(_))));
    }

    /// GAP-006: Test error message contains size info
    #[test]
    fn test_content_too_large_error_message() {
        let config = MultimodalConfig {
            enabled: true,
            max_image_size: 50,
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        let large_data = vec![0u8; 100];
        let result = scanner.scan_content(&large_data, Some(ContentType::Image));

        match result {
            Err(MultimodalError::ContentTooLarge { size, max }) => {
                assert_eq!(size, 100);
                assert_eq!(max, 50);
                let msg = format!("{}", MultimodalError::ContentTooLarge { size, max });
                assert!(msg.contains("100"));
                assert!(msg.contains("50"));
            }
            _ => panic!("Expected ContentTooLarge error"),
        }
    }

    /// GAP-006: Test MultimodalScanResult fields
    #[test]
    fn test_scan_result_has_duration() {
        let config = MultimodalConfig {
            enabled: true,
            content_types: vec![ContentType::Unknown],
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        let data = b"some random bytes";
        let result = scanner
            .scan_content(data, Some(ContentType::Unknown))
            .unwrap();

        // Duration should be very small but present
        assert!(result.scan_duration_ms < 1000); // Less than 1 second
        assert!(result.injection_findings.is_empty());
        assert!(result.stego_indicators.is_empty());
    }

    #[test]
    fn test_pdf_scan_fails_closed_when_extractor_unavailable() {
        let config = MultimodalConfig {
            enabled: true,
            content_types: vec![ContentType::Pdf],
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        let pdf_data = b"%PDF-1.4 test content";
        let result = scanner.scan_content(pdf_data, Some(ContentType::Pdf));
        assert!(matches!(
            result,
            Err(MultimodalError::UnsupportedContentType(ContentType::Pdf))
        ));
    }

    #[test]
    fn test_stego_enabled_fails_closed_without_backend() {
        let config = MultimodalConfig {
            enabled: true,
            enable_ocr: false,
            enable_stego_detection: true,
            content_types: vec![ContentType::Image],
            ..Default::default()
        };
        let scanner = MultimodalScanner::new(config);

        let png_data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A];
        let result = scanner.scan_content(&png_data, Some(ContentType::Image));
        assert!(matches!(result, Err(MultimodalError::StegoError(_))));
    }

    /// GAP-006: Test with_injection_scanner constructor
    #[test]
    fn test_with_injection_scanner() {
        let config = MultimodalConfig {
            enabled: true,
            ..Default::default()
        };

        // Create an InjectionScanner with some patterns
        let patterns = ["ignore previous", "disregard instructions"];
        if let Some(injection_scanner) = InjectionScanner::new(&patterns) {
            let scanner = MultimodalScanner::with_injection_scanner(config, injection_scanner);
            assert!(scanner.is_enabled());
        }
    }
}
