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
        // Placeholder: OCR not available without multimodal feature
        Ok((None, None))
    }

    /// Extract text from image using OCR (with feature enabled).
    #[cfg(feature = "multimodal")]
    fn extract_text_from_image(
        &self,
        data: &[u8],
    ) -> Result<(Option<String>, Option<f32>), MultimodalError> {
        use image::io::Reader as ImageReader;
        use std::io::Cursor;

        // Decode image
        let img = ImageReader::new(Cursor::new(data))
            .with_guessed_format()
            .map_err(|e| MultimodalError::ImageDecodeError(e.to_string()))?
            .decode()
            .map_err(|e| MultimodalError::ImageDecodeError(e.to_string()))?;

        // Convert to grayscale for OCR
        let gray = img.to_luma8();

        // TODO: Integrate with actual OCR library (Tesseract)
        // For now, return placeholder
        // In production, this would call:
        // let text = tesseract::ocr(&gray, "eng")?;

        Ok((None, None))
    }

    /// Extract text from PDF.
    fn extract_text_from_pdf(
        &self,
        _data: &[u8],
    ) -> Result<(Option<String>, Option<f32>), MultimodalError> {
        // Placeholder: PDF text extraction not yet implemented
        // Would use pdf-extract or similar crate
        Ok((None, None))
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
        // Placeholder: Steganography detection not yet implemented
        // Would analyze:
        // - LSB patterns in images
        // - Statistical anomalies
        // - Known stego tool signatures
        Ok(vec![])
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
        assert_eq!(
            ContentType::from_mime("text/plain"),
            ContentType::Unknown
        );
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
        assert_eq!(
            ContentType::from_magic_bytes(b"%PDF-1.4"),
            ContentType::Pdf
        );

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
}
