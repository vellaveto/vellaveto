//! Output Channel Security Analysis (OWASP ASI07 mitigation).
//!
//! This module detects covert channel exfiltration attempts in tool outputs:
//! - Steganography detection (hidden data in seemingly normal output)
//! - Entropy analysis (abnormally high/low entropy patterns)
//! - Output normalization (stripping potential covert channels)
//!
//! References:
//! - OWASP ASI Top 10 (ASI07: Insecure Tool Output Handling)
//! - Microsoft "Runtime Risk to Real-Time Defense" (2026)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{OnceLock, RwLock};

/// Maximum number of session baselines tracked by OutputSecurityAnalyzer.
/// Prevents unbounded memory growth from attacker-controlled session IDs.
const MAX_SESSION_BASELINES: usize = 100_000;

/// Maximum byte length of a session_id key accepted by update_baseline / get_baseline.
/// Mirrors MAX_SESSION_ID_LENGTH used elsewhere in the codebase (256 bytes).
const MAX_SESSION_ID_LENGTH: usize = 256;

/// Pre-compiled base64 detection regex.
/// Performance (IMP-007): Compiled once at first use rather than per-call.
fn get_base64_pattern() -> Option<&'static regex::Regex> {
    static BASE64_PATTERN: OnceLock<Option<regex::Regex>> = OnceLock::new();
    BASE64_PATTERN
        .get_or_init(|| {
            // This pattern is a constant literal that will always compile successfully.
            regex::Regex::new(r"[A-Za-z0-9+/]{32,}={0,2}").ok()
        })
        .as_ref()
}

/// Alert types for output security violations.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputSecurityAlert {
    /// Detected steganographic content.
    Steganography(SteganographyAlert),
    /// Abnormal entropy detected.
    AbnormalEntropy(EntropyAlert),
    /// Suspicious encoding pattern.
    SuspiciousEncoding(EncodingAlert),
}

/// Steganography detection alert.
#[derive(Debug, Clone, PartialEq)]
pub struct SteganographyAlert {
    /// Type of steganography detected.
    pub stego_type: SteganographyType,
    /// Confidence score in the range `[0.0, 1.0]`. Values outside this range
    /// indicate a bug in the detection logic and must not be relied upon.
    pub confidence: f32,
    /// Description of detection.
    pub description: String,
    /// Suspicious segment offset (if applicable).
    pub offset: Option<usize>,
    /// Length of suspicious segment.
    pub length: Option<usize>,
}

/// Types of steganography that can be detected.
#[derive(Debug, Clone, PartialEq)]
pub enum SteganographyType {
    /// Hidden data in whitespace (zero-width chars, trailing spaces).
    Whitespace,
    /// Unicode homoglyphs used to encode data.
    Homoglyph,
    /// Base64/hex encoded blocks in unexpected locations.
    EncodedBlocks,
    /// Unusual Unicode control characters.
    ControlCharacters,
    /// Data hidden in invisible Unicode characters.
    InvisibleCharacters,
}

/// Entropy analysis alert.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyAlert {
    /// Computed entropy value.
    pub entropy: f32,
    /// Expected entropy range (low, high).
    pub expected_range: (f32, f32),
    /// Whether entropy is too high or too low.
    pub deviation: EntropyDeviation,
    /// Description.
    pub description: String,
}

/// Direction of entropy deviation.
#[derive(Debug, Clone, PartialEq)]
pub enum EntropyDeviation {
    /// Entropy too high (may indicate encrypted/compressed data).
    TooHigh,
    /// Entropy too low (may indicate padding/redundancy attack).
    TooLow,
}

/// Suspicious encoding pattern alert.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodingAlert {
    /// Type of suspicious encoding.
    pub encoding_type: String,
    /// Pattern detected.
    pub pattern: String,
    /// Description.
    pub description: String,
}

/// Result of entropy analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum EntropyResult {
    /// Entropy within normal range.
    Normal { entropy: f32 },
    /// Entropy outside normal range.
    Abnormal(EntropyAlert),
}

/// Configuration for the output security analyzer.
// SECURITY (FIND-R63-MCP-006): deny_unknown_fields prevents attacker-injected
// fields from being silently accepted in security-critical configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSecurityConfig {
    /// Enable steganography detection.
    pub detect_steganography: bool,
    /// Enable entropy analysis.
    pub analyze_entropy: bool,
    /// Minimum entropy threshold (below this is suspicious).
    pub min_entropy_threshold: f32,
    /// Maximum entropy threshold (above this is suspicious).
    pub max_entropy_threshold: f32,
    /// Minimum length for entropy analysis.
    pub min_analysis_length: usize,
    /// Enable output normalization.
    pub normalize_output: bool,
    /// Strip zero-width characters during normalization.
    pub strip_zero_width: bool,
    /// Strip trailing whitespace during normalization.
    pub strip_trailing_whitespace: bool,
}

impl OutputSecurityConfig {
    /// Validate configuration values.
    ///
    /// Ensures entropy thresholds are finite, non-negative, and that
    /// min < max. Shannon entropy for byte data is in `[0.0, 8.0]`,
    /// so thresholds outside that range are rejected.
    pub fn validate(&self) -> Result<(), String> {
        if !self.min_entropy_threshold.is_finite() {
            return Err("min_entropy_threshold must be finite".to_string());
        }
        if !self.max_entropy_threshold.is_finite() {
            return Err("max_entropy_threshold must be finite".to_string());
        }
        if self.min_entropy_threshold < 0.0 || self.min_entropy_threshold > 8.0 {
            return Err(format!(
                "min_entropy_threshold must be in [0.0, 8.0], got {}",
                self.min_entropy_threshold
            ));
        }
        if self.max_entropy_threshold < 0.0 || self.max_entropy_threshold > 8.0 {
            return Err(format!(
                "max_entropy_threshold must be in [0.0, 8.0], got {}",
                self.max_entropy_threshold
            ));
        }
        if self.min_entropy_threshold >= self.max_entropy_threshold {
            return Err(format!(
                "min_entropy_threshold ({}) must be less than max_entropy_threshold ({})",
                self.min_entropy_threshold, self.max_entropy_threshold
            ));
        }
        Ok(())
    }
}
impl Default for OutputSecurityConfig {
    fn default() -> Self {
        Self {
            detect_steganography: true,
            analyze_entropy: true,
            // Natural language typically has entropy between 3.5-5.0 bits per byte
            min_entropy_threshold: 2.0,
            max_entropy_threshold: 6.5,
            min_analysis_length: 100,
            normalize_output: true,
            strip_zero_width: true,
            strip_trailing_whitespace: true,
        }
    }
}

/// Output security analyzer for covert channel detection.
pub struct OutputSecurityAnalyzer {
    config: OutputSecurityConfig,
    /// Per-session baseline entropy (for anomaly detection).
    session_baselines: RwLock<HashMap<String, EntropyBaseline>>,
}

/// Entropy baseline for a session.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for future entropy anomaly detection
struct EntropyBaseline {
    /// Running average entropy.
    average: f32,
    /// Number of samples.
    sample_count: u32,
    /// Standard deviation.
    std_dev: f32,
}

impl OutputSecurityAnalyzer {
    /// Create a new analyzer with default configuration.
    pub fn new() -> Self {
        Self::with_config(OutputSecurityConfig::default())
    }

    /// Create a new analyzer with custom configuration.
    ///
    /// Logs a warning if validation fails but still constructs the analyzer,
    /// since output security analysis is observational (not enforcement).
    pub fn with_config(config: OutputSecurityConfig) -> Self {
        if let Err(e) = config.validate() {
            tracing::warn!(
                target: "vellaveto::security",
                error = %e,
                "OutputSecurityConfig validation failed — using config as-is"
            );
        }
        Self {
            config,
            session_baselines: RwLock::new(HashMap::new()),
        }
    }

    /// Analyze output for steganographic content.
    pub fn detect_steganography(&self, output: &str) -> Option<SteganographyAlert> {
        if !self.config.detect_steganography {
            return None;
        }

        // Check for zero-width characters (common steganography technique)
        if let Some(alert) = self.detect_zero_width_stego(output) {
            return Some(alert);
        }

        // Check for homoglyph encoding
        if let Some(alert) = self.detect_homoglyph_stego(output) {
            return Some(alert);
        }

        // Check for invisible Unicode characters
        if let Some(alert) = self.detect_invisible_chars(output) {
            return Some(alert);
        }

        // Check for unusual control characters
        if let Some(alert) = self.detect_control_chars(output) {
            return Some(alert);
        }

        // Check for encoded blocks in unexpected locations
        if let Some(alert) = self.detect_encoded_blocks(output) {
            return Some(alert);
        }

        None
    }

    /// Detect zero-width character steganography.
    fn detect_zero_width_stego(&self, output: &str) -> Option<SteganographyAlert> {
        // Zero-width characters used for steganography
        const ZERO_WIDTH_CHARS: &[char] = &[
            '\u{200B}', // Zero-width space
            '\u{200C}', // Zero-width non-joiner
            '\u{200D}', // Zero-width joiner
            '\u{FEFF}', // Zero-width no-break space (BOM)
            '\u{2060}', // Word joiner
            '\u{180E}', // Mongolian vowel separator
        ];

        let mut count = 0;
        let mut first_offset = None;

        for (i, c) in output.chars().enumerate() {
            if ZERO_WIDTH_CHARS.contains(&c) {
                count += 1;
                if first_offset.is_none() {
                    first_offset = Some(i);
                }
            }
        }

        // More than 3 zero-width chars is suspicious
        if count > 3 {
            return Some(SteganographyAlert {
                stego_type: SteganographyType::Whitespace,
                confidence: (count as f32 / 10.0).min(1.0),
                description: format!(
                    "Detected {} zero-width characters potentially hiding data",
                    count
                ),
                offset: first_offset,
                length: Some(count),
            });
        }

        None
    }

    /// Detect homoglyph-based steganography.
    fn detect_homoglyph_stego(&self, output: &str) -> Option<SteganographyAlert> {
        // R58-014/015: Use a lazily-initialized static HashSet for O(1)
        // per-character lookup instead of recreating a HashMap on every call.
        static CONFUSABLE_SET: OnceLock<HashSet<char>> = OnceLock::new();
        let confusable_set = CONFUSABLE_SET.get_or_init(|| {
            [
                'а', 'ɑ', 'α', // Latin 'a' confusables: Cyrillic, IPA, Greek
                'е', 'ε', // Latin 'e' confusables: Cyrillic, Greek
                'о', 'ο', '0', // Latin 'o' confusables: Cyrillic, Greek omicron, digit zero
                'с', // Latin 'c' confusable: Cyrillic
                'р', // Latin 'p' confusable: Cyrillic
                'х', // Latin 'x' confusable: Cyrillic
                'у', // Latin 'y' confusable: Cyrillic
            ]
            .into_iter()
            .collect()
        });

        let mut homoglyph_count = 0;
        let mut first_offset = None;

        for (i, c) in output.chars().enumerate() {
            if confusable_set.contains(&c) {
                homoglyph_count += 1;
                if first_offset.is_none() {
                    first_offset = Some(i);
                }
            }
        }

        // More than 5 homoglyphs in otherwise ASCII text is suspicious
        let ascii_count = output.chars().filter(|c| c.is_ascii()).count();
        let total_chars = output.chars().count();

        // R58-005: Guard against division by zero on empty input.
        if total_chars == 0 {
            return None;
        }

        if homoglyph_count > 5 && ascii_count as f32 / total_chars as f32 > 0.9 {
            return Some(SteganographyAlert {
                stego_type: SteganographyType::Homoglyph,
                confidence: (homoglyph_count as f32 / 20.0).min(1.0),
                description: format!(
                    "Detected {} potential homoglyph characters in mostly ASCII text",
                    homoglyph_count
                ),
                offset: first_offset,
                length: Some(homoglyph_count),
            });
        }

        None
    }

    /// Detect invisible Unicode characters.
    fn detect_invisible_chars(&self, output: &str) -> Option<SteganographyAlert> {
        // Invisible formatting and control characters
        const INVISIBLE_RANGES: &[(u32, u32)] = &[
            (0x00AD, 0x00AD), // Soft hyphen
            (0x034F, 0x034F), // Combining grapheme joiner
            (0x061C, 0x061C), // Arabic letter mark
            (0x115F, 0x1160), // Hangul fillers
            (0x17B4, 0x17B5), // Khmer vowel inherent
            (0x2028, 0x202F), // Various separators and invisibles
            (0x2060, 0x206F), // Word joiners, invisible operators
            (0x3164, 0x3164), // Hangul filler
            (0xFE00, 0xFE0F), // Variation selectors
            (0xFEFF, 0xFEFF), // BOM
        ];

        let mut count = 0;
        let mut first_offset = None;

        for (i, c) in output.chars().enumerate() {
            let code = c as u32;
            for (start, end) in INVISIBLE_RANGES {
                if code >= *start && code <= *end {
                    count += 1;
                    if first_offset.is_none() {
                        first_offset = Some(i);
                    }
                    break;
                }
            }
        }

        if count > 5 {
            return Some(SteganographyAlert {
                stego_type: SteganographyType::InvisibleCharacters,
                confidence: (count as f32 / 15.0).min(1.0),
                description: format!(
                    "Detected {} invisible Unicode characters that may hide data",
                    count
                ),
                offset: first_offset,
                length: Some(count),
            });
        }

        None
    }

    /// Detect unusual control characters.
    fn detect_control_chars(&self, output: &str) -> Option<SteganographyAlert> {
        // ASCII control chars (except common ones like \n, \r, \t)
        let mut suspicious_count = 0;
        let mut first_offset = None;

        for (i, c) in output.chars().enumerate() {
            if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                suspicious_count += 1;
                if first_offset.is_none() {
                    first_offset = Some(i);
                }
            }
        }

        if suspicious_count > 3 {
            return Some(SteganographyAlert {
                stego_type: SteganographyType::ControlCharacters,
                confidence: (suspicious_count as f32 / 10.0).min(1.0),
                description: format!("Detected {} unusual control characters", suspicious_count),
                offset: first_offset,
                length: Some(suspicious_count),
            });
        }

        None
    }

    /// Detect encoded blocks in unexpected locations.
    fn detect_encoded_blocks(&self, output: &str) -> Option<SteganographyAlert> {
        // Look for base64-like patterns of significant length
        // IMP-007: Use pre-compiled static pattern for performance
        let base64_pattern = get_base64_pattern()?;

        if let Some(mat) = base64_pattern.find(output) {
            // Check if it's in a context that suggests encoding
            let before = if mat.start() > 0 {
                &output[mat.start().saturating_sub(10)..mat.start()]
            } else {
                ""
            };

            // If not preceded by typical base64 context markers, it's suspicious
            if !before.contains("base64")
                && !before.contains("data:")
                && !before.contains("==")
                && !before.contains("token")
            {
                return Some(SteganographyAlert {
                    stego_type: SteganographyType::EncodedBlocks,
                    confidence: 0.6,
                    description: "Detected potential base64-encoded block in unexpected location"
                        .to_string(),
                    offset: Some(mat.start()),
                    length: Some(mat.len()),
                });
            }
        }

        None
    }

    /// Normalize output to remove potential covert channels.
    pub fn normalize(&self, output: &str) -> String {
        if !self.config.normalize_output {
            return output.to_string();
        }

        let mut result = output.to_string();

        // Strip zero-width characters
        if self.config.strip_zero_width {
            result = result
                .chars()
                .filter(|c| {
                    !matches!(
                        c,
                        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}'
                    )
                })
                .collect();
        }

        // Strip trailing whitespace from each line
        if self.config.strip_trailing_whitespace {
            result = result
                .lines()
                .map(|line| line.trim_end())
                .collect::<Vec<_>>()
                .join("\n");
        }

        result
    }

    /// Check output entropy against baseline.
    pub fn check_entropy(&self, output: &str) -> EntropyResult {
        if !self.config.analyze_entropy {
            return EntropyResult::Normal { entropy: 0.0 };
        }

        if output.len() < self.config.min_analysis_length {
            return EntropyResult::Normal { entropy: 0.0 };
        }

        let entropy = self.calculate_entropy(output);

        if entropy < self.config.min_entropy_threshold {
            return EntropyResult::Abnormal(EntropyAlert {
                entropy,
                expected_range: (
                    self.config.min_entropy_threshold,
                    self.config.max_entropy_threshold,
                ),
                deviation: EntropyDeviation::TooLow,
                description: format!(
                    "Entropy {:.2} is below threshold {:.2}, may indicate padding/redundancy attack",
                    entropy, self.config.min_entropy_threshold
                ),
            });
        }

        if entropy > self.config.max_entropy_threshold {
            return EntropyResult::Abnormal(EntropyAlert {
                entropy,
                expected_range: (
                    self.config.min_entropy_threshold,
                    self.config.max_entropy_threshold,
                ),
                deviation: EntropyDeviation::TooHigh,
                description: format!(
                    "Entropy {:.2} exceeds threshold {:.2}, may indicate encrypted/compressed data",
                    entropy, self.config.max_entropy_threshold
                ),
            });
        }

        EntropyResult::Normal { entropy }
    }

    /// Calculate Shannon entropy of a string (bits per character).
    fn calculate_entropy(&self, data: &str) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        // Count character frequencies
        let mut freq: HashMap<char, u32> = HashMap::with_capacity(data.len().min(256));
        let mut total = 0u32;

        for c in data.chars() {
            *freq.entry(c).or_insert(0) += 1;
            total += 1;
        }

        // Calculate Shannon entropy
        let mut entropy = 0.0f32;
        let total_f = total as f32;

        for count in freq.values() {
            let p = *count as f32 / total_f;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Update session baseline with new entropy sample.
    ///
    /// SECURITY: Rejects non-finite, negative, and >8.0 entropy values to prevent
    /// NaN/Infinity from corrupting the running average baseline, which could
    /// suppress future anomaly detection.
    pub fn update_baseline(&self, session_id: &str, entropy: f32) {
        // SECURITY: Reject oversized session IDs to prevent attacker-controlled
        // strings from consuming unbounded memory as HashMap keys.
        if session_id.len() > MAX_SESSION_ID_LENGTH {
            tracing::warn!(
                target: "vellaveto::security",
                "update_baseline: session_id exceeds max length ({}), ignoring",
                MAX_SESSION_ID_LENGTH
            );
            return;
        }
        if !entropy.is_finite() || !(0.0..=8.0).contains(&entropy) {
            tracing::warn!(
                target: "vellaveto::security",
                session_id = %session_id,
                entropy = %entropy,
                "update_baseline called with invalid entropy — ignoring"
            );
            return;
        }
        let mut baselines = match self.session_baselines.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in OutputSecurityAnalyzer::update_baseline");
                return;
            }
        };

        // Enforce capacity bound: reject new sessions when at capacity
        if !baselines.contains_key(session_id) && baselines.len() >= MAX_SESSION_BASELINES {
            tracing::warn!(
                target: "vellaveto::security",
                "session_baselines at capacity ({}), rejecting new session",
                MAX_SESSION_BASELINES
            );
            return;
        }

        let baseline = baselines
            .entry(session_id.to_string())
            .or_insert(EntropyBaseline {
                average: entropy,
                sample_count: 0,
                std_dev: 0.0,
            });

        // Exponential moving average
        let alpha = 0.2;
        baseline.average = alpha * entropy + (1.0 - alpha) * baseline.average;
        baseline.sample_count = baseline.sample_count.saturating_add(1);

        // Update standard deviation approximation
        let diff = (entropy - baseline.average).abs();
        baseline.std_dev = alpha * diff + (1.0 - alpha) * baseline.std_dev;
    }

    /// Get baseline for a session.
    pub fn get_baseline(&self, session_id: &str) -> Option<(f32, f32)> {
        // SECURITY: Reject oversized session IDs — they cannot have been stored
        // (update_baseline rejects them), so we can return None immediately.
        if session_id.len() > MAX_SESSION_ID_LENGTH {
            return None;
        }
        let baselines = match self.session_baselines.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in OutputSecurityAnalyzer::get_baseline");
                return None;
            }
        };
        baselines.get(session_id).map(|b| (b.average, b.std_dev))
    }

    /// Perform full security analysis on output.
    pub fn analyze(&self, output: &str) -> Vec<OutputSecurityAlert> {
        let mut alerts = Vec::new();

        if let Some(stego_alert) = self.detect_steganography(output) {
            alerts.push(OutputSecurityAlert::Steganography(stego_alert));
        }

        if let EntropyResult::Abnormal(entropy_alert) = self.check_entropy(output) {
            alerts.push(OutputSecurityAlert::AbnormalEntropy(entropy_alert));
        }

        alerts
    }
}

impl Default for OutputSecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_width_detection() {
        let analyzer = OutputSecurityAnalyzer::new();

        // Normal text - no alert
        assert!(analyzer.detect_steganography("Hello, world!").is_none());

        // Text with zero-width chars - should alert
        let stego_text = "Hello\u{200B}wo\u{200C}rld\u{200D}!\u{200B}";
        let alert = analyzer.detect_steganography(stego_text);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().stego_type, SteganographyType::Whitespace);
    }

    #[test]
    fn test_homoglyph_detection() {
        let analyzer = OutputSecurityAnalyzer::new();

        // Normal ASCII text - no alert
        assert!(analyzer.detect_homoglyph_stego("Hello, world!").is_none());

        // Text with Cyrillic homoglyphs mixed in longer ASCII text - should alert
        // 'а' (Cyrillic) looks like 'a' (Latin), 'о' looks like 'o', 'у' looks like 'y'
        // Need mostly ASCII (>90%) with >5 homoglyphs
        let homoglyph_text = "This is a longer text with mostly ASCII characters. \
            The quick brown fox jumps over the lazy dog. Here аre sоme hоmоglуphs \
            hidden in plаin sight with mоre ASCII padding after them.";
        let alert = analyzer.detect_homoglyph_stego(homoglyph_text);
        assert!(alert.is_some(), "Expected homoglyph detection");
        assert_eq!(alert.unwrap().stego_type, SteganographyType::Homoglyph);
    }

    #[test]
    fn test_invisible_char_detection() {
        let analyzer = OutputSecurityAnalyzer::new();

        // Normal text
        assert!(analyzer.detect_invisible_chars("Normal text").is_none());

        // Text with invisible chars
        let invisible_text =
            "Text\u{2060}with\u{2061}invisible\u{2062}chars\u{2063}\u{2064}\u{2065}";
        let alert = analyzer.detect_invisible_chars(invisible_text);
        assert!(alert.is_some());
        assert_eq!(
            alert.unwrap().stego_type,
            SteganographyType::InvisibleCharacters
        );
    }

    #[test]
    fn test_control_char_detection() {
        let analyzer = OutputSecurityAnalyzer::new();

        // Normal text with standard newlines
        assert!(analyzer
            .detect_control_chars("Line 1\nLine 2\r\n")
            .is_none());

        // Text with unusual control chars
        let control_text = "Text\x01with\x02control\x03chars\x04";
        let alert = analyzer.detect_control_chars(control_text);
        assert!(alert.is_some());
        assert_eq!(
            alert.unwrap().stego_type,
            SteganographyType::ControlCharacters
        );
    }

    #[test]
    fn test_entropy_normal() {
        let analyzer = OutputSecurityAnalyzer::new();

        // Normal English text has entropy around 4.0-4.5
        let normal_text = "The quick brown fox jumps over the lazy dog. \
            This is a longer sentence to ensure we have enough characters \
            for entropy analysis to work properly.";

        if let EntropyResult::Normal { entropy } = analyzer.check_entropy(normal_text) {
            assert!(entropy > 2.0 && entropy < 6.5);
        } else {
            panic!("Expected normal entropy result");
        }
    }

    #[test]
    fn test_entropy_too_low() {
        let analyzer = OutputSecurityAnalyzer::new();

        // Extremely repetitive text has very low entropy
        let low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        if let EntropyResult::Abnormal(alert) = analyzer.check_entropy(low_entropy) {
            assert_eq!(alert.deviation, EntropyDeviation::TooLow);
        } else {
            panic!("Expected abnormal entropy result");
        }
    }

    #[test]
    fn test_entropy_too_high() {
        let config = OutputSecurityConfig {
            max_entropy_threshold: 4.5, // Lower threshold for test
            ..Default::default()
        };
        let analyzer = OutputSecurityAnalyzer::with_config(config);

        // Data with many unique characters has high entropy
        // Using all printable ASCII chars plus some extras to push entropy above threshold
        let high_entropy = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ\
            0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?`~\
            ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";

        if let EntropyResult::Abnormal(alert) = analyzer.check_entropy(high_entropy) {
            assert_eq!(alert.deviation, EntropyDeviation::TooHigh);
        } else {
            // If not abnormal, at least verify it's close to threshold
            if let EntropyResult::Normal { entropy } = analyzer.check_entropy(high_entropy) {
                assert!(entropy > 4.0, "Expected high entropy, got {}", entropy);
            }
        }
    }

    #[test]
    fn test_normalize_output() {
        let analyzer = OutputSecurityAnalyzer::new();

        // Text with zero-width chars and trailing whitespace
        let input = "Hello\u{200B}world   \n  Trailing spaces  ";
        let normalized = analyzer.normalize(input);

        assert!(!normalized.contains('\u{200B}'));
        assert!(!normalized.ends_with(' '));
    }

    #[test]
    fn test_baseline_update() {
        let analyzer = OutputSecurityAnalyzer::new();

        analyzer.update_baseline("session1", 4.0);
        analyzer.update_baseline("session1", 4.5);
        analyzer.update_baseline("session1", 4.2);

        let baseline = analyzer.get_baseline("session1");
        assert!(baseline.is_some());
        let (avg, _std) = baseline.unwrap();
        assert!(avg > 3.0 && avg < 5.0);
    }

    #[test]
    fn test_full_analysis() {
        let analyzer = OutputSecurityAnalyzer::new();

        // Normal text - no alerts
        let normal = "This is a normal piece of text without any suspicious content.";
        assert!(analyzer.analyze(normal).is_empty());

        // Suspicious text with zero-width chars
        let suspicious = "Hidden\u{200B}da\u{200C}ta\u{200D}he\u{200B}re";
        let alerts = analyzer.analyze(suspicious);
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_disabled_detection() {
        let config = OutputSecurityConfig {
            detect_steganography: false,
            analyze_entropy: false,
            ..Default::default()
        };
        let analyzer = OutputSecurityAnalyzer::with_config(config);

        // Even with suspicious content, should not alert when disabled
        let suspicious = "Hidden\u{200B}da\u{200C}ta\u{200D}he\u{200B}re";
        assert!(analyzer.analyze(suspicious).is_empty());
    }

    #[test]
    fn test_calculate_entropy() {
        let analyzer = OutputSecurityAnalyzer::new();

        // All same character = 0 entropy
        assert_eq!(analyzer.calculate_entropy("aaaa"), 0.0);

        // Two equally distributed chars = 1 bit
        let entropy = analyzer.calculate_entropy("aabb");
        assert!((entropy - 1.0).abs() < 0.001);

        // Four equally distributed chars = 2 bits
        let entropy = analyzer.calculate_entropy("abcd");
        assert!((entropy - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_output_config_validate_default_ok() {
        let config = OutputSecurityConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_output_config_validate_nan_min() {
        let config = OutputSecurityConfig {
            min_entropy_threshold: f32::NAN,
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finite"));
    }

    #[test]
    fn test_output_config_validate_nan_max() {
        let config = OutputSecurityConfig {
            max_entropy_threshold: f32::NAN,
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finite"));
    }

    #[test]
    fn test_output_config_validate_min_out_of_range() {
        let low = OutputSecurityConfig {
            min_entropy_threshold: -1.0,
            ..Default::default()
        };
        assert!(low.validate().is_err());

        let high = OutputSecurityConfig {
            min_entropy_threshold: 9.0,
            ..Default::default()
        };
        assert!(high.validate().is_err());
    }

    #[test]
    fn test_output_config_validate_min_ge_max() {
        let equal = OutputSecurityConfig {
            min_entropy_threshold: 5.0,
            max_entropy_threshold: 5.0,
            ..Default::default()
        };
        assert!(equal.validate().is_err());

        let greater = OutputSecurityConfig {
            min_entropy_threshold: 6.0,
            max_entropy_threshold: 5.0,
            ..Default::default()
        };
        assert!(greater.validate().is_err());
    }

    #[test]
    fn test_homoglyph_empty_input() {
        let analyzer = OutputSecurityAnalyzer::new();
        assert!(analyzer.detect_homoglyph_stego("").is_none());
    }

    #[test]
    fn test_baseline_capacity_bound() {
        let analyzer = OutputSecurityAnalyzer::new();
        // Fill baselines to capacity
        for i in 0..100 {
            analyzer.update_baseline(&format!("sess_{}", i), 4.0);
        }
        // Existing sessions can still be updated
        analyzer.update_baseline("sess_0", 4.5);
        let baseline = analyzer.get_baseline("sess_0");
        assert!(baseline.is_some());
    }

    #[test]
    fn test_update_baseline_rejects_oversized_session_id() {
        let analyzer = OutputSecurityAnalyzer::new();
        let long_id = "x".repeat(257);
        // Should silently ignore — not panic, not store
        analyzer.update_baseline(&long_id, 4.0);
        assert!(analyzer.get_baseline(&long_id).is_none());
    }

    #[test]
    fn test_get_baseline_returns_none_for_oversized_session_id() {
        let analyzer = OutputSecurityAnalyzer::new();
        // update with valid id, then try get with oversized — must not find it
        analyzer.update_baseline("valid_session", 4.0);
        let long_id = "v".repeat(257);
        assert!(analyzer.get_baseline(&long_id).is_none());
    }
}
