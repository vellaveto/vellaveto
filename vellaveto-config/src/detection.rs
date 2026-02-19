use serde::{Deserialize, Serialize};

use crate::default_true;

/// Configuration for the prompt injection detection scanner.
///
/// Controls which patterns are used for response inspection. The scanner
/// operates as a heuristic pre-filter — it cannot stop all injection attacks
/// but raises alerts for known signatures.
///
/// # TOML Example
///
/// ```toml
/// [injection]
/// enabled = true
/// extra_patterns = ["transfer funds", "send bitcoin", "exfiltrate"]
/// disabled_patterns = ["pretend you are"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InjectionConfig {
    /// Master toggle for injection scanning. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// When true, injection matches block the response instead of just logging.
    /// Default: `false` (log-only mode, backward compatible).
    #[serde(default)]
    pub block_on_injection: bool,

    /// Additional patterns appended to the default set.
    /// Matched case-insensitively after Unicode sanitization.
    #[serde(default)]
    pub extra_patterns: Vec<String>,

    /// Default patterns to remove. Any default pattern whose text matches
    /// an entry here (case-insensitive) will be excluded from scanning.
    #[serde(default)]
    pub disabled_patterns: Vec<String>,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // SECURITY: Default to blocking for fail-closed behavior.
            // Previously defaulted to false (log-only), which could allow
            // prompt injection attacks to pass unblocked.
            block_on_injection: true,
            extra_patterns: Vec::new(),
            disabled_patterns: Vec::new(),
        }
    }
}

/// Configuration for Data Loss Prevention (DLP) scanning.
///
/// Controls secret detection in tool call parameters and responses.
/// DLP scanning detects API keys, tokens, credentials, and other secrets
/// that should not be exfiltrated via tool calls (OWASP ASI03).
///
/// # TOML Example
///
/// ```toml
/// [dlp]
/// enabled = true
/// block_on_finding = true
/// max_depth = 32
/// time_budget_ms = 5
/// extra_patterns = [["custom_secret", "CUSTOM_[A-Z0-9]{32}"]]
/// disabled_patterns = ["generic_api_key"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DlpConfig {
    /// Master toggle for DLP scanning. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// When true, DLP findings block the request instead of just logging.
    /// Default: `true` (secure by default — block exfiltration attempts).
    #[serde(default = "default_true")]
    pub block_on_finding: bool,

    /// Maximum JSON recursion depth for scanning. Defaults to 32.
    #[serde(default = "default_dlp_max_depth")]
    pub max_depth: usize,

    /// Time budget for multi-layer decode in milliseconds.
    /// After this budget is exhausted, remaining decode layers are skipped.
    /// Default: 5ms (production), 200ms (debug builds).
    #[serde(default = "default_dlp_time_budget_ms")]
    pub time_budget_ms: u64,

    /// Maximum string size to scan in bytes. Strings exceeding this are truncated.
    /// Secrets are unlikely to exceed 1MB so this limit doesn't affect detection.
    /// Default: 1MB (1_048_576 bytes).
    #[serde(default = "default_dlp_max_string_size")]
    pub max_string_size: usize,

    /// Additional patterns appended to the default set.
    /// Each entry is a tuple of (name, regex_pattern).
    #[serde(default)]
    pub extra_patterns: Vec<(String, String)>,

    /// Default patterns to disable. Any default pattern whose name matches
    /// an entry here (case-insensitive) will be excluded from scanning.
    #[serde(default)]
    pub disabled_patterns: Vec<String>,
}

fn default_dlp_max_depth() -> usize {
    32
}

fn default_dlp_time_budget_ms() -> u64 {
    5
}

fn default_dlp_max_string_size() -> usize {
    1024 * 1024 // 1 MB
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_on_finding: true,
            max_depth: 32,
            time_budget_ms: 5,
            max_string_size: 1024 * 1024,
            extra_patterns: Vec::new(),
            disabled_patterns: Vec::new(),
        }
    }
}

/// Rate limiting configuration for the HTTP server.
///
/// All fields are optional — omitted values fall back to environment variable
/// overrides or sensible defaults (rate limiting disabled for that category).
///
/// # TOML Example
///
/// ```toml
/// [rate_limit]
/// evaluate_rps = 1000
/// evaluate_burst = 50
/// admin_rps = 20
/// admin_burst = 5
/// readonly_rps = 200
/// readonly_burst = 20
/// per_ip_rps = 100
/// per_ip_burst = 10
/// per_ip_max_capacity = 100000
/// per_principal_rps = 50
/// per_principal_burst = 10
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Max sustained requests/sec for `/evaluate` endpoints.
    pub evaluate_rps: Option<u32>,
    /// Burst allowance above `evaluate_rps` (tokens in the bucket beyond 1).
    pub evaluate_burst: Option<u32>,
    /// Max sustained requests/sec for admin/mutating endpoints.
    pub admin_rps: Option<u32>,
    /// Burst allowance above `admin_rps`.
    pub admin_burst: Option<u32>,
    /// Max sustained requests/sec for read-only endpoints.
    pub readonly_rps: Option<u32>,
    /// Burst allowance above `readonly_rps`.
    pub readonly_burst: Option<u32>,
    /// Max sustained requests/sec per unique client IP.
    pub per_ip_rps: Option<u32>,
    /// Burst allowance above `per_ip_rps`.
    pub per_ip_burst: Option<u32>,
    /// Maximum number of unique IPs tracked simultaneously.
    pub per_ip_max_capacity: Option<usize>,
    /// Max sustained requests/sec per principal (identified by X-Principal
    /// header, Bearer token, or client IP as fallback).
    pub per_principal_rps: Option<u32>,
    /// Burst allowance above `per_principal_rps`.
    pub per_principal_burst: Option<u32>,
}

/// A custom PII detection pattern for audit log redaction.
///
/// Allows operators to add site-specific patterns beyond the built-in set
/// (email, SSN, phone, credit card, etc.).
///
/// # TOML Example
///
/// ```toml
/// [[audit.custom_pii_patterns]]
/// name = "internal_employee_id"
/// pattern = "EMP-\\d{6}"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CustomPiiPattern {
    /// Human-readable name for this pattern (used in diagnostics).
    pub name: String,
    /// Regex pattern string. Invalid patterns are logged and skipped at startup.
    pub pattern: String,
}

/// Audit log configuration.
///
/// # TOML Example
///
/// ```toml
/// [audit]
/// redaction_level = "KeysAndPatterns"
///
/// [[audit.custom_pii_patterns]]
/// name = "internal_employee_id"
/// pattern = "EMP-\\d{6}"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Redaction level for audit log entries.
    /// - `"Off"`: no redaction
    /// - `"KeysOnly"`: redact sensitive keys and value prefixes
    /// - `"KeysAndPatterns"` (default): redact keys, prefixes, and PII patterns
    #[serde(default)]
    pub redaction_level: Option<String>,
    /// Custom PII detection patterns appended to the built-in set.
    #[serde(default)]
    pub custom_pii_patterns: Vec<CustomPiiPattern>,
    /// Strict audit mode (FIND-005): When true, audit logging failures cause
    /// requests to be denied instead of proceeding without an audit trail.
    /// This ensures fail-closed behavior for security-critical deployments
    /// where every decision must be recorded.
    /// Default: false (backward compatible, fail-open for audit).
    #[serde(default)]
    pub strict_mode: bool,
}

/// Memory poisoning defense configuration (OWASP ASI06).
///
/// # TOML Example
///
/// ```toml
/// [memory_tracking]
/// enabled = false
/// block_on_match = false
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemoryTrackingConfig {
    /// Enable cross-request data flow tracking. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Block tool calls that replay data from previous responses. Default: false.
    #[serde(default)]
    pub block_on_match: bool,
}

/// Audit log export configuration for SIEM integration (P3.3).
///
/// Controls the format and delivery of audit entries to external SIEM platforms.
/// Supports CEF (Common Event Format) and JSON Lines (ndjson) output.
///
/// # TOML Example
///
/// ```toml
/// [audit_export]
/// format = "jsonl"
/// webhook_url = "https://siem.example.com/ingest"
/// batch_size = 10
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuditExportConfig {
    /// Export format: "cef" or "jsonl". Default: "jsonl".
    #[serde(default = "default_export_format")]
    pub format: String,
    /// Optional webhook URL for streaming entries.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Number of entries per webhook batch. Default: 10.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_export_format() -> String {
    "jsonl".to_string()
}

fn default_batch_size() -> usize {
    10
}

impl Default for AuditExportConfig {
    fn default() -> Self {
        Self {
            format: default_export_format(),
            webhook_url: None,
            batch_size: default_batch_size(),
        }
    }
}

/// Configuration for multimodal content inspection (image/audio/video/PDF).
///
/// Controls which content types are scanned for prompt injection attacks
/// hidden in non-text media (e.g., EXIF fields, ID3 tags, MP4 metadata).
/// Content types are specified as strings; the MCP crate converts them
/// to the runtime `ContentType` enum.
///
/// # TOML Example
///
/// ```toml
/// [multimodal]
/// enabled = true
/// enable_ocr = true
/// max_image_size = 10485760
/// max_audio_size = 52428800
/// max_video_size = 104857600
/// ocr_timeout_ms = 5000
/// min_ocr_confidence = 0.5
/// enable_stego_detection = false
/// content_types = ["Image", "Pdf", "Audio", "Video"]
/// blocked_content_types = []
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MultimodalPolicyConfig {
    /// Enable multimodal scanning. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Enable OCR for image text extraction. Default: true when enabled.
    #[serde(default = "default_true")]
    pub enable_ocr: bool,

    /// Maximum image/PDF size to process in bytes. Default: 10MB.
    #[serde(default = "default_max_image_size")]
    pub max_image_size: usize,

    /// Maximum audio file size to process in bytes. Default: 50MB.
    #[serde(default = "default_max_audio_size")]
    pub max_audio_size: usize,

    /// Maximum video file size to process in bytes. Default: 100MB.
    #[serde(default = "default_max_video_size")]
    pub max_video_size: usize,

    /// OCR timeout in milliseconds. Default: 5000ms.
    #[serde(default = "default_ocr_timeout_ms")]
    pub ocr_timeout_ms: u64,

    /// Minimum confidence for OCR text. Default: 0.5.
    #[serde(default = "default_min_ocr_confidence")]
    pub min_ocr_confidence: f32,

    /// Enable steganography detection. Default: false (computationally expensive).
    #[serde(default)]
    pub enable_stego_detection: bool,

    /// Content types to scan. Recognized values: "Image", "Pdf", "Audio", "Video".
    /// Default: `["Image"]`.
    #[serde(default = "default_multimodal_content_types")]
    pub content_types: Vec<String>,

    /// Content types to explicitly block (reject immediately).
    /// Evaluated before `content_types`. If a type appears in both lists,
    /// it is blocked. Default: empty.
    #[serde(default)]
    pub blocked_content_types: Vec<String>,
}

/// Maximum number of content type entries.
const MAX_CONTENT_TYPES: usize = 20;

impl MultimodalPolicyConfig {
    /// Validate float fields and collection bounds.
    pub fn validate(&self) -> Result<(), String> {
        if !self.min_ocr_confidence.is_finite()
            || self.min_ocr_confidence < 0.0
            || self.min_ocr_confidence > 1.0
        {
            return Err(format!(
                "multimodal.min_ocr_confidence must be in [0.0, 1.0], got {}",
                self.min_ocr_confidence
            ));
        }
        if self.content_types.len() > MAX_CONTENT_TYPES {
            return Err(format!(
                "multimodal.content_types has {} entries, max is {}",
                self.content_types.len(),
                MAX_CONTENT_TYPES
            ));
        }
        if self.blocked_content_types.len() > MAX_CONTENT_TYPES {
            return Err(format!(
                "multimodal.blocked_content_types has {} entries, max is {}",
                self.blocked_content_types.len(),
                MAX_CONTENT_TYPES
            ));
        }
        Ok(())
    }
}

fn default_max_image_size() -> usize {
    10 * 1024 * 1024
}
fn default_max_audio_size() -> usize {
    50 * 1024 * 1024
}
fn default_max_video_size() -> usize {
    100 * 1024 * 1024
}
fn default_ocr_timeout_ms() -> u64 {
    5000
}
fn default_min_ocr_confidence() -> f32 {
    0.5
}
fn default_multimodal_content_types() -> Vec<String> {
    vec!["Image".to_string()]
}

impl Default for MultimodalPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enable_ocr: true,
            max_image_size: default_max_image_size(),
            max_audio_size: default_max_audio_size(),
            max_video_size: default_max_video_size(),
            ocr_timeout_ms: default_ocr_timeout_ms(),
            min_ocr_confidence: default_min_ocr_confidence(),
            enable_stego_detection: false,
            content_types: default_multimodal_content_types(),
            blocked_content_types: vec![],
        }
    }
}
